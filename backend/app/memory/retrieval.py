import re
from datetime import datetime

from sqlalchemy.orm import Session

from app.database.models import Memory

from app.memory.embedding_service import (
    generate_embedding
)

from app.memory.vector_storage import (
    semantic_search
)

from app.security.retrieval_gaurd import (
    filter_memories
)

from app.security.semantic_engine import (
    get_embedding,
    score_prototypes,
)
from app.security.semantic_classifier import classify_query_categories

WEIGHTS = {
    "category": 0.35,
    "semantic": 0.30,
    "keyword": 0.10,
    "trust": 0.15,
    "importance": 0.05,
    "recency": 0.05,
}


def _keyword_score(query, fact):
    query_tokens = set(re.findall(r"\w+", query.lower()))
    fact_tokens = set(re.findall(r"\w+", fact.lower()))
    if not query_tokens:
        return 0.0
    overlap = len(query_tokens & fact_tokens)
    return round(overlap / len(query_tokens), 4)


def _recency_score(updated_at):
    if not updated_at:
        return 0.5
    age_days = (datetime.utcnow() - updated_at).total_seconds() / 86400
    return round(max(0.1, 1.0 - age_days / 365), 4)


def _hybrid_score(memory, query, query_embedding, target_categories):
    fact_embedding = get_embedding(memory.fact)
    semantic = score_prototypes(query_embedding, [fact_embedding])
    keyword = _keyword_score(query, memory.fact)
    trust = memory.trust_score or 0.5
    importance = getattr(memory, "importance_score", None) or 0.5
    recency = _recency_score(memory.updated_at)
    category = 1.0 if memory.category in target_categories else 0.0

    final = (
        WEIGHTS["category"] * category
        + WEIGHTS["semantic"] * semantic
        + WEIGHTS["keyword"] * keyword
        + WEIGHTS["trust"] * trust
        + WEIGHTS["importance"] * importance
        + WEIGHTS["recency"] * recency
    )

    return {
        "final_score": round(final, 4),
        "category": category,
        "semantic": round(semantic, 4),
        "keyword": keyword,
        "trust": round(trust, 4),
        "importance": round(importance, 4),
        "recency": recency,
    }


def retrieve_memories(
    db: Session,
    user_id: str,
    query: str,
    top_k: int = 5,
    target_categories=None,
):
    target_categories = target_categories or classify_query_categories(query)
    query_embedding = generate_embedding(query)

    vector_results = semantic_search(
        embedding=query_embedding,
        top_k=top_k * 3,
    )

    memory_ids = []
    if (
        vector_results
        and "ids" in vector_results
        and len(vector_results["ids"]) > 0
    ):
        for memory_id in vector_results["ids"][0]:
            try:
                memory_ids.append(int(memory_id))
            except ValueError:
                pass

    memories = []
    if memory_ids:
        memories = (
            db.query(Memory)
            .filter(
                Memory.id.in_(memory_ids),
                Memory.user_id == user_id,
                Memory.active == True,
                Memory.category.in_(target_categories),
            )
            .all()
        )

    if len(memories) < top_k:
        additional = (
            db.query(Memory)
            .filter(
                Memory.user_id == user_id,
                Memory.active == True,
                Memory.category.in_(target_categories),
            )
            .order_by(Memory.updated_at.desc())
            .limit(top_k * 2)
            .all()
        )
        existing = {memory.id for memory in memories}
        for memory in additional:
            if memory.id not in existing:
                memories.append(memory)

    ranked = []
    for memory in memories:
        scores = _hybrid_score(memory, query, query_embedding, target_categories)
        ranked.append({
            "memory": memory,
            "scores": scores,
        })

    ranked.sort(key=lambda x: x["scores"]["final_score"], reverse=True)
    ranked_memories = [item["memory"] for item in ranked[:top_k * 2]]

    security_result = filter_memories(ranked_memories, query, db=db, user_id=user_id)

    allowed = security_result["allowed_memories"]
    allowed_ranked = sorted(
        allowed,
        key=lambda m: next(
            (r["scores"]["final_score"] for r in ranked if r["memory"].id == m.id),
            0.0,
        ),
        reverse=True,
    )[:top_k]

    for memory in allowed_ranked:
        if hasattr(memory, "usage_count"):
            memory.usage_count = (memory.usage_count or 0) + 1
    if allowed_ranked:
        db.commit()

    avg_score = (
        round(
            sum(
                next(
                    (r["scores"]["final_score"] for r in ranked if r["memory"].id == m.id),
                    0.0,
                )
                for m in allowed_ranked
            ) / len(allowed_ranked),
            4,
        )
        if allowed_ranked else 0.0
    )

    return {
        "query": query,
        "target_categories": target_categories,
        "semantic_matches": len(memories),
        "safe_memories": [memory.fact for memory in allowed_ranked],
        "ranked_memories": [
            {
                "memory_id": m.id,
                "content": m.fact,
                "category": m.category,
                "trust_score": round(m.trust_score, 4),
                "importance_score": round(
                    getattr(m, "importance_score", 0.5) or 0.5, 4
                ),
                "final_score": next(
                    (r["scores"]["final_score"] for r in ranked if r["memory"].id == m.id),
                    0.0,
                ),
            }
            for m in allowed_ranked
        ],
        "blocked_count": len(security_result["blocked_memories"]),
        "blocked_reasons": security_result["blocked_reasons"],
        "retrieval_confidence": avg_score,
    }
