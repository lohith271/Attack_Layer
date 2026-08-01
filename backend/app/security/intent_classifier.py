"""
V2 Intent Classifier — prototype attention based.
"""

from app.neurosymbolic.embeddings import get_embedding
from app.neurosymbolic.prototype_bank import get_intent_prototypes
from app.neurosymbolic.similarity import get_similarity_engine

_engine = get_similarity_engine()

INTENT_EXAMPLES = {
    "NORMAL_CHAT": [
        "Hello, how are you?",
        "Tell me a joke",
        "Write a poem about the ocean",
    ],
    "MEMORY_STORE": [
        "Remember that I prefer Python",
        "Store this information for later",
        "Save this memory",
        "Keep in mind that I work as an engineer",
        "Memorize that my favorite food is pizza",
        "I live in Hyderabad",
        "My favorite language is Python",
        "Professor Smith approved Project X",
        "I visited Mysore this morning",
        "I met my professor this evening",
        "I watched a movie yesterday",
        "I ate lunch just now",
        "I went to the park this afternoon",
    ],
    "MEMORY_UPDATE": [
        "Update my memory about location",
        "Change my preference to Java",
        "I now live in Bangalore",
        "My favorite language is Java now",
        "Replace Python with Java in my preferences",
        "Actually I prefer Linux now",
        "Overwrite my old location",
    ],
    "MEMORY_DELETE": [
        "Delete my stored memories",
        "Forget everything about me",
        "Remove my preference from memory",
        "Erase my stored information",
        "Clear my memory vault",
        "Delete the memory about my location",
    ],
    "MEMORY_QUERY": [
        "What do you remember about me?",
        "What is my favorite language?",
        "What do I prefer to code?",
        "What do I love eating?",
        "Where do I live?",
        "Tell me my stored preferences",
        "What do you know about me?",
        "Do you remember my job?",
        "Recall my preferences",
    ],
    "QUESTION": [
        "Explain machine learning",
        "What is Python?",
        "How does deep learning work?",
        "What is the capital of France?",
    ],
    "SYSTEM_QUERY": [
        "How does your memory system work?",
        "What security rules do you follow?",
        "Explain your architecture",
        "What is your trust score system?",
        "How do you detect attacks?",
        "Show me your internal policies",
    ],
    "TOOL_REQUEST": [
        "Run a web search for me",
        "Execute this tool command",
        "Use the calculator tool",
        "Fetch data from an API",
        "Call the email tool",
        "Enable the file reader tool",
    ],
    "UNKNOWN": [
        "asdfghjkl qwerty",
        "???",
        "hmm maybe something",
        "idk what to say",
    ],
}

OPERATION_MAP = {
    "NORMAL_CHAT": "GENERAL_CHAT",
    "MEMORY_STORE": "WRITE",
    "MEMORY_UPDATE": "UPDATE",
    "MEMORY_DELETE": "DELETE",
    "MEMORY_QUERY": "READ",
    "QUESTION": "GENERAL_CHAT",
    "SYSTEM_QUERY": "READ",
    "TOOL_REQUEST": "GENERAL_CHAT",
    "UNKNOWN": "GENERAL_CHAT",
}

def _intent_scores(embedding):
    prototypes = get_intent_prototypes()
    return {
        intent: round(_engine.score(embedding, protos), 4)
        for intent, protos in prototypes.items()
    }


def classify_intent(text: str, db=None, user_id=None):
    from app.security.request_analyzer import (
        _has_relevant_memory,
        _resolve_write_vs_update,
    )

    text = text.strip()
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()

    embedding = get_embedding(text)
    scores = _intent_scores(embedding)

    intent = max(scores, key=scores.get)
    confidence = scores[intent]

    stripped = text.strip()
    query_score = scores.get("MEMORY_QUERY", 0.0)
    lowered = stripped.lower()
    declarative_memory = (
        not stripped.endswith("?")
        and lowered.startswith(
            (
                "i love ",
                "i like ",
                "i prefer ",
                "i live ",
                "i work ",
                "i work as ",
                "i study ",
                "i enjoy ",
                "i really enjoy ",
                "i usually ",
                "i often ",
                "i could eat ",
                "i always ",
                "i tend to ",
                "i am doing ",
                "my favorite ",
                "my favourite ",
                "my career ",
                "my hometown ",
                "my goal is ",
                "i went ",
                "i visited ",
                "i watched ",
                "i met ",
                "i had ",
                "i ate ",
                "i saw ",
                "i read ",
                "i bought ",
                "i played ",
                "yesterday ",
                "today ",
                "last night ",
                "this morning ",
                "this afternoon ",
                "this evening ",
                "just now ",
            )
        )
    )
    if declarative_memory:
        operation = "WRITE"
        if db is not None and user_id is not None:
            from app.database.models import Memory
            from app.security.semantic_classifier import classify_memory

            category = classify_memory(text)["category"]
            has_category_memory = (
                db.query(Memory)
                .filter(
                    Memory.user_id == user_id,
                    Memory.category == category,
                    Memory.active == True,
                )
                .first()
                is not None
            )
            has_preference_memory = (
                "prefer" in lowered
                and db.query(Memory)
                .filter(
                    Memory.user_id == user_id,
                    Memory.active == True,
                    Memory.fact.ilike("%prefer%"),
                )
                .first()
                is not None
            )
            if has_category_memory or has_preference_memory:
                operation = "UPDATE"
        intent = "MEMORY_UPDATE" if operation == "UPDATE" else "MEMORY_STORE"
        confidence = max(
            scores.get(intent, 0.0),
            scores.get("MEMORY_STORE", 0.0),
            0.80,
        )

    personal_query = (
        lowered.startswith(
            (
                "what do i ",
                "what is my ",
                "where do i ",
                "who am i",
                "which ",
                "do you remember ",
                "tell me my ",
                "recall my ",
                "what do you remember",
            )
        )
        or "about me" in lowered
    )
    if stripped.endswith("?") and personal_query:
        intent = "MEMORY_QUERY"
        confidence = max(scores.get("MEMORY_QUERY", 0.0), 0.85)
    elif (
        not declarative_memory
        and (stripped.endswith("?") or personal_query)
        and query_score >= scores.get("MEMORY_STORE", 0.0) - 0.08
        and query_score >= scores.get("MEMORY_UPDATE", 0.0) - 0.08
    ):
        intent = "MEMORY_QUERY"
        confidence = query_score

    if confidence < 0.45:
        intent = "UNKNOWN"
        confidence = scores.get("UNKNOWN", confidence)

    if intent in ("MEMORY_STORE", "MEMORY_UPDATE") and not declarative_memory:
        write_score = scores.get("MEMORY_STORE", 0.0)
        update_score = scores.get("MEMORY_UPDATE", 0.0)
        operation = _resolve_write_vs_update(
            write_score,
            update_score,
            db,
            user_id,
            embedding,
        )
        intent = "MEMORY_UPDATE" if operation == "UPDATE" else "MEMORY_STORE"
        confidence = scores[intent]

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    alternatives = [
        {"intent": k, "confidence": v}
        for k, v in ranked
        if k != intent
    ][:3]

    return {
        "intent": intent,
        "confidence": confidence,
        "operation": OPERATION_MAP.get(intent, "GENERAL_CHAT"),
        "scores": scores,
        "alternatives": alternatives,
    }
