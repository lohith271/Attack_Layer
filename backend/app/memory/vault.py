from sqlalchemy.orm import Session

from app.database.models import (
    Memory,
    MemoryHistory
)

from app.memory.embedding_service import (
    generate_embedding
)

from app.memory.vector_storage import (
    add_memory_embedding,
    remove_memory_embedding
)

from app.security.security_gateway import (
    evaluate_security
)

from app.security.memory_conflict_engine import (
    detect_conflict
)

from app.security.trust_engine import (
    calculate_trust
)

from app.audit.history_logger import (
    log_memory_history
)

from app.memory_security.services.memory_security_pipeline import (
    MemorySecurityPipeline
)

from app.memory_security.quarantine.quarantine_manager import (
    quarantine_memory
)
from app.memory_security.services.poison_event_logger import (
    log_poison_event
)

from app.memory_security.services.preference_event_logger import (
    log_preference_event
)

from app.memory_security.services.tool_policy_event_logger import (
    log_tool_policy_event
)
from app.ml.predict_decision import predict_decision
from app.ml.decision_mapper import map_decision
from app.memory.embedding_service import generate_embedding
def create_memory(
    db,
    user_id,
    fact
):

    security_result = evaluate_security(
        fact
    )
    # ============================
    # ML Decision Layer
    # ============================

    embedding = generate_embedding(
        fact
    )

    decision_output = predict_decision(
        embedding
    )

    ml_prediction = decision_output["prediction"]

    ml_confidence = decision_output["confidence"]

    ml_decision = map_decision(
        ml_prediction,
        ml_confidence
    )

    print()
    print("===== ML MODEL =====")

    print(
        "Prediction:",
        ml_prediction
    )

    print(
        "Confidence:",
        round(
            ml_confidence,
            4
        )
    )

    print(
        "Decision:",
        ml_decision
    )
    if security_result["decision"] == "BLOCK":

        attack_type = (
            security_result.get(
                "tool_policy_type"
            )
            or security_result.get(
                "memory_poison_type"
            )
            or security_result.get(
                "threat"
            )
            or "Security Policy"
        )

        if security_result.get(
            "tool_policy_type"
        ):

            log_tool_policy_event(

                db=db,

                user_id=user_id,

                policy_text=fact,

                violation_reason=(
                    security_result.get(
                        "tool_policy_violation"
                    )
                    or ""
                ),

                risk_score=(
                    security_result.get(
                        "risk_score",
                        0.0
                    )
                ),

                decision="BLOCK",

                unapproved_domains=",".join(
                    security_result.get(
                        "tool_policy_unapproved_domains",
                        []
                    )
                ),

            )

            log_poison_event(

                db=db,

                attack_type=attack_type,

                poison_score=(
                    security_result.get(
                        "risk_score",
                        0.9
                    )
                ),

                decision="BLOCK",

                details=fact

            )

        return {

            "status": "blocked",

            "attack_type": attack_type,

            "security": security_result
        }
    # ===================================
    # ML BLOCK
    # ===================================

    if ml_decision == "BLOCK":

        return {

            "status": "blocked",

            "attack_type": "ML_ATTACK",

            "ml_prediction": ml_prediction,

            "ml_confidence": ml_confidence,

            "decision": "BLOCK"

        }
    conflict_result = detect_conflict(

        db=db,

        user_id=user_id,

        fact=fact,

        category=security_result["category"]

    )

    new_version = 1

    conflict_detected = False

    existing_memory = None

    conflict_score = 0.0

    poison_score = 0.0

    attack_type = "NONE"

    drift_score = None

    stability_score = None

    if conflict_result:

        conflict_detected = True

        existing_memory = conflict_result["memory"]

        conflict_score = conflict_result.get(
            "conflict_score",
            0.0
        )

        poison_score = conflict_result.get(
            "poison_score",
            0.0
        )

        attack_type = conflict_result.get(
            "attack_type",
            "SAFE"
        )

        drift_score = conflict_result.get(
            "drift_score"
        )

        stability_score = conflict_result.get(
            "stability_score"
        )

        # ===================================
        # Duplicate Memory
        # ===================================

        if attack_type == "DUPLICATE":
            existing_memory.verification_count = (
                (existing_memory.verification_count or 0) + 1
            )
            db.commit()

            return {
                "status": "duplicate",
                "memory_id": existing_memory.id,
                "memory_version": existing_memory.memory_version,
                "attack_type": "DUPLICATE",
                "decision": "ALLOW"
            }

        new_version = (
            existing_memory.memory_version
            + 1
        )
    
    # ===================================
    # Preserve memory lineage
    # ===================================

    parent_memory_id = None

    if existing_memory:

        parent_memory_id = existing_memory.id
    trust_result = calculate_trust(
        source="USER",
        security_decision=security_result["decision"],
        category_confidence=security_result["category_confidence"],
        conflict_detected=conflict_detected,
        version=new_version,
        attack_type=attack_type,
        poison_score=poison_score,
        conflict_score=conflict_score,
        category=security_result["category"],
        verification_count=(existing_memory.verification_count or 0) if existing_memory else 0,
        conflict_count=(existing_memory.conflict_count or 0) if existing_memory else 0,
    )

    # ===================================
    # Override detector values
    # ===================================

    trust_result["conflict_score"] = max(
        trust_result["conflict_score"],
        conflict_score
    )

    trust_result["poison_score"] = max(
        trust_result["poison_score"],
        poison_score
    )


    # ===================================
    # ML FINAL DECISION
    # ===================================

    final_decision = ml_decision

    # ===================================
    # QUARANTINE
    # ===================================

    if final_decision == "QUARANTINE":

        quarantine_record = (

            quarantine_memory(

                db=db,

                user_id=user_id,

                fact=fact,

                category=
                    security_result[
                        "category"
                    ],

                attack_type=
                    attack_type,

                reason=
                    "Memory poisoning review",

                risk_score=
                    security_result[
                        "risk_score"
                    ],

                poison_score=
                    trust_result[
                        "poison_score"
                    ]

            )

        )

        log_poison_event(

            db=db,

            attack_type=
                attack_type,

            poison_score=
                trust_result[
                    "poison_score"
                ],

            decision=
                final_decision,

            details=
                fact

        )

        return {

            "status":
                "quarantined",

            "quarantine_id":
                quarantine_record.id,

            "attack_type":
                attack_type,

            "decision":
                final_decision

        }

    # ===================================
    # BLOCK
    # ===================================

    if final_decision == "BLOCK":

        log_poison_event(

            db=db,

            attack_type=
                attack_type,

            poison_score=
                trust_result[
                    "poison_score"
                ],

            decision=
                final_decision,

            details=
                fact

        )

        if attack_type == "TOOL_POLICY_POISONING":

            log_tool_policy_event(

                db=db,

                user_id=user_id,

                policy_text=fact,

                violation_reason=(
                    conflict_result.get(
                        "violation_reason"
                    )
                    if conflict_result
                    else ""
                ),

                risk_score=trust_result[
                    "poison_score"
                ],

                decision=final_decision,

                unapproved_domains=",".join(
                    security_result.get(
                        "tool_policy_unapproved_domains",
                        []
                    )
                ),

                memory_id=(
                    existing_memory.id
                    if existing_memory
                    else None
                ),

            )

        return {

            "status":
                "blocked",

            "attack_type":
                attack_type,

            "decision":
                final_decision

            }

    # ===================================
    # STORE MEMORY
    # ===================================
    # ===================================
    # Archive previous version
    # ===================================

    if (
        conflict_detected
        and
        attack_type
        in (
            "NONE",
            "PREFERENCE_UPDATE",
            "TOOL_POLICY_UPDATE",
        )
        and
        existing_memory
    ):

        existing_memory.active = False
        existing_memory.status = "ARCHIVED"
        existing_memory.conflict_count = (
            (getattr(existing_memory, "conflict_count", 0) or 0) + 1
        )

        remove_memory_embedding(existing_memory.id)

        if (
            attack_type
            ==
            "PREFERENCE_UPDATE"
            and
            existing_memory
        ):

            log_preference_event(

                db=db,

                user_id=user_id,

                memory_id=existing_memory.id,

                old_fact=existing_memory.fact,

                new_fact=fact,

                category=security_result[
                    "category"
                ],

                stability_score=(
                    stability_score or 1.0
                ),

                drift_score=(
                    drift_score or 0.0
                ),

                is_legitimate_update=True,

                attack_type="PREFERENCE_UPDATE"

            )

        log_memory_history(

            db=db,

            old_memory=
                existing_memory,

            new_fact=
                fact,

            new_version=
                new_version

        )

        db.commit()
    memory = Memory(

        user_id=user_id,

        fact=fact,

        category=
            security_result[
                "category"
            ],
        memory_type=
    security_result[
        "memory_type"
    ],
        trust_score=
            trust_result[
                "trust_score"
            ],

        confidence_score=
            trust_result[
                "confidence_score"
            ],

        conflict_score=
            trust_result[
                "conflict_score"
            ],

        poison_score=
            trust_result[
                "poison_score"
            ],

        risk_score=
            security_result[
                "risk_score"
            ],

        source="USER",

        attack_type=
            attack_type,

        final_decision=
            final_decision,

        poison_flag=
            trust_result[
                "poison_score"
            ] > 0.8,

        memory_version=
            new_version,
        parent_memory_id=
    parent_memory_id,

        # For research purposes, keep all memories active
        active=True,

        # For research purposes, keep all memories as ACTIVE status
        status="ACTIVE",
        verification_count=1,

        preference_stability_score=
            stability_score,

        preference_drift_score=
            drift_score,
        ml_prediction=
    ml_prediction,

ml_confidence=
    ml_confidence,

ml_decision=
    ml_decision

    )

    import json
    explanation = trust_result.get("trust_explanation", {})
    if explanation:
        memory.trust_explanation = json.dumps(explanation)

    db.add(memory)

    db.commit()

    db.refresh(memory)

    import os

    BENCHMARK_MODE = (
        os.getenv(
            "ATTACKLAYER_BENCHMARK",
            "0"
        ) == "1"
    )

    if (
        final_decision != "ALLOW_WITH_WARNING"
        and
        not BENCHMARK_MODE
    ):

        embedding = generate_embedding(
            fact
        )

        add_memory_embedding(

            memory.id,

            fact,

            embedding

        )

    return {

    "status":
        (
            "pending_review"
            if final_decision in ("ALLOW_WITH_WARNING", "REVIEW")
            else "stored"
        ),

    "memory_id":
        memory.id,

    "memory_version":
        memory.memory_version,

    "decision":
        final_decision,

    "attack_type":
        attack_type,

    "poison_score":
        trust_result[
            "poison_score"
        ],

    "conflict_detected":
        conflict_detected,

    "category":
        security_result["category"],
    "memory_type":
    security_result[
        "memory_type"
    ],
    "trust_score":
        trust_result["trust_score"],

    "security":
        security_result,
    "ml_prediction":
    ml_prediction,

"ml_confidence":
    ml_confidence,

"ml_decision":
    ml_decision
    

}


def get_all_memories(
    db: Session
):
    return db.query(
        Memory
    ).all()


def get_memory_by_id(
    db: Session,
    memory_id: int
):
    return (
        db.query(Memory)
        .filter(
            Memory.id == memory_id
        )
        .first()
    )


def archive_memory(
    db: Session,
    memory_id: int
):

    memory = (
        db.query(Memory)
        .filter(
            Memory.id == memory_id
        )
        .first()
    )

    if not memory:
        return None

    memory.active = False
    memory.status = "ARCHIVED"

    remove_memory_embedding(
        memory_id
    )

    db.commit()

    db.refresh(memory)

    return memory


def get_memory_history(
    db,
    memory_id
):

    return (
        db.query(
            MemoryHistory
        )
        .filter(
            MemoryHistory.memory_id
            == memory_id
        )
        .all()
    )


def delete_memory(db: Session, memory_id: int):
    memory = (
        db.query(Memory)
        .filter(Memory.id == memory_id)
        .first()
    )
    if not memory:
        return None

    remove_memory_embedding(memory_id)
    db.delete(memory)
    db.commit()
    return {"status": "deleted", "memory_id": memory_id}


def get_memory_trust(db: Session, memory_id: int):
    memory = (
        db.query(Memory)
        .filter(Memory.id == memory_id)
        .first()
    )
    if not memory:
        return None

    import json
    explanation = {}
    raw = getattr(memory, "trust_explanation", None)
    if raw:
        try:
            explanation = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            explanation = {"summary": str(raw)}

    return {
        "memory_id": memory.id,
        "trust_score": memory.trust_score,
        "confidence_score": memory.confidence_score,
        "conflict_score": memory.conflict_score,
        "poison_score": memory.poison_score,
        "category": memory.category,
        "memory_type": getattr(memory, "memory_type", "LONG_TERM"),
        "attack_type": memory.attack_type,
        "verification_count": memory.verification_count or 0,
        "trust_explanation": explanation,
    }


def clear_episodic_memories(db: Session):
    memories = (
        db.query(Memory)
        .filter(Memory.memory_type == "EPISODIC", Memory.active == True)
        .all()
    )
    count = 0
    for memory in memories:
        remove_memory_embedding(memory.id)
        db.delete(memory)
        count += 1
    db.commit()
    return count


def clear_short_term_memories(db: Session):
    memories = (
        db.query(Memory)
        .filter(Memory.memory_type == "SHORT_TERM", Memory.active == True)
        .all()
    )
    count = 0
    for memory in memories:
        remove_memory_embedding(memory.id)
        db.delete(memory)
        count += 1
    db.commit()
    return count


def clear_long_term_memories(db: Session):
    memories = (
        db.query(Memory)
        .filter(Memory.memory_type == "LONG_TERM", Memory.active == True)
        .all()
    )
    count = 0
    for memory in memories:
        remove_memory_embedding(memory.id)
        db.delete(memory)
        count += 1
    db.commit()
    return count


def refresh_memory(db: Session, memory_id: int):
    memory = (
        db.query(Memory)
        .filter(Memory.id == memory_id)
        .first()
    )
    if not memory:
        return None

    # Re-evaluate safety
    security_result = evaluate_security(memory.fact, db=db, user_id=memory.user_id)
    
    # ML Decision Layer
    embedding = generate_embedding(memory.fact)
    decision_output = predict_decision(embedding)
    ml_prediction = decision_output["prediction"]
    ml_confidence = decision_output["confidence"]
    ml_decision = map_decision(ml_prediction, ml_confidence)

    # Determine if the memory fact contains an attack
    is_attack = False
    if (
        security_result["decision"] == "BLOCK"
        or security_result["attack_type"] != "SAFE"
        or ml_decision == "BLOCK"
    ):
        is_attack = True

    if is_attack:
        # Remove from vector storage
        remove_memory_embedding(memory.id)
        
        # Deactivate in the database and mark status
        memory.active = False
        memory.status = "WAITING_APPROVAL"
        memory.final_decision = "ALLOW_WITH_WARNING"
        memory.poison_flag = True
        memory.attack_type = security_result.get("attack_type") or "ML_ATTACK"
        
        from app.audit.logger import log_security_event
        log_security_event(
            db=db,
            operation="REFRESH_SCAN",
            decision="ALLOW_WITH_WARNING",
            threat=security_result.get("attack_type") or "ML_ATTACK",
            risk_score=security_result.get("risk_score", 0.9),
            payload=memory.fact,
            final_decision="ALLOW_WITH_WARNING",
            explanation={
                "security_result": {"decision": "BLOCK"},
                "reason": "Attack detected during memory refresh scan"
            },
            memory_id=memory.id,
            ip_address=None
        )
        db.commit()
        db.refresh(memory)
        return {
            "status": "sent_to_approval",
            "memory_id": memory_id,
            "fact": memory.fact,
            "attack_type": security_result.get("attack_type") or "ML_ATTACK",
            "decision": "ALLOW_WITH_WARNING"
        }
    else:
        # It's safe, keep it and update details
        memory.attack_type = security_result["attack_type"]
        memory.final_decision = security_result["decision"]
        memory.poison_score = security_result.get("risk_score", memory.poison_score)
        
        from app.audit.logger import log_security_event
        log_security_event(
            db=db,
            operation="REFRESH_SCAN",
            decision="ALLOW",
            threat="SAFE",
            risk_score=security_result.get("risk_score", 0.0),
            payload=memory.fact,
            final_decision="ALLOW",
            explanation={
                "security_result": {"decision": "ALLOW"},
                "reason": "Verified safe during memory refresh scan"
            },
            memory_id=memory.id,
            ip_address=None
        )
        db.commit()
        db.refresh(memory)
        return {
            "status": "safe",
            "memory_id": memory_id,
            "fact": memory.fact,
            "attack_type": memory.attack_type,
            "decision": memory.final_decision
        }


def refresh_memories_by_type(db: Session, memory_type: str):
    memories = (
        db.query(Memory)
        .filter(Memory.memory_type == memory_type)
        .all()
    )
    
    removed = []
    safe = []
    
    for memory in memories:
        # Re-evaluate safety
        security_result = evaluate_security(memory.fact, db=db, user_id=memory.user_id)
        
        # ML Decision Layer
        embedding = generate_embedding(memory.fact)
        decision_output = predict_decision(embedding)
        ml_prediction = decision_output["prediction"]
        ml_confidence = decision_output["confidence"]
        ml_decision = map_decision(ml_prediction, ml_confidence)

        is_attack = False
        if (
            security_result["decision"] == "BLOCK"
            or security_result["attack_type"] != "SAFE"
            or ml_decision == "BLOCK"
        ):
            is_attack = True

        if is_attack:
            # Send to human approval & remove from memory
            remove_memory_embedding(memory.id)
            memory.active = False
            memory.status = "WAITING_APPROVAL"
            memory.final_decision = "ALLOW_WITH_WARNING"
            memory.poison_flag = True
            memory.attack_type = security_result.get("attack_type") or "ML_ATTACK"
            
            from app.audit.logger import log_security_event
            log_security_event(
                db=db,
                operation="REFRESH_SCAN",
                decision="ALLOW_WITH_WARNING",
                threat=security_result.get("attack_type") or "ML_ATTACK",
                risk_score=security_result.get("risk_score", 0.9),
                payload=memory.fact,
                final_decision="ALLOW_WITH_WARNING",
                explanation={
                    "security_result": {"decision": "BLOCK"},
                    "reason": f"Attack detected during batch {memory_type} memory refresh scan"
                },
                memory_id=memory.id,
                ip_address=None
            )
            removed.append({
                "id": memory.id,
                "fact": memory.fact,
                "attack_type": security_result.get("attack_type") or "ML_ATTACK"
            })
        else:
            memory.attack_type = security_result["attack_type"]
            memory.final_decision = security_result["decision"]
            memory.poison_score = security_result.get("risk_score", memory.poison_score)
            
            from app.audit.logger import log_security_event
            log_security_event(
                db=db,
                operation="REFRESH_SCAN",
                decision="ALLOW",
                threat="SAFE",
                risk_score=security_result.get("risk_score", 0.0),
                payload=memory.fact,
                final_decision="ALLOW",
                explanation={
                    "security_result": {"decision": "ALLOW"},
                    "reason": f"Verified safe during batch {memory_type} memory refresh scan"
                },
                memory_id=memory.id,
                ip_address=None
            )
            safe.append({
                "id": memory.id,
                "fact": memory.fact,
                "attack_type": memory.attack_type
            })
            
    db.commit()
    return {
        "status": "success",
        "memory_type": memory_type,
        "total_checked": len(memories),
        "removed_count": len(removed),
        "removed_memories": removed,
        "safe_count": len(safe)
    }


