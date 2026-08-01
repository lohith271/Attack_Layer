from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from app.database.session import get_db
from app.memory.vault import (
    get_all_memories,
    archive_memory,
    delete_memory,
    get_memory_history,
    get_memory_trust,
    clear_episodic_memories,
    clear_short_term_memories,
    clear_long_term_memories,
)
from app.database.models import MemoryHistory

router = APIRouter(prefix="/memory", tags=["Memory"])


def _serialize_memory(memory):
    import json
    trust_explanation = {}
    raw = getattr(memory, "trust_explanation", None)
    if raw:
        try:
            trust_explanation = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            trust_explanation = {}

    return {
        "id": memory.id,
        "unique_id": getattr(memory, "unique_id", None),
        "user_id": memory.user_id,
        "fact": memory.fact,
        "category": memory.category,
        "memory_type": getattr(memory, "memory_type", "LONG_TERM"),
        "trust_score": round(memory.trust_score, 4),
        "confidence_score": round(memory.confidence_score, 4),
        "conflict_score": round(memory.conflict_score, 4),
        "poison_score": round(memory.poison_score, 4),
        "risk_score": round(memory.risk_score, 4),
        "attack_type": memory.attack_type,
        "decision": memory.final_decision,
        "memory_version": memory.memory_version,
        "verified": memory.verified,
        "poison_flag": memory.poison_flag,
        "status": getattr(memory, "status", None) or ("ACTIVE" if memory.active else "INACTIVE"),
        "source": memory.source,
        "importance_score": round(getattr(memory, "importance_score", 0.5) or 0.5, 4),
        "verification_count": getattr(memory, "verification_count", 0) or 0,
        "conflict_count": getattr(memory, "conflict_count", 0) or 0,
        "usage_count": getattr(memory, "usage_count", 0) or 0,
        "created_at": memory.created_at.isoformat() if memory.created_at else None,
        "updated_at": memory.updated_at.isoformat() if memory.updated_at else None,
        "trust_explanation": trust_explanation,
    }


@router.get("/all")
def all_memories(db: Session = Depends(get_db)):
    memories = get_all_memories(db)
    return [_serialize_memory(m) for m in memories]


@router.delete("/{memory_id}")
def remove_memory(memory_id: int, db: Session = Depends(get_db)):
    result = delete_memory(db, memory_id)
    if not result:
        return {"status": "not_found", "memory_id": memory_id}
    return result


@router.post("/archive/{memory_id}")
def archive(memory_id: int, db: Session = Depends(get_db)):
    memory = archive_memory(db, memory_id)
    if not memory:
        return {"status": "not_found"}
    return _serialize_memory(memory)


@router.get("/trust/{memory_id}")
def memory_trust(memory_id: int, db: Session = Depends(get_db)):
    result = get_memory_trust(db, memory_id)
    if not result:
        return {"status": "not_found"}
    return result


@router.get("/history/{memory_id}")
def history(memory_id: int, db: Session = Depends(get_db)):
    history_items = get_memory_history(db, memory_id)
    return [
        {
            "id": item.id,
            "old_fact": item.old_fact,
            "new_fact": item.new_fact,
            "category": item.category,
            "old_version": item.old_version,
            "new_version": item.new_version,
            "time": item.created_at.strftime("%H:%M:%S") if item.created_at else "Unknown",
        }
        for item in history_items
    ]


@router.get("/history")
def full_history(db: Session = Depends(get_db)):
    records = (
        db.query(MemoryHistory)
        .order_by(MemoryHistory.id.desc())
        .all()
    )
    return [
        {
            "memory_id": item.memory_id,
            "old_fact": item.old_fact,
            "new_fact": item.new_fact,
            "category": item.category,
            "old_version": item.old_version,
            "new_version": item.new_version,
            "time": item.created_at.strftime("%H:%M:%S") if item.created_at else "Unknown",
        }
        for item in records
    ]


@router.delete("/episodic")
def clear_episodic(db: Session = Depends(get_db)):
    count = clear_episodic_memories(db)
    return {"status": "success", "cleared_count": count}


@router.delete("/short-term")
def clear_short_term(db: Session = Depends(get_db)):
    count = clear_short_term_memories(db)
    return {"status": "success", "cleared_count": count}


@router.delete("/long-term")
def clear_long_term(db: Session = Depends(get_db)):
    count = clear_long_term_memories(db)
    return {"status": "success", "cleared_count": count}


@router.post("/refresh/{memory_id}")
def refresh_single(memory_id: int, db: Session = Depends(get_db)):
    from app.memory.vault import refresh_memory
    from app.audit.logger import log_security_event
    result = refresh_memory(db, memory_id)
    if result:
        log_security_event(
            db=db,
            operation="REFRESH_ACTION",
            decision="ALLOW",
            threat="NONE",
            risk_score=0.0,
            payload=f"Refreshed memory {memory_id}",
            final_decision="ALLOW"
        )
    if not result:
        return {"status": "not_found", "memory_id": memory_id}
    return result


@router.post("/refresh-type/{memory_type}")
def refresh_by_type(memory_type: str, db: Session = Depends(get_db)):
    from app.memory.vault import refresh_memories_by_type
    from app.audit.logger import log_security_event
    mtype = memory_type.upper().replace("-", "_")
    result = refresh_memories_by_type(db, mtype)
    log_security_event(
        db=db,
        operation="REFRESH_ACTION",
        decision="ALLOW",
        threat="NONE",
        risk_score=0.0,
        payload=f"Refreshed memory type {mtype}",
        final_decision="ALLOW"
    )
    return result

