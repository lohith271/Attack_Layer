from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import AuditEvent
from app.database.models import (
    AuditEvent,
    Memory
)

from app.memory.embedding_service import (
    generate_embedding
)

from app.memory.vector_storage import (
    add_memory_embedding
)

router = APIRouter(prefix="/hitl", tags=["HITL"])


@router.get("/queue")
def get_hitl_queue(db: Session = Depends(get_db)):
    """
    Get all audit events that are pending human review (ALLOW_WITH_WARNING).
    """
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.final_decision == "ALLOW_WITH_WARNING")
        .order_by(AuditEvent.id.desc())
        .all()
    )

    import json
    result = []
    for event in events:
        explanation = event.explanation or {}
        if isinstance(explanation, str):
            try:
                explanation = json.loads(explanation)
            except Exception:
                explanation = {}
                
        # Ensure it hasn't been approved/rejected already
        if "human_decision" in explanation:
            continue
            
        result.append({
            "id": event.id,
            "prompt": event.payload,
            "threat_type": event.threat if event.threat else "NONE",
            "severity": event.risk_level if event.risk_level else "LOW",
            "detection_reason": explanation.get("security_result", {}).get("decision", "UNKNOWN"),
            "timestamp": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "human_decision": explanation.get("human_decision"),
            "memory_id": event.memory_id
        })

    return result


@router.post("/approve/{request_id}")
def approve_hitl_request(request_id: int, db: Session = Depends(get_db)):
    """
    Approve a HITL request: change final_decision to ALLOW and add note.
    """
    event = db.query(AuditEvent).filter(AuditEvent.id == request_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Request not found")
    if event.final_decision != "ALLOW_WITH_WARNING":
        raise HTTPException(status_code=400, detail="Request is not pending review")

    from datetime import datetime
    # Update the event
    event.final_decision = "ALLOW"
    # Update explanation to note human approval
    import json
    explanation = event.explanation or {}
    if isinstance(explanation, str):
        try:
            explanation = json.loads(explanation)
        except Exception:
            explanation = {}
            
    explanation["human_decision"] = "APPROVED"
    explanation["human_decision_timestamp"] = datetime.utcnow().isoformat()

    final_response = "Got it. I've updated your memory."
    if not event.memory_id:
        # Generate response using Ollama and secure context
        from app.llm.orchestrator import _should_use_personal_context
        from app.memory.retrieval import retrieve_memories
        from app.security.context_builder import build_secure_context
        from app.llm.service import generate_response

        message = event.payload
        user_id = explanation.get("user_id", "default")
        
        secure_context = ""
        if _should_use_personal_context(message):
            retrieval_result = retrieve_memories(
                db=db,
                user_id=user_id,
                query=message,
            )
            ranked_memories = retrieval_result.get("ranked_memories", [])
            secure_context = build_secure_context(
                query=message,
                safe_memories=retrieval_result["safe_memories"],
                ranked_memories=ranked_memories,
            )

        llm_response = generate_response(query=message, secure_context=secure_context)
        final_response = llm_response

    explanation["human_decision_response"] = final_response
    event.explanation = json.dumps(explanation)

    # ------------------------
    # Activate pending memory
    # ------------------------
    if event.memory_id:
        memory = (
            db.query(Memory)
            .filter(
                Memory.id == event.memory_id
            )
            .first()
        )

        if memory:
            memory.active = True
            memory.status = "ACTIVE"
            embedding = generate_embedding(
                memory.fact
            )
            add_memory_embedding(
                memory.id,
                memory.fact,
                embedding
            )

    db.commit()
    db.refresh(event)

    return {"status": "approved", "request_id": request_id, "response": final_response}


@router.post("/reject/{request_id}")
def reject_hitl_request(request_id: int, db: Session = Depends(get_db)):
    """
    Reject a HITL request: change final_decision to BLOCK and add note.
    """
    event = db.query(AuditEvent).filter(AuditEvent.id == request_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Request not found")
    if event.final_decision != "ALLOW_WITH_WARNING":
        raise HTTPException(status_code=400, detail="Request is not pending review")

    from datetime import datetime
    # Update the event
    event.final_decision = "BLOCK"
    # Update explanation to note human rejection
    import json
    explanation = event.explanation or {}
    if isinstance(explanation, str):
        try:
            explanation = json.loads(explanation)
        except Exception:
            explanation = {}
            
    explanation["human_decision"] = "REJECTED"
    explanation["human_decision_timestamp"] = datetime.utcnow().isoformat()
    event.explanation = json.dumps(explanation)

    # ------------------------
    # Remove pending memory
    # ------------------------

    if event.memory_id:

        memory = (
            db.query(Memory)
            .filter(
                Memory.id == event.memory_id
            )
            .first()
        )

        if memory:

            db.delete(memory)

    db.commit()

    db.refresh(event)

    return {"status": "rejected", "request_id": request_id}
@router.get("/status/{request_id}")
def get_hitl_status(
    request_id: int,
    db: Session = Depends(get_db)
):

    event = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.id == request_id
        )
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Request not found"
        )

    import json

    explanation = event.explanation or {}

    if isinstance(explanation, str):
        try:
            explanation = json.loads(
                explanation
            )
        except Exception:
            explanation = {}

    human_decision = explanation.get(
        "human_decision"
    )

    if not human_decision:
        return {
            "resolved": False
        }

    if human_decision == "APPROVED":
        if event.memory_id:
            response = f"✓ Request #{request_id} Approved. Your memory has been saved and is now active."
        else:
            ollama_resp = explanation.get("human_decision_response") or "Your request was approved by a human reviewer and has been processed."
            response = f"✓ Request #{request_id} Approved:\n{ollama_resp}"
    elif human_decision == "IP_BLOCKED":
        response = explanation.get("human_decision_response") or f"⛔ **Security Notice**: Your IP address (`{event.ip_address}`) has been reviewed and officially BLOCKED by human security approval. You can no longer send messages or save memories."
    else:
        if event.memory_id:
            response = f"⚠ Request #{request_id} Rejected. The memory update was blocked by human review."
        else:
            response = f"⚠ Request #{request_id} Rejected. Your request was reviewed and rejected by a human reviewer. It has been blocked."

    return {
        "resolved": True,
        "decision": human_decision,
        "response": response
    }
@router.get("/resolved")
def get_resolved_hitl_items(db: Session = Depends(get_db)):
    """
    Get all HITL requests that have already been approved or rejected.
    """
    import json
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.final_decision.in_(["ALLOW", "BLOCK"]))
        .order_by(AuditEvent.id.desc())
        .limit(50)
        .all()
    )

    result = []
    for event in events:
        explanation = event.explanation or {}
        if isinstance(explanation, str):
            try:
                explanation = json.loads(explanation)
            except Exception:
                explanation = {}

        human_decision = explanation.get("human_decision")
        if not human_decision:
            continue  # was auto-allowed/blocked, not HITL

        result.append({
            "id": event.id,
            "prompt": event.payload,
            "status": "approved" if human_decision == "APPROVED" else "rejected",
            "response": "Got it. I've updated your memory." if human_decision == "APPROVED"
                        else "Request rejected and blocked by security policy.",
            "timestamp": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "memory_id": event.memory_id
        })

    return result


@router.post("/ip/approve/{ip_address}")
def approve_ip_block(ip_address: str, db: Session = Depends(get_db)):
    """Human Reviewer approves blocking the specified IP address."""
    from app.database.models import BlockedIP, AuditEvent
    import json

    entry = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    if not entry:
        entry = BlockedIP(ip_address=ip_address, status="BLOCKED", approved_by_human=True)
        db.add(entry)
    else:
        entry.status = "BLOCKED"
        entry.approved_by_human = True

    block_notice = f"⛔ **Security Notice**: Your IP address (`{ip_address}`) has been reviewed and officially BLOCKED by human security approval. You can no longer send messages or save memories."

    # Update explanation for recent audit events from this IP so HITL status polling gets the blocked notification
    recent_events = (
        db.query(AuditEvent)
        .filter(AuditEvent.ip_address == ip_address)
        .order_by(AuditEvent.id.desc())
        .limit(20)
        .all()
    )

    for ev in recent_events:
        exp = ev.explanation or {}
        if isinstance(exp, str):
            try:
                exp = json.loads(exp)
            except Exception:
                exp = {}
        exp["human_decision"] = "IP_BLOCKED"
        exp["human_decision_response"] = block_notice
        ev.explanation = json.dumps(exp)
        ev.final_decision = "BLOCK"

    db.commit()

    return {
        "status": "approved",
        "message": f"IP {ip_address} has been approved for blocking and is now officially BLOCKED.",
        "ip_address": ip_address,
        "notification": block_notice
    }


@router.post("/ip/reject/{ip_address}")
def reject_ip_block(ip_address: str, db: Session = Depends(get_db)):
    """Human Reviewer rejects blocking the IP address (resets block state)."""
    from app.database.models import BlockedIP
    entry = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    if entry:
        entry.status = "TRUSTED"
        entry.approved_by_human = False
        db.commit()

    return {
        "status": "rejected",
        "message": f"IP {ip_address} block request was rejected. IP is now marked as Trusted.",
        "ip_address": ip_address
    }


@router.get("/ip/pending")
def get_pending_ip_approvals(db: Session = Depends(get_db)):
    """Fetch all IP addresses pending human approval (status == PENDING)."""
    from app.database.models import BlockedIP
    entries = db.query(BlockedIP).filter(BlockedIP.status == "PENDING").all()
    result = []
    for entry in entries:
        pct = round((entry.block_rate or 0.0) * 100, 1)
        result.append({
            "id": entry.id,
            "ip_address": entry.ip_address,
            "status": entry.status,
            "block_count": entry.block_count,
            "total_interactions": entry.total_interactions,
            "block_rate_pct": pct,
            "reason": entry.reason or "EXCESSIVE_BLOCKS",
            "detection_reason": f"Exceeded 85% block rate threshold ({pct}% blocked out of {entry.total_interactions} interactions)",
            "timestamp": entry.updated_at.strftime("%Y-%m-%d %H:%M:%S") if entry.updated_at else "Unknown"
        })
    return result


@router.get("/ip/resolved")
def get_resolved_ip_approvals(db: Session = Depends(get_db)):
    """Fetch all resolved IP address block decisions (status in BLOCKED, TRUSTED)."""
    from app.database.models import BlockedIP
    entries = db.query(BlockedIP).filter(BlockedIP.status.in_(["BLOCKED", "TRUSTED"])).order_by(BlockedIP.updated_at.desc()).all()
    result = []
    for entry in entries:
        pct = round((entry.block_rate or 0.0) * 100, 1)
        result.append({
            "id": entry.id,
            "ip_address": entry.ip_address,
            "status": "approved" if entry.status == "BLOCKED" and entry.approved_by_human else "rejected",
            "decision": entry.status,
            "block_count": entry.block_count,
            "total_interactions": entry.total_interactions,
            "block_rate_pct": pct,
            "response": f"IP officially BLOCKED (Human Approved)" if (entry.status == "BLOCKED" and entry.approved_by_human) else "IP marked as TRUSTED (Block Rejected)",
            "timestamp": entry.updated_at.strftime("%Y-%m-%d %H:%M:%S") if entry.updated_at else "Unknown"
        })
    return result
