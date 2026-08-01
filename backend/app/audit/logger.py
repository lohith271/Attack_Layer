import json

from app.database.models import AuditEvent


def log_security_event(
    db,
    operation,
    decision,
    threat,
    risk_score,
    payload,
    intent=None,
    intent_confidence=0.0,
    attack_type="SAFE",
    attack_confidence=0.0,
    risk_level="LOW",
    memory_category="GENERAL",
    conflict_status="NONE",
    trust_scores=None,
    retrieved_memories=None,
    memories_used=None,
    poison_detected=False,
    quarantine_status="NONE",
    response_confidence=0.0,
    memory_confidence=0.0,
    security_confidence=0.0,
    execution_time_ms=0.0,
    final_decision="ALLOW",
    explanation=None,
    memory_id=None,
    ip_address=None
):
    event = AuditEvent(
        operation=operation,
        decision=decision,
        threat=threat,
        risk_score=risk_score,
        payload=payload,
        intent=intent or "UNKNOWN",
        intent_confidence=intent_confidence,
        attack_type=attack_type,
        attack_confidence=attack_confidence,
        risk_level=risk_level,
        memory_category=memory_category,
        conflict_status=conflict_status,
        trust_scores=json.dumps(trust_scores or []),
        retrieved_memories=json.dumps(retrieved_memories or []),
        memories_used=json.dumps(memories_used or []),
        poison_detected=poison_detected,
        quarantine_status=quarantine_status,
        response_confidence=response_confidence,
        memory_confidence=memory_confidence,
        security_confidence=security_confidence,
        execution_time_ms=execution_time_ms,
        final_decision=final_decision,
        explanation=json.dumps(explanation or {}),
        memory_id=memory_id,
        ip_address=ip_address
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    if final_decision == "ALLOW_WITH_WARNING":
        try:
            from app.utils.email_service import send_approval_alert_email_async
            send_approval_alert_email_async(
                event_id=event.id,
                payload=payload,
                threat_type=threat,
                severity=risk_level,
                memory_id=memory_id
            )
        except Exception as e:
            import logging
            logging.getLogger("app.audit.logger").error(f"Failed to trigger async email alert: {e}")

    return event