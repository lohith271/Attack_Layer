"""Shared audit event serialization."""

import json

from app.database.models import AuditEvent


def serialize_audit_event(event: AuditEvent) -> dict:
    retrieved = []
    memories_used = []
    explanation = {}
    trust_scores = []

    try:
        retrieved = json.loads(event.retrieved_memories or "[]")
    except (json.JSONDecodeError, TypeError):
        pass

    try:
        memories_used = json.loads(event.memories_used or "[]")
    except (json.JSONDecodeError, TypeError):
        pass

    try:
        explanation = json.loads(event.explanation or "{}")
    except (json.JSONDecodeError, TypeError):
        pass

    try:
        trust_scores = json.loads(getattr(event, "trust_scores", "[]") or "[]")
    except (json.JSONDecodeError, TypeError):
        pass

    return {
        "id": event.id,
        "time": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
        "prompt": event.payload,
        "operation": event.operation,
        "threat": event.threat if event.threat else "NONE",
        "risk_score": round(event.risk_score, 4),
        "decision": event.decision,
        "intent": getattr(event, "intent", "UNKNOWN") or "UNKNOWN",
        "intent_confidence": round(
            getattr(event, "intent_confidence", 0.0) or 0.0, 4
        ),
        "attack_type": getattr(event, "attack_type", "SAFE") or "SAFE",
        "attack_confidence": round(
            getattr(event, "attack_confidence", 0.0) or 0.0, 4
        ),
        "risk_level": getattr(event, "risk_level", "LOW") or "LOW",
        "memory_category": getattr(event, "memory_category", "GENERAL") or "GENERAL",
        "conflict_status": getattr(event, "conflict_status", "NONE") or "NONE",
        "trust_scores": trust_scores,
        "retrieved_memories": retrieved,
        "memories_used": memories_used,
        "poison_detected": getattr(event, "poison_detected", False) or False,
        "quarantine_status": getattr(event, "quarantine_status", "NONE") or "NONE",
        "response_confidence": round(
            getattr(event, "response_confidence", 0.0) or 0.0, 4
        ),
        "execution_time_ms": round(
            getattr(event, "execution_time_ms", 0.0) or 0.0, 2
        ),
        "final_decision": getattr(event, "final_decision", event.decision) or event.decision,
        "explanation": explanation,
        "ip_address": getattr(event, "ip_address", None),
    }
