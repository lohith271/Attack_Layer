from app.security.intent_classifier import classify_intent
from app.security.security_classifier import classify_security
from app.security.sensitive_detector import detect_sensitive_data
from app.security.semantic_classifier import (
    classify_memory,
    classify_memory_type,
)
from app.security.explainability import build_explanation


def evaluate_security(text: str, db=None, user_id=None):
    from app.agents import orchestrator
    return orchestrator.evaluate_security(text, db=db, user_id=user_id)
