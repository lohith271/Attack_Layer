from app.agents.base_agent import BaseAgent
from app.security.intent_classifier import classify_intent
from app.security.security_classifier import classify_security
from app.security.sensitive_detector import detect_sensitive_data
from app.security.semantic_classifier import (
    classify_memory,
    classify_memory_type,
)

class RiskScoringAgent(BaseAgent):
    def __init__(self):
        super().__init__("RiskScoringAgent")

    def evaluate_risk(self, text: str, db=None, user_id=None):
        self.log(f"Evaluating security risk for: {text[:50]}...")
        intent_result = classify_intent(text, db=db, user_id=user_id)
        classification_result = classify_memory(text)
        memory_type_result = classify_memory_type(text)
        category = classification_result["category"]

        security_result = classify_security(text, category=category)
        sensitive_result = detect_sensitive_data(text)

        self.log(f"Intent classified: {intent_result.get('intent')} (confidence: {intent_result.get('confidence')})")
        self.log(f"Security classified: {security_result.get('attack_type')} (confidence: {security_result.get('confidence')})")
        self.log(f"Sensitive result: {sensitive_result.get('type')} (decision: {sensitive_result.get('decision')})")

        return {
            "intent_result": intent_result,
            "classification_result": classification_result,
            "memory_type_result": memory_type_result,
            "security_result": security_result,
            "sensitive_result": sensitive_result,
            "category": category,
        }
