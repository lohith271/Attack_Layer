from app.agents.base_agent import BaseAgent
from app.security.explainability import build_explanation

class PolicyAgent(BaseAgent):
    def __init__(self):
        super().__init__("PolicyAgent")

    def check_policy(self, risk_eval: dict) -> dict:
        self.log("Evaluating policy constraints...")
        intent_result = risk_eval["intent_result"]
        security_result = risk_eval["security_result"]
        sensitive_result = risk_eval["sensitive_result"]
        category = risk_eval["category"]

        decision = security_result.get("decision", "ALLOW")
        risk_score = security_result.get("risk_score", 0.0)

        if sensitive_result.get("decision") == "BLOCK":
            decision = "BLOCK"
            security_result["attack_type"] = "MEMORY_POISONING"
            security_result["risk_level"] = "HIGH"
            intent_result["intent"] = "SENSITIVE_DATA"
            intent_result["operation"] = "GENERAL_CHAT"
            intent_result["confidence"] = max(intent_result.get("confidence", 0.99), 0.99)

        elif security_result.get("decision") == "BLOCK":
            decision = "BLOCK"
            if security_result.get("attack_type") == "PROMPT_INJECTION":
                intent_result["intent"] = "PROMPT_INJECTION"
                intent_result["operation"] = "GENERAL_CHAT"
                intent_result["confidence"] = max(intent_result.get("confidence", 0.99), 0.99)

        elif security_result.get("decision") == "ALLOW_WITH_WARNING":
            decision = "ALLOW_WITH_WARNING"

        benign_categories = {
            "FOOD_PREFERENCE", "CODING_PREFERENCE", "PROFESSION", "LOCATION",
            "PERSONAL_INFO", "CAREER", "STUDY_DOMAIN", "GENERAL_FACT", "GENERAL",
        }
        if (
            category in benign_categories
            and security_result.get("attack_type") in ("SAFE", "SOCIAL_ENGINEERING", "SUSPICIOUS")
            and decision != "BLOCK"
        ):
            security_result["attack_type"] = "SAFE"
            decision = "ALLOW"
            risk_score = 0.0

        explanation = build_explanation(
            intent_result=intent_result,
            security_result=security_result,
            final_decision=decision,
        )

        threat = (
            security_result.get("attack_type", "SAFE")
            if security_result.get("attack_type", "SAFE") != "SAFE"
            else "NONE"
        )

        # Inject policy agent's own explanation step
        if isinstance(explanation, dict) and "reasons" in explanation:
            explanation["reasons"].append({
                "component": "policy_agent",
                "decision": decision,
                "confidence": 1.0,
                "reason": f"Gatekeeper evaluated threat '{threat}' with risk {risk_score:.2f} -> Verdict: {decision}"
            })

        self.log(f"Policy evaluation completed. Verdict: {decision}, Risk: {risk_score}")

        return {
            "decision": decision,
            "risk_score": risk_score,
            "threat": threat,
            "explanation": explanation,
            "intent": intent_result.get("intent"),
            "intent_confidence": intent_result.get("confidence"),
            "operation": intent_result.get("operation"),
            "operation_confidence": intent_result.get("confidence"),
            "category": category,
            "category_confidence": risk_eval["classification_result"].get("confidence"),
            "memory_type": risk_eval["memory_type_result"].get("memory_type"),
            "memory_type_confidence": risk_eval["memory_type_result"].get("confidence"),
            "attack_type": security_result.get("attack_type"),
            "attack_confidence": security_result.get("confidence"),
            "risk_level": security_result.get("risk_level"),
            "sensitive_type": sensitive_result.get("type"),
            "mitigation": security_result.get("mitigation", "NONE"),
        }
