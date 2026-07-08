from app.agents.base_agent import BaseAgent
from app.agents.risk_agent import RiskScoringAgent
from app.agents.policy_agent import PolicyAgent
from app.agents.memory_agent import MemoryAgent
from app.agents.analytics_agent import ThreatAnalyticsAgent

class SecurityOrchestrator(BaseAgent):
    def __init__(self):
        super().__init__("SecurityOrchestrator")
        self.risk_agent = RiskScoringAgent()
        self.policy_agent = PolicyAgent()
        self.memory_agent = MemoryAgent()
        self.analytics_agent = ThreatAnalyticsAgent()

    def evaluate_security(self, text: str, db=None, user_id=None) -> dict:
        self.log(f"Starting cooperative agent evaluation for input: {text[:50]}...")
        
        # 1. Run Risk Scoring Agent
        risk_result = self.risk_agent.evaluate_risk(text, db=db, user_id=user_id)
        
        # 2. Run Policy & Gatekeeper Agent
        policy_result = self.policy_agent.check_policy(risk_result)
        
        # Construct exact output format required by AttackLayer pipeline
        threat = policy_result["threat"]
        decision = policy_result["decision"]
        
        orchestration_result = {
            "input": text,
            "intent": policy_result["intent"],
            "intent_confidence": policy_result["intent_confidence"],
            "operation": policy_result["operation"],
            "operation_confidence": policy_result["operation_confidence"],
            "operation_scores": risk_result["intent_result"].get("scores", {}),
            "category": policy_result["category"],
            "category_confidence": policy_result["category_confidence"],
            "memory_type": policy_result["memory_type"],
            "memory_type_confidence": policy_result["memory_type_confidence"],
            "attack_type": policy_result["attack_type"],
            "attack_confidence": policy_result["attack_confidence"],
            "risk_level": policy_result["risk_level"],
            "threat": threat,
            "risk_score": policy_result["risk_score"],
            "sensitive_type": policy_result["sensitive_type"],
            "memory_poison_type": (
                policy_result["attack_type"]
                if policy_result["attack_type"] == "MEMORY_POISONING"
                else None
            ),
            "tool_policy_type": (
                policy_result["attack_type"]
                if policy_result["attack_type"] in ("TOOL_MANIPULATION", "TOOL_POLICY_MANIPULATION")
                else None
            ),
            "mitigation": policy_result["mitigation"],
            "decision": decision,
            "explanation": policy_result["explanation"],
        }
        
        self.log("Agent orchestration complete.")
        return orchestration_result

# Global singleton orchestrator
orchestrator = SecurityOrchestrator()
