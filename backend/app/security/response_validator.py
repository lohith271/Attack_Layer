# backend/app/security/response_validator.py
"""
V2 Response Validator — checks response before delivery.
"""

import re

from app.security.sensitive_detector import detect_sensitive_data
from app.security.response_guard import filter_response

LEAK_PATTERNS = [
    r"system\s*prompt",
    r"internal\s*architecture",
    r"hidden\s*instructions",
    r"attacklayer\s*pipeline",
    r"security\s*gateway",
    r"chroma\s*database",
    r"sqlite\s*database",
    r"orchestrator",
]

# New list to detect malicious safety overrides in the generated response
MALICIOUS_PATTERNS = [
    r"override\s*safety",
    r"security\s*checks\s*(are\s*)?disabled",
    r"ignore\s*safety\s*guidelines",
    r"disable\s*security",
    r"bypass\s*safety",
]

ARCHITECTURE_TERMS = [
    "security_gateway",
    "intent_classifier",
    "memory_vault",
    "quarantine_manager",
    "poison_propagation",
]


def validate_response(
    response,
    query,
    memories_used=None,
    security_result=None,
):
    issues = []
    guard = filter_response(response)
    final_response = guard["response"]

    if guard.get("blocked"):
        issues.append("Sensitive data detected in response")

    # 1. Check for system prompt leaks
    for pattern in LEAK_PATTERNS:
        if re.search(pattern, final_response, re.IGNORECASE):
            issues.append("Potential system prompt leak detected")
            break

    # 2. Check for internal architecture leaks
    for term in ARCHITECTURE_TERMS:
        if term.lower() in final_response.lower():
            issues.append("Internal architecture details leaked")
            break

    # 3. Double-check for malicious safety overrides in generated response
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, final_response, re.IGNORECASE):
            issues.append("Malicious safety override attempt detected in LLM generation")
            # Force block the response and replace it with a warning
            guard["blocked"] = True
            final_response = "⚠️ [Response Blocked] The generated response was influenced by a malicious memory and tried to override safety guidelines."
            break

    # 4. Check the generated response against the security gateway (Ensemble ML & Heuristics)
    from app.security.security_gateway import evaluate_security
    security_eval = evaluate_security(final_response)
    if security_eval.get("decision") == "BLOCK" or security_eval.get("risk_score", 0.0) >= 0.70:
        issues.append(f"Security gateway blocked generated output: {security_eval.get('attack_type', 'UNSAFE')}")
        guard["blocked"] = True
        final_response = "⚠️ [Response Blocked] The generated response was classified as unsafe or an adversarial attack by the security gateway."

    poisoned_used = False
    for mem in memories_used or []:
        trust = mem.get("trust_score", 1.0) if isinstance(mem, dict) else 1.0
        poison = mem.get("poison_score", 0.0) if isinstance(mem, dict) else 0.0
        if trust < 0.4 or poison > 0.7:
            poisoned_used = True
            issues.append("Low-trust or poisoned memory may have influenced response")
            # Force block the response immediately because a poisoned memory was used in context
            guard["blocked"] = True
            final_response = "⚠️ [Response Blocked] The response generation was blocked because a low-trust or poisoned memory was retrieved."
            break

    memory_confidence = 0.9
    if not memories_used:
        memory_confidence = 0.7 if "remember" in query.lower() else 0.85
    elif poisoned_used:
        memory_confidence = 0.4

    security_confidence = 0.95
    if security_result and security_result.get("attack_type") != "SAFE":
        if security_result.get("decision") == "ALLOW":
            security_confidence = 0.5
            issues.append("Attack may have bypassed input detection")

    response_confidence = 0.85
    if issues:
        response_confidence = max(0.3, 0.85 - len(issues) * 0.15)
    if guard.get("blocked"):
        response_confidence = 0.2

    should_regenerate = (
        response_confidence < 0.5
        and not guard.get("blocked")
        and len(issues) >= 2
    )

    return {
        "response": final_response,
        "response_confidence": round(response_confidence, 4),
        "memory_confidence": round(memory_confidence, 4),
        "security_confidence": round(security_confidence, 4),
        "issues": issues,
        "poisoned_memory_used": poisoned_used,
        "blocked": guard.get("blocked", False),
        "regenerated": False,
        "should_regenerate": should_regenerate,
    }