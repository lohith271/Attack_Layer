import time
import json

from sqlalchemy.orm import Session

from app.memory.retrieval import retrieve_memories
from app.security.context_builder import build_secure_context
from app.llm.service import generate_response
from app.security.security_gateway import evaluate_security
from app.security.llm_guardrails import llm_input_filter, llm_output_filter
from app.memory.vault import create_memory
from app.security.response_validator import validate_response
from app.audit.logger import log_security_event
from app.memory.memory_normalizer import normalize_memory
from app.security.memory_worthiness import should_store_memory
from app.security.self_reflection import generate_reflection, store_reflection
from app.learning.classification_tracker import record_classification
from app.security.semantic_classifier import classify_query_categories
from app.security.ip_guard import is_ip_blocked, evaluate_ip_for_human_approval



def _should_use_personal_context(message):
    lowered = message.lower()
    return any(
        phrase in lowered
        for phrase in (
            "suggest",
            "recommend",
            "for me",
            "based on my",
            "suited to me",
        )
    )


def _retrieve_context(db, user_id, message):
    return retrieve_memories(
        db=db,
        user_id=user_id,
        query=message,
        target_categories=classify_query_categories(message, limit=2),
    )


def _build_memory_response(memory_result, stored_message="Got it. I'll remember that."):
    if not memory_result:
        return stored_message

    status = memory_result.get("status")

    if status == "blocked":
        return (
            "⚠ Memory update blocked.\n\n"
            "Reason: "
            + memory_result.get("attack_type", "Security Policy")
            + "\n\nOriginal memory preserved."
        )

    if status == "quarantined":
        return "⚠ Memory sent for security review."
    if status == "pending_review":
        return (
            "⚠ This memory update requires human review.\n\n"
            "It has been placed in the HITL queue and "
            "will become active only after approval."
        )
    if status == "duplicate":
        return "I already know that."

    return stored_message


def _handle_memory_store(
    db,
    user_id,
    message,
    security_result,
    stored_message="Got it. I'll remember that.",
):
    normalized_fact = normalize_memory(message)

    worth = should_store_memory(normalized_fact)

    if not worth["store"]:
        return {
            "response": "Understood.",
            "retrieved_memories": [],
            "security": security_result,
            "memory": None,
            "validation": None,
        }

    memory_result = create_memory(
        db=db,
        user_id=user_id,
        fact=normalized_fact,
    )

    quarantine_status = "NONE"
    if memory_result and memory_result.get("status") == "quarantined":
        quarantine_status = "PENDING"

    return {
        "response": _build_memory_response(
            memory_result,
            stored_message=stored_message,
        ),
        "retrieved_memories": [],
        "security": security_result,
        "memory": memory_result,
        "validation": None,
        "quarantine_status": quarantine_status,
    }


def process_user_message(db: Session, user_id: str, message: str, ip_address: str = None):
    start_time = time.time()

    message = message.strip()
    if (message.startswith('"') and message.endswith('"')) or (message.startswith("'") and message.endswith("'")):
        message = message[1:-1].strip()

    # 1. EARLY INTERCEPT: If IP is blocked after human approval, reject immediately and DO NOT save memory
    if ip_address and is_ip_blocked(db, ip_address):
        elapsed = round((time.time() - start_time) * 1000, 2)
        log_security_event(
            db=db,
            operation="BLOCKED_IP_ATTEMPT",
            decision="BLOCK",
            threat="BLOCKED_IP_ACCESS",
            risk_score=1.0,
            payload=message,
            ip_address=ip_address,
            execution_time_ms=elapsed,
            final_decision="BLOCK",
            explanation={"reason": "Request rejected because IP address is blocked by human approval."}
        )
        return {
            "response": f"⛔ **Access Denied**: So many blocks have come from your IP address (`{ip_address}`), and it has been officially BLOCKED following security approval. No actions or memories will be saved.",
            "retrieved_memories": [],
            "security": {"decision": "BLOCK", "threat": "BLOCKED_IP", "risk_score": 1.0, "operation": "UNKNOWN"},
            "memory": None
        }

    # 2. Additive Regex Input Filter check
    if llm_input_filter(message):
        elapsed = round((time.time() - start_time) * 1000, 2)
        fake_security_result = {
            "decision": "BLOCK",
            "threat": "PROMPT_INJECTION",
            "risk_score": 1.0,
            "operation": "GENERAL_CHAT",
            "intent": "SYSTEM_QUERY",
            "intent_confidence": 1.0,
            "attack_type": "PROMPT_INJECTION",
            "attack_confidence": 1.0,
            "risk_level": "HIGH",
            "category": "GENERAL",
            "input": message,
            "explanation": {"reason": "Request blocked by additive regex prompt injection input filter."}
        }
        log_security_event(
            db=db,
            operation="GENERAL_CHAT",
            decision="BLOCK",
            threat="PROMPT_INJECTION",
            risk_score=1.0,
            payload=message,
            intent="SYSTEM_QUERY",
            intent_confidence=1.0,
            attack_type="PROMPT_INJECTION",
            attack_confidence=1.0,
            risk_level="HIGH",
            memory_category="GENERAL",
            conflict_status="NONE",
            execution_time_ms=elapsed,
            final_decision="BLOCK",
            explanation=fake_security_result["explanation"],
            ip_address=ip_address,
        )
        return {
            "response": "I can only help with cooking.",
            "retrieved_memories": [],
            "security": fake_security_result,
            "memory": None,
            "dashboard": _build_dashboard_payload(
                fake_security_result, None, None, elapsed, "BLOCK"
            ),
        }

    security_result = evaluate_security(
        message,
        db=db,
        user_id=user_id,
    )


    operation = security_result["operation"]

    record_classification(
        db=db,
        component="intent_classifier",
        predicted_label=security_result.get("intent", "UNKNOWN"),
        confidence=security_result.get("intent_confidence", 0.0),
        was_blocked=security_result["decision"] == "BLOCK",
    )

    record_classification(
        db=db,
        component="security_classifier",
        predicted_label=security_result.get("attack_type", "SAFE"),
        confidence=security_result.get("attack_confidence", 0.0),
        was_blocked=security_result["decision"] == "BLOCK",
    )

    # Handle BLOCK decision
    if security_result["decision"] == "BLOCK":
        elapsed = round((time.time() - start_time) * 1000, 2)

        event = log_security_event(
            db=db,
            operation=operation,
            decision="BLOCK",
            threat=security_result["threat"],
            risk_score=security_result["risk_score"],
            payload=message,
            intent=security_result.get("intent"),
            intent_confidence=security_result.get("intent_confidence", 0.0),
            attack_type=security_result.get("attack_type", "SAFE"),
            attack_confidence=security_result.get("attack_confidence", 0.0),
            risk_level=security_result.get("risk_level", "LOW"),
            memory_category=security_result.get("category", "GENERAL"),
            conflict_status="NONE",
            poison_detected=security_result.get("attack_type") == "MEMORY_POISONING",
            security_confidence=security_result.get("attack_confidence", 0.0),
            execution_time_ms=elapsed,
            final_decision="BLOCK",
            explanation=security_result.get("explanation"),
            ip_address=ip_address,
        )

        attack_type = security_result.get("attack_type", "SAFE")
        block_response = f"⚠ Request blocked by Security Policy (Reason: {attack_type})."

        hitl_request_id = None
        if ip_address:
            ip_eval = evaluate_ip_for_human_approval(db, ip_address)
            if ip_eval.get("send_to_hitl"):
                block_response = (
                    f"⚠ Request blocked by Security Policy (Reason: {attack_type}).\n\n"
                    f"Notice: Out of your last **{ip_eval['total_interactions']} interactions**, "
                    f"**{ip_eval['blocked_count']} ({ip_eval['block_rate_pct']}%)** were blocked by our security policy. "
                    f"Your IP address (`{ip_address}`) has been submitted to Human Approval for blocking review."
                )
                hitl_request_id = event.id if event else None

        return {
            "response": block_response,
            "hitl_request_id": hitl_request_id,
            "retrieved_memories": [],
            "security": security_result,
            "memory": None,
            "dashboard": _build_dashboard_payload(
                security_result, [], None, elapsed, "BLOCK"
            ),
        }

    # Handle ALLOW_WITH_WARNING decision - send to HITL, do not generate LLM response
    if security_result["decision"] == "ALLOW_WITH_WARNING":
        elapsed = round((time.time() - start_time) * 1000, 2)

        # Still retrieve memories for context and potential storage, but don't use for LLM
        retrieval_result = None
        ranked_memories = []
        memories_used = []

        if operation == "GENERAL_CHAT" or operation == "READ":
            retrieval_result = retrieve_memories(
                db=db,
                user_id=user_id,
                query=message,
            )
            ranked_memories = retrieval_result.get("ranked_memories", [])
            memories_used = ranked_memories

        # Log the event with ALLOW_WITH_WARNING final decision
        explanation = security_result.get("explanation") or {}
        if isinstance(explanation, str):
            try:
                explanation = json.loads(explanation)
            except Exception:
                explanation = {"reason": explanation}
        else:
            explanation = dict(explanation)
        explanation["user_id"] = user_id

        hitl_event = log_security_event(
            db=db,
            operation=operation,
            decision=security_result["decision"],  # This will be "ALLOW_WITH_WARNING"
            threat=security_result["threat"],
            risk_score=security_result["risk_score"],
            payload=message,
            intent=security_result.get("intent"),
            intent_confidence=security_result.get("intent_confidence", 0.0),
            attack_type=security_result.get("attack_type", "SAFE"),
            attack_confidence=security_result.get("attack_confidence", 0.0),
            risk_level=security_result.get("risk_level", "LOW"),
            memory_category=security_result.get("category", "GENERAL"),
            conflict_status="NONE",
            poison_detected=security_result.get("attack_type") == "MEMORY_POISONING",
            retrieved_memories=(retrieval_result["safe_memories"] if retrieval_result else []),
            memories_used=[m.get("content", "") for m in memories_used],
            trust_scores=[m.get("trust_score") for m in memories_used],
            execution_time_ms=elapsed,
            final_decision="ALLOW_WITH_WARNING",  # Explicitly set for HITL queue
            explanation=explanation,
            ip_address=ip_address,
        )

        # Return response indicating it's waiting for human approval
        hitl_response = (
            "⚠ This request requires human review due to potential security concerns.\n\n"
            "Your request has been submitted to the Human Validation Center (HITL) for approval.\n"
            "Please visit the HITL page to review and approve or reject this request.\n\n"
            f"Threat Type: {security_result.get('threat', 'UNKNOWN')}\n"
            f"Risk Level: {security_result.get('risk_level', 'LOW')}\n"
            f"Attack Type: {security_result.get('attack_type', 'SAFE')}"
        )

        return {
            "response": hitl_response,
            "hitl_request_id": hitl_event.id,
            "retrieved_memories": (retrieval_result["safe_memories"] if retrieval_result else []),
            "security": security_result,
            "memory": None,
            "validation": None,
            "dashboard": _build_dashboard_payload(
                security_result, retrieval_result, None, elapsed, "ALLOW_WITH_WARNING"
            ),
        }

    # Intercept tool-use queries in chat to simulate execution-time firewall
    import re
    action_keywords = ["search", "fetch", "read", "query", "get", "connect", "summarize", "download", "run"]
    has_action = any(kw in message.lower() for kw in action_keywords)
    domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\S*)?)', message.lower())
    
    if has_action and domain_match:
        raw_url = domain_match.group(1)
        domain = raw_url.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0].split("#")[0].strip(".,?!:;()")
        
        from app.memory_security.detectors.tool_policy_validator import ToolPolicyValidator
        tool_name = "web_search"
        if "db" in message.lower() or "database" in message.lower():
            tool_name = "database_query"
            
        tool_result = ToolPolicyValidator.validate_tool_execution(
            db=db,
            tool_name=tool_name,
            parameters={"url": f"https://{domain}"},
            user_id=user_id,
            original_user_prompt=message
        )
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        
        if tool_result["decision"] == "BLOCK":
            from app.memory_security.services.tool_policy_event_logger import log_tool_policy_event
            log_tool_policy_event(
                db=db,
                user_id=user_id,
                policy_text=f"Execution of tool {tool_name} with params {{'url': 'https://{domain}'}} (via Chat)",
                violation_reason=tool_result["violation_reason"],
                risk_score=tool_result["risk_score"],
                decision="BLOCK",
                unapproved_domains=domain
            )
            
            block_response = (
                f"⚠ **Tool Execution Blocked**\n\n"
                f"**Tool**: `{tool_name}`\n"
                f"**Reason**: `UNAPPROVED_DOMAIN:{domain}`\n"
                f"**Risk Score**: `{tool_result['risk_score']}`\n\n"
                f"This connection has been terminated by your Security Policy."
            )
            return {
                "response": block_response,
                "retrieved_memories": [],
                "security": security_result,
                "memory": None,
                "validation": None,
                "dashboard": _build_dashboard_payload(
                    security_result, None, None, elapsed, "BLOCK"
                ),
            }
        else:
            # Inject mock data representing successful API payload retrieval for trusted domain
            mock_data = f"Web content retrieved from trusted endpoint: {domain}. Status: Active. Safety: OK."
            if "github" in domain:
                mock_data = "Repository name: AttackLayer. Owner: SharvaniLekkala. Stars: 342. Open issues: 4. Latest commit: 'Implemented tool policy execution check & live dashboard update logs'."
            elif "openai" in domain:
                mock_data = "OpenAI API service is operational. Current active models: gpt-4o, gpt-4-turbo, text-embedding-3-small."
            
            # Fetch personal context if needed
            secure_context = ""
            retrieval_result = None
            if _should_use_personal_context(message):
                retrieval_result = retrieve_memories(
                    db=db,
                    user_id=user_id,
                    query=message,
                )
                secure_context = build_secure_context(
                    query=message,
                    safe_memories=retrieval_result["safe_memories"],
                    ranked_memories=retrieval_result.get("ranked_memories", []),
                )
            
            extended_query = (
                f"{message}\n\n"
                f"[System Note: Below is the web content retrieved from the trusted domain '{domain}':\n"
                f"{mock_data}\n"
                f"Please summarize this information to answer the user's query. "
                f"If this information does not contain the answer, you are allowed and expected to use "
                f"your own general pre-trained knowledge about '{domain}' to answer the user's question correctly.]"
            )
            
            llm_response = generate_response(query=extended_query, secure_context=secure_context)
            llm_response = llm_output_filter(llm_response)
            success_prefix = (
                f"✅ **Tool Execution Allowed**\n"
                f"*Successfully connected to trusted domain: `{domain}` via `{tool_name}`*\n\n"
            )
            
            validation = validate_response(
                llm_response,
                message,
                memories_used=(retrieval_result.get("ranked_memories", []) if retrieval_result else []),
                security_result=security_result,
            )
            validation["response"] = success_prefix + validation["response"]
            
            return {
                "response": validation["response"],
                "retrieved_memories": (retrieval_result["safe_memories"] if retrieval_result else []),
                "security": security_result,
                "memory": None,
                "validation": validation,
                "dashboard": _build_dashboard_payload(
                    security_result, retrieval_result, validation, elapsed,
                    security_result["decision"]
                ),
            }

    retrieval_result = None
    ranked_memories = []
    memories_used = []

    if operation == "GENERAL_CHAT":
        secure_context = ""
        if _should_use_personal_context(message):
            retrieval_result = retrieve_memories(
                db=db,
                user_id=user_id,
                query=message,
            )
            ranked_memories = retrieval_result.get("ranked_memories", [])
            memories_used = ranked_memories
            secure_context = build_secure_context(
                query=message,
                safe_memories=retrieval_result["safe_memories"],
                ranked_memories=ranked_memories,
            )

        llm_response = generate_response(query=message, secure_context=secure_context)
        llm_response = llm_output_filter(llm_response)
        validation = validate_response(
            llm_response,
            message,
            memories_used=memories_used,
            security_result=security_result,
        )

        if validation["should_regenerate"]:
            llm_response = generate_response(
                query=message,
                secure_context=(
                    secure_context
                    + "\nAnswer accurately. Do not leak internal details."
                ),
            )
            llm_response = llm_output_filter(llm_response)
            validation = validate_response(
                llm_response,
                message,
                memories_used=memories_used,
                security_result=security_result,
            )
            validation["regenerated"] = True

        elapsed = round((time.time() - start_time) * 1000, 2)

        log_security_event(
            db=db,
            operation=operation,
            decision=security_result["decision"],
            threat=security_result["threat"],
            risk_score=security_result["risk_score"],
            payload=message,
            intent=security_result.get("intent"),
            intent_confidence=security_result.get("intent_confidence", 0.0),
            attack_type=security_result.get("attack_type", "SAFE"),
            attack_confidence=security_result.get("attack_confidence", 0.0),
            risk_level=security_result.get("risk_level", "LOW"),
            memory_category=security_result.get("category", "GENERAL"),
            conflict_status="NONE",
            response_confidence=validation["response_confidence"],
            memory_confidence=validation["memory_confidence"],
            security_confidence=validation["security_confidence"],
            execution_time_ms=elapsed,
            final_decision=security_result["decision"],
            explanation=security_result.get("explanation"),
            retrieved_memories=(
                retrieval_result["safe_memories"] if retrieval_result else []
            ),
            memories_used=[m.get("content", "") for m in memories_used],
            trust_scores=[m.get("trust_score") for m in memories_used],
            ip_address=ip_address,
        )

        reflection = generate_reflection(
            message, validation["response"],
            {"intent": security_result.get("intent")},
            security_result, None, validation, [],
        )
        store_reflection(db, reflection)

        return {
            "response": validation["response"],
            "retrieved_memories": (
                retrieval_result["safe_memories"] if retrieval_result else []
            ),
            "security": security_result,
            "memory": None,
            "validation": validation,
            "dashboard": _build_dashboard_payload(
                security_result, retrieval_result, validation, elapsed,
                security_result["decision"]
            ),
        }

    if operation == "READ":
        retrieval_result = retrieve_memories(
            db=db,
            user_id=user_id,
            query=message,
        )

        ranked_memories = retrieval_result.get("ranked_memories", [])
        memories_used = ranked_memories

        secure_context = build_secure_context(
            query=message,
            safe_memories=retrieval_result["safe_memories"],
            ranked_memories=ranked_memories,
        )

        llm_response = generate_response(
            query=message,
            secure_context=secure_context,
        )
        llm_response = llm_output_filter(llm_response)

        validation = validate_response(
            llm_response,
            message,
            memories_used=memories_used,
            security_result=security_result,
        )

        if validation["should_regenerate"]:
            llm_response = generate_response(
                query=message,
                secure_context=secure_context + "\nBe precise. Only use listed memories.",
            )
            llm_response = llm_output_filter(llm_response)
            validation = validate_response(
                llm_response,
                message,
                memories_used=memories_used,
                security_result=security_result,
            )
            validation["regenerated"] = True

        elapsed = round((time.time() - start_time) * 1000, 2)

        log_security_event(
            db=db,
            operation=operation,
            decision=security_result["decision"],
            threat=security_result["threat"],
            risk_score=security_result["risk_score"],
            payload=message,
            intent=security_result.get("intent"),
            intent_confidence=security_result.get("intent_confidence", 0.0),
            attack_type=security_result.get("attack_type", "SAFE"),
            attack_confidence=security_result.get("attack_confidence", 0.0),
            risk_level=security_result.get("risk_level", "LOW"),
            memory_category=security_result.get("category", "GENERAL"),
            conflict_status="NONE",
            retrieved_memories=retrieval_result["safe_memories"],
            memories_used=[m.get("content", "") for m in memories_used],
            trust_scores=[m.get("trust_score") for m in memories_used],
            response_confidence=validation["response_confidence"],
            memory_confidence=validation["memory_confidence"],
            security_confidence=validation["security_confidence"],
            execution_time_ms=elapsed,
            final_decision=security_result["decision"],
            explanation=security_result.get("explanation"),
            ip_address=ip_address,
        )

        reflection = generate_reflection(
            message, validation["response"],
            {"intent": security_result.get("intent")},
            security_result, retrieval_result, validation, memories_used,
        )
        store_reflection(db, reflection)

        return {
            "response": validation["response"],
            "retrieved_memories": retrieval_result["safe_memories"],
            "security": security_result,
            "memory": None,
            "validation": validation,
            "dashboard": _build_dashboard_payload(
                security_result, retrieval_result, validation, elapsed,
                security_result["decision"],
            ),
        }

    if operation == "WRITE":
        result = _handle_memory_store(
            db=db,
            user_id=user_id,
            message=message,
            security_result=security_result,
        )
        elapsed = round((time.time() - start_time) * 1000, 2)
        _log_memory_event(db, message, security_result, result, elapsed, ip_address=ip_address)
        result["dashboard"] = _build_dashboard_payload(
            security_result, None, None, elapsed,
            (result.get("memory") or {}).get("decision", security_result["decision"]),
            quarantine=result.get("quarantine_status"),
        )
        return result

    if operation == "UPDATE":
        result = _handle_memory_store(
            db=db,
            user_id=user_id,
            message=message,
            security_result=security_result,
            stored_message="Got it. I've updated your memory.",
        )
        elapsed = round((time.time() - start_time) * 1000, 2)
        event = _log_memory_event(
            db,
            message,
            security_result,
            result,
            elapsed,
            ip_address=ip_address
        )

        if (result.get("memory") or {}).get("status") == "pending_review":
            result["hitl_request_id"] = event.id
            result["dashboard"] = _build_dashboard_payload(
                security_result, None, None, elapsed,
                (result.get("memory") or {}).get("decision", security_result["decision"]),
                quarantine=result.get("quarantine_status"),
            )
        return result

    llm_response = generate_response(query=message, secure_context="")
    llm_response = llm_output_filter(llm_response)
    validation = validate_response(
        llm_response, message, security_result=security_result,
    )
    elapsed = round((time.time() - start_time) * 1000, 2)

    log_security_event(
        db=db,
        operation=operation,
        decision=security_result["decision"],
        threat=security_result["threat"],
        risk_score=security_result["risk_score"],
        payload=message,
        intent=security_result.get("intent"),
        intent_confidence=security_result.get("intent_confidence", 0.0),
        attack_type=security_result.get("attack_type", "SAFE"),
        attack_confidence=security_result.get("attack_confidence", 0.0),
        risk_level=security_result.get("risk_level", "LOW"),
        memory_category=security_result.get("category", "GENERAL"),
        conflict_status="NONE",
        response_confidence=validation["response_confidence"],
        execution_time_ms=elapsed,
        final_decision=security_result["decision"],
        explanation=security_result.get("explanation"),
        ip_address=ip_address,
    )

    return {
        "response": validation["response"],
        "retrieved_memories": [],
        "security": security_result,
        "memory": None,
        "validation": validation,
        "dashboard": _build_dashboard_payload(
            security_result, None, validation, elapsed, security_result["decision"]
        ),
    }


def _log_memory_event(db, message, security_result, result, elapsed, ip_address=None):
    memory = result.get("memory") or {}
    return log_security_event(
        db=db,
        operation=security_result["operation"],
        decision=security_result["decision"],
        threat=security_result["threat"],
        risk_score=security_result["risk_score"],
        payload=message,
        intent=security_result.get("intent"),
        intent_confidence=security_result.get("intent_confidence", 0.0),
        attack_type=memory.get(
            "attack_type",
            security_result.get("attack_type", "SAFE"),
        ),
        attack_confidence=security_result.get("attack_confidence", 0.0),
        risk_level=security_result.get("risk_level", "LOW"),
        memory_category=security_result.get("category", "GENERAL"),
        conflict_status=(
            "DETECTED"
            if memory.get("conflict_detected")
            else "NONE"
        ),
        trust_scores=(
            [memory.get("trust_score")]
            if memory.get("trust_score") is not None
            else []
        ),
        poison_detected=memory.get("status") == "blocked",
        quarantine_status=result.get("quarantine_status", "NONE"),
        execution_time_ms=elapsed,
        final_decision=memory.get("decision", security_result["decision"]),
        explanation=security_result.get("explanation"),
        memory_id=memory.get(
            "memory_id"
        ),
        ip_address=ip_address,
    )


def _build_dashboard_payload(
    security_result,
    retrieval_result,
    validation,
    elapsed_ms,
    final_decision,
    quarantine="NONE",
):
    return {
        "user_input": security_result.get("input"),
        "intent": security_result.get("intent"),
        "intent_confidence": security_result.get("intent_confidence"),
        "memory_category": security_result.get("category"),
        "attack_type": security_result.get("attack_type"),
        "attack_confidence": security_result.get("attack_confidence"),
        "risk_level": security_result.get("risk_level"),
        "retrieved_memories": (
            retrieval_result["safe_memories"]
            if retrieval_result else []
        ),
        "trust_scores": [
            m.get("trust_score")
            for m in (retrieval_result or {}).get("ranked_memories", [])
        ],
        "memories_used": [
            m.get("content")
            for m in (retrieval_result or {}).get("ranked_memories", [])
        ],
        "poison_detected": security_result.get("attack_type") == "MEMORY_POISONING",
        "quarantine_status": quarantine,
        "response_confidence": (
            validation["response_confidence"] if validation else 0.0
        ),
        "memory_confidence": (
            validation["memory_confidence"] if validation else 0.0
        ),
        "security_confidence": (
            validation["security_confidence"] if validation else 0.0
        ),
        "execution_time_ms": elapsed_ms,
        "final_decision": final_decision,
        "conflict_status": (
            "DETECTED"
            if security_result.get("operation") == "UPDATE"
            else "NONE"
        ),
        "explanation": security_result.get("explanation"),
    }