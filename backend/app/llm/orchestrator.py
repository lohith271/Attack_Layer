import time
import json

from sqlalchemy.orm import Session

from app.memory.retrieval import retrieve_memories
from app.security.context_builder import build_secure_context
from app.llm.service import generate_response
from app.security.security_gateway import evaluate_security
from app.memory.vault import create_memory
from app.security.response_validator import validate_response
from app.audit.logger import log_security_event
from app.memory.memory_normalizer import normalize_memory
from app.security.memory_worthiness import should_store_memory
from app.security.self_reflection import generate_reflection, store_reflection
from app.learning.classification_tracker import record_classification
from app.security.semantic_classifier import classify_query_categories


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

        log_security_event(
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

        block_response = (
            "I can't retain sensitive credentials or secret information."
        )

        attack_type = security_result.get("attack_type")
        sensitive_type = security_result.get("sensitive_type")

        if sensitive_type and sensitive_type != "NONE":
            block_response = (
                "I can't retain sensitive credentials or secret information."
            )
        elif attack_type == "TOOL_MANIPULATION":
            block_response = (
                "⚠ Unsafe tool policy blocked.\n\n"
                "Reason: TOOL_MANIPULATION"
            )
        elif attack_type == "PROMPT_INJECTION":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: Prompt injection detected."
            )
        elif attack_type == "FALSE_FACT_INJECTION":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: False fact injection detected."
            )
        elif attack_type == "MEMORY_POISONING":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: Memory poisoning detected."
            )
        elif attack_type == "MEMORY_OVERWRITE":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: Memory overwrite detected."
            )
        elif attack_type == "PROPAGATION_ATTACK":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: Propagation attack detected."
            )
        elif attack_type == "ROLE_HIJACK":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: Role hijacking detected."
            )
        elif attack_type == "PREFERENCE_MANIPULATION":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: Preference manipulation detected."
            )
        elif attack_type == "SYSTEM_PROMPT_EXTRACTION":
            block_response = (
                "⚠ Request blocked.\n\n"
                "Reason: System prompt extraction detected."
            )

        return {
            "response": block_response,
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