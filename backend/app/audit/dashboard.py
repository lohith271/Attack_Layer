import json
from app.database.models import AuditEvent


def get_ip_intelligence(db):
    # Get unique IPs and their info
    ip_records = db.query(AuditEvent).filter(AuditEvent.ip_address.isnot(None)).all()

    # Group by IP address
    ip_groups = {}
    for record in ip_records:
        ip = record.ip_address
        if ip not in ip_groups:
            ip_groups[ip] = []
        ip_groups[ip].append(record)

    ip_data = []
    for ip, events in ip_groups.items():
        request_count = len(events)
        last_seen = max(event.created_at for event in events if event.created_at) if events else None

        # Determine threat type: pick the threat with highest risk score (non-SAFE if possible)
        threat_type = "NONE"
        max_risk = 0.0
        for event in events:
            if event.threat != "SAFE" and event.risk_score > max_risk:
                max_risk = event.risk_score
                threat_type = event.threat

        # Compute custom risk score based on blocked requests, suspicious activity, HITL requests, repeated attacks
        blocked_count = sum(1 for e in events if e.decision == "BLOCK")
        suspicious_count = sum(1 for e in events if e.threat == "SUSPICIOUS")
        hitl_count = sum(1 for e in events if e.final_decision == "ALLOW_WITH_WARNING")
        raw_score = (blocked_count * 0.1) + (suspicious_count * 0.05) + (hitl_count * 0.02) + ((request_count - 1) * 0.01 if request_count > 1 else 0)
        risk_score = min(1.0, raw_score)  # clamp to 1.0

        # Reputation based on risk score
        if risk_score < 0.3:
            reputation = "Good"
        elif risk_score < 0.6:
            reputation = "Fair"
        else:
            reputation = "Poor"

        # Status: Trusted, Suspicious, Blocked (Title Case for frontend)
        if blocked_count > 0:
            status = "Blocked"
        elif risk_score >= 0.7:
            status = "Suspicious"
        else:
            status = "Trusted"

        # Action based on status
        if status == "BLOCKED":
            action = "Blocked"
        elif status == "SUSPICIOUS":
            action = "Monitor"
        else:
            action = "Allow"

        ip_data.append({
            "ipAddress": ip,
            "country": "Unknown",
            "city": "Unknown",
            "riskScore": round(risk_score, 2),
            "reputation": reputation,
            "threatType": threat_type,
            "requestCount": request_count,
            "lastSeen": last_seen.isoformat() if last_seen else "",
            "status": status,
            "action": action
        })

    # Sort by risk score descending
    ip_data.sort(key=lambda x: x["riskScore"], reverse=True)
    return ip_data


def get_blocked_events(db):
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.decision == "BLOCK")
        .order_by(AuditEvent.id.desc())
        .all()
    )

    result = []

    for event in events:
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

        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%H:%M:%S") if event.created_at else "Unknown",
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
        })

    return result


def get_threat_events(db):
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.threat != "SAFE")
        .order_by(AuditEvent.id.desc())
        .all()
    )

    result = []

    for event in events:
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

        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%H:%M:%S") if event.created_at else "Unknown",
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
        })

    return result


def get_conflict_events(db):
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.conflict_status != "NONE")
        .order_by(AuditEvent.id.desc())
        .all()
    )

    result = []

    for event in events:
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

        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%H:%M:%S") if event.created_at else "Unknown",
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
        })

    return result


def get_trust_analytics(db):
    # Get trust score distribution
    events = db.query(AuditEvent).all()

    high_trust = 0
    medium_trust = 0
    low_trust = 0

    for event in events:
        # Using risk_score as inverse of trust for simplicity
        trust = 1.0 - min(event.risk_score, 1.0)
        if trust >= 0.7:
            high_trust += 1
        elif trust >= 0.4:
            medium_trust += 1
        else:
            low_trust += 1

    total = len(events)
    if total == 0:
        total = 1

    return [
        {"trust_level": "High (0.7-1.0)", "count": high_trust, "percentage": round((high_trust / total) * 100, 2)},
        {"trust_level": "Medium (0.4-0.7)", "count": medium_trust, "percentage": round((medium_trust / total) * 100, 2)},
        {"trust_level": "Low (0.0-0.4)", "count": low_trust, "percentage": round((low_trust / total) * 100, 2)}
    ]


def get_top_attack_types(db):
    events = db.query(AuditEvent).filter(AuditEvent.attack_type != "SAFE").all()

    attack_counts = {}
    for event in events:
        attack_type = event.attack_type
        attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

    # Sort by count descending and return top 10
    sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return [{"attack_type": attack, "count": count} for attack, count in sorted_attacks]


def get_risk_distribution(db):
    events = db.query(AuditEvent).all()

    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for event in events:
        risk_level = event.risk_level
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1
        else:
            # Default to MEDIUM for unknown levels
            risk_counts["MEDIUM"] += 1

    total = sum(risk_counts.values())
    if total == 0:
        total = 1

    return [
        {"risk_level": level, "count": count, "percentage": round((count / total) * 100, 2)}
        for level, count in risk_counts.items()
    ]


def get_security_timeline(db):
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(50).all()

    result = []
    for event in events:
        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "operation": event.operation,
            "threat": event.threat if event.threat else "NONE",
            "risk_score": round(event.risk_score, 4),
            "decision": event.decision,
            "prompt": event.payload[:100] + "..." if len(event.payload) > 100 else event.payload
        })

    return result


def get_attack_statistics(db):
    from app.analytics.metrics_service import get_attack_statistics as _stats
    return _stats(db)


def get_decision_distribution(db):
    events = db.query(AuditEvent).all()

    decision_counts = {}
    for event in events:
        decision = event.decision
        decision_counts[decision] = decision_counts.get(decision, 0) + 1

    total = sum(decision_counts.values())
    if total == 0:
        total = 1

    return [
        {"decision": decision, "count": count, "percentage": round((count / total) * 100, 2)}
        for decision, count in decision_counts.items()
    ]


def get_threat_category_distribution(db):
    events = db.query(AuditEvent).filter(AuditEvent.threat != "SAFE").all()

    threat_counts = {}
    for event in events:
        threat = event.threat
        threat_counts[threat] = threat_counts.get(threat, 0) + 1

    total = sum(threat_counts.values())
    if total == 0:
        total = 1

    return [
        {"threat": threat, "count": count, "percentage": round((count / total) * 100, 2)}
        for threat, count in threat_counts.items()
    ]


def get_memory_usage_distribution(db):
    from app.analytics.metrics_service import get_memory_usage_distribution as _mem
    result = _mem(db)
    return result.get("array", [])


def get_human_approval_vs_rejection(db):
    from app.analytics.metrics_service import get_human_approval_vs_rejection as _human
    return _human(db).get("array", [])


def get_attack_severity_breakdown(db):
    from app.analytics.metrics_service import get_attack_severity_breakdown as _sev
    return _sev(db).get("array", [])


def get_attack_simulator(db):
    # Placeholder for attack simulator functionality
    # In a real implementation, this would generate or retrieve simulated attack data
    return {
        "available_simulations": [
            {"id": "prompt_injection", "name": "Prompt Injection", "description": "Simulate prompt injection attacks"},
            {"id": "memory_poisoning", "name": "Memory Poisoning", "description": "Simulate memory poisoning attacks"},
            {"id": "preference_manipulation", "name": "Preference Manipulation", "description": "Simulate preference manipulation attacks"}
        ],
        "simulation_count": 0,
        "last_simulation": None
    }


def get_trust_breakdown(db):
    from app.analytics.metrics_service import get_trust_score_distribution
    return get_trust_score_distribution(db)


def get_user_risk_profile(db):
    # Get user risk profiles based on audit events
    from sqlalchemy import func, Integer

    # Query to get risk stats per user
    user_stats = db.query(
        AuditEvent.ip_address.label("user_id"),
        func.count(AuditEvent.id).label("total_events"),
        func.sum(func.cast(AuditEvent.decision == "BLOCK", Integer)).label("blocked_events"),
        func.avg(AuditEvent.risk_score).label("avg_risk_score")
    ).filter(AuditEvent.ip_address.isnot(None)).group_by(AuditEvent.ip_address).all()

    result = []
    for stat in user_stats:
        user_id = stat.user_id or "unknown"
        total_events = stat.total_events or 0
        blocked_events = stat.blocked_events or 0
        avg_risk = float(stat.avg_risk_score or 0.0)

        block_rate = (blocked_events / total_events * 100) if total_events > 0 else 0

        # Determine risk level based on average risk score
        if avg_risk >= 0.8:
            risk_level = "CRITICAL"
        elif avg_risk >= 0.6:
            risk_level = "HIGH"
        elif avg_risk >= 0.3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        result.append({
            "user_id": user_id,
            "total_events": total_events,
            "blocked_events": blocked_events,
            "block_rate": round(block_rate, 2),
            "average_risk_score": round(avg_risk, 4),
            "risk_level": risk_level
        })

    # Sort by risk score descending
    result.sort(key=lambda x: x["average_risk_score"], reverse=True)
    return result


def get_preference_drift_analytics(db):
    # Get preference drift analytics from PreferenceEvent model
    from app.database.models import PreferenceEvent

    events = db.query(PreferenceEvent).all()

    total_events = len(events)
    legitimate_updates = len([e for e in events if e.is_legitimate_update])
    manipulation_attempts = len([e for e in events if e.attack_type == "PREFERENCE_MANIPULATION"])
    blocked_drifts = len([e for e in events if not e.is_legitimate_update and e.drift_score > 0.5])

    manipulation_rate = (manipulation_attempts / total_events * 100) if total_events > 0 else 0
    legitimacy_rate = (legitimate_updates / total_events * 100) if total_events > 0 else 0

    # Average drift score
    avg_drift = sum(e.drift_score for e in events) / total_events if total_events > 0 else 0

    return {
        "total_preference_events": total_events,
        "legitimate_updates": legitimate_updates,
        "manipulation_attempts": manipulation_attempts,
        "blocked_drifts": blocked_drifts,
        "manipulation_rate": round(manipulation_rate, 2),
        "legitimacy_rate": round(legitimacy_rate, 2),
        "average_drift_score": round(avg_drift, 4)
    }


def get_preference_timeline(db):
    # Get preference events timeline from PreferenceEvent model
    from app.database.models import PreferenceEvent

    events = db.query(PreferenceEvent).order_by(PreferenceEvent.created_at.desc()).limit(50).all()

    result = []
    for event in events:
        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "user_id": event.user_id,
            "old_fact": event.old_fact[:50] + "..." if len(event.old_fact) > 50 else event.old_fact,
            "new_fact": event.new_fact[:50] + "..." if len(event.new_fact) > 50 else event.new_fact,
            "category": event.category,
            "is_legitimate_update": event.is_legitimate_update,
            "attack_type": event.attack_type,
            "drift_score": round(event.drift_score, 4),
            "stability_score": round(event.stability_score, 4)
        })

    return result


def get_preference_drift_distribution(db):
    # Get preference drift score distribution from PreferenceEvent model
    from app.database.models import PreferenceEvent

    events = db.query(PreferenceEvent).all()

    drift_ranges = {
        "0.0-0.1": 0,
        "0.1-0.2": 0,
        "0.2-0.3": 0,
        "0.3-0.4": 0,
        "0.4-0.5": 0,
        "0.5-0.6": 0,
        "0.6-0.7": 0,
        "0.7-0.8": 0,
        "0.8-0.9": 0,
        "0.9-1.0": 0
    }

    for event in events:
        drift = event.drift_score
        if drift <= 0.1:
            drift_ranges["0.0-0.1"] += 1
        elif drift <= 0.2:
            drift_ranges["0.1-0.2"] += 1
        elif drift <= 0.3:
            drift_ranges["0.2-0.3"] += 1
        elif drift <= 0.4:
            drift_ranges["0.3-0.4"] += 1
        elif drift <= 0.5:
            drift_ranges["0.4-0.5"] += 1
        elif drift <= 0.6:
            drift_ranges["0.5-0.6"] += 1
        elif drift <= 0.7:
            drift_ranges["0.6-0.7"] += 1
        elif drift <= 0.8:
            drift_ranges["0.7-0.8"] += 1
        elif drift <= 0.9:
            drift_ranges["0.8-0.9"] += 1
        else:
            drift_ranges["0.9-1.0"] += 1

    total = sum(drift_ranges.values())
    if total == 0:
        total = 1

    return [
        {"drift_range": range_key, "count": count, "percentage": round((count / total) * 100, 2)}
        for range_key, count in drift_ranges.items()
    ]


def get_tool_policy_violations(db):
    # Get tool policy violations from ToolPolicyEvent model
    from app.database.models import ToolPolicyEvent

    events = db.query(ToolPolicyEvent).filter(ToolPolicyEvent.decision == "BLOCK").order_by(ToolPolicyEvent.id.desc()).all()

    result = []
    for event in events:
        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "user_id": event.user_id,
            "policy_text": event.policy_text[:100] + "..." if len(event.policy_text) > 100 else event.policy_text,
            "violation_reason": event.violation_reason,
            "risk_score": round(event.risk_score, 4),
            "unapproved_domains": event.unapproved_domains
        })

    return result


def get_tool_policy_analytics(db):
    # Get tool policy analytics from ToolPolicyEvent model
    from app.database.models import ToolPolicyEvent

    events = db.query(ToolPolicyEvent).all()

    total_events = len(events)
    blocked_events = len([e for e in events if e.decision == "BLOCK"])
    allowed_events = len([e for e in events if e.decision == "ALLOW"])

    block_rate = (blocked_events / total_events * 100) if total_events > 0 else 0

    # Average risk score
    avg_risk = sum(e.risk_score for e in events) / total_events if total_events > 0 else 0

    # Unique users
    unique_users = len(set(e.user_id for e in events if e.user_id))

    return {
        "total_policy_events": total_events,
        "blocked_events": blocked_events,
        "allowed_events": allowed_events,
        "block_rate": round(block_rate, 2),
        "average_risk_score": round(avg_risk, 4),
        "unique_users": unique_users
    }


def get_tool_policy_timeline(db):
    # Get tool policy events timeline from ToolPolicyEvent model
    from app.database.models import ToolPolicyEvent

    events = db.query(ToolPolicyEvent).order_by(ToolPolicyEvent.created_at.desc()).limit(50).all()

    result = []
    for event in events:
        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "user_id": event.user_id,
            "policy_text": event.policy_text[:50] + "..." if len(event.policy_text) > 50 else event.policy_text,
            "violation_reason": event.violation_reason,
            "risk_score": round(event.risk_score, 4),
            "decision": event.decision,
            "unapproved_domains": event.unapproved_domains
        })

    return result


def get_propagation_analytics(db):
    # Get propagation analytics from PropagationEvent model
    from app.database.models import PropagationEvent

    events = db.query(PropagationEvent).all()

    total_events = len(events)
    blocked_events = len([e for e in events if e.decision == "BLOCK"])

    block_rate = (blocked_events / total_events * 100) if total_events > 0 else 0

    # Average spread percentage
    avg_spread = sum(e.spread_percentage for e in events) / total_events if total_events > 0 else 0

    # Max spread percentage
    max_spread = max([e.spread_percentage for e in events], default=0.0)

    # Unique origin agents
    unique_origins = len(set(e.origin_agent for e in events if e.origin_agent))

    # Unique target agents
    unique_targets = len(set(e.target_agent for e in events if e.target_agent))

    return {
        "total_propagation_events": total_events,
        "blocked_events": blocked_events,
        "block_rate": round(block_rate, 2),
        "average_spread_percentage": round(avg_spread, 2),
        "max_spread_percentage": round(max_spread, 2),
        "unique_origin_agents": unique_origins,
        "unique_target_agents": unique_targets
    }


def get_propagation_timeline(db):
    # Get propagation events timeline from PropagationEvent model
    from app.database.models import PropagationEvent

    events = db.query(PropagationEvent).order_by(PropagationEvent.created_at.desc()).limit(50).all()

    result = []
    for event in events:
        result.append({
            "id": event.id,
            "time": event.created_at.strftime("%Y-%m-%d %H:%M:%S") if event.created_at else "Unknown",
            "memory_id": event.memory_id,
            "origin_agent": event.origin_agent,
            "target_agent": event.target_agent,
            "propagation_path": event.propagation_path,
            "spread_percentage": round(event.spread_percentage, 2),
            "poison_score": round(event.poison_score, 4),
            "attack_type": event.attack_type,
            "decision": event.decision,
            "fact": event.fact[:50] + "..." if len(event.fact) > 50 else event.fact
        })

    return result


def get_propagation_attack_count(db):
    # Get count of propagation events that are considered attacks
    from app.database.models import PropagationEvent

    # Consider events with decision BLOCK or high spread percentage as attacks
    attack_count = db.query(PropagationEvent).filter(
        (PropagationEvent.decision == "BLOCK") |
        (PropagationEvent.spread_percentage > 50.0)
    ).count()

    return {"propagation_attacks": attack_count}


def get_attack_trend_over_time(db):
    # Get attack trend over time from AuditEvent model
    events = db.query(AuditEvent).filter(AuditEvent.threat != "SAFE").order_by(AuditEvent.created_at.asc()).all()

    buckets = {}

    for event in events:
        if event.created_at:
            key = event.created_at.strftime("%Y-%m-%d")
            buckets[key] = buckets.get(key, 0) + 1

    result = [
        {"date": key, "count": buckets[key]}
        for key in sorted(buckets.keys())
    ]

    # Limit to last 30 days
    return result[-30:] if len(result) > 30 else result