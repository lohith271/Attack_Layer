import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.models import AuditEvent
from app.analytics.serializers import serialize_audit_event
from app.audit.dashboard import (
    get_blocked_events,
    get_threat_events,
    get_conflict_events,
    get_trust_analytics,
    get_top_attack_types,
    get_risk_distribution,
    get_attack_statistics,
    get_security_timeline,
    get_attack_simulator,
    get_trust_breakdown,
    get_user_risk_profile,
    get_preference_drift_analytics,
    get_preference_timeline,
    get_preference_drift_distribution,
    get_tool_policy_violations,
    get_tool_policy_analytics,
    get_tool_policy_timeline,
    get_propagation_analytics,
    get_propagation_timeline,
    get_propagation_attack_count,
    get_attack_trend_over_time,
    get_decision_distribution,
    get_threat_category_distribution,
    get_memory_usage_distribution,
    get_human_approval_vs_rejection,
    get_attack_severity_breakdown,
    get_ip_intelligence,
)
from app.analytics.metrics_service import (
    get_memory_usage_distribution as get_memory_usage_full,
    get_attack_success_rate_history,
    get_full_dashboard,
)

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/events")
def get_events(db: Session = Depends(get_db)):
    events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .all()
    )
    return [serialize_audit_event(e) for e in events]


@router.get("/dashboard")
def dashboard_snapshot(db: Session = Depends(get_db)):
    return get_full_dashboard(db)


@router.get("/attack-success-rate")
def attack_success_rate(db: Session = Depends(get_db)):
    stats = get_attack_statistics(db)
    return {
        "attack_success_rate": stats.get("attack_success_rate", 0),
        "attack_attempts": stats.get("attack_attempts", 0),
        "successful_attacks": stats.get("successful_attacks", 0),
        "history": get_attack_success_rate_history(db),
    }


@router.get("/memory-usage-full")
def memory_usage_full(db: Session = Depends(get_db)):
    return get_memory_usage_full(db)


@router.get("/blocked")
def blocked_events(db: Session = Depends(get_db)):
    return get_blocked_events(db)


@router.get("/threats")
def threat_events(db: Session = Depends(get_db)):
    return get_threat_events(db)


@router.get("/conflicts")
def conflict_events(db: Session = Depends(get_db)):
    return get_conflict_events(db)


@router.get("/trust")
def trust_analytics(db: Session = Depends(get_db)):
    return get_trust_analytics(db)


@router.get("/top-attacks")
def top_attacks(db: Session = Depends(get_db)):
    return get_top_attack_types(db)


@router.get("/risk-distribution")
def risk_distribution(db: Session = Depends(get_db)):
    return get_risk_distribution(db)


@router.get("/timeline")
def security_timeline(db: Session = Depends(get_db)):
    return get_security_timeline(db)


@router.get("/attack-simulator")
def attack_simulator(db: Session = Depends(get_db)):
    return get_attack_simulator(db)


@router.get("/trust-breakdown")
def trust_breakdown(db: Session = Depends(get_db)):
    return get_trust_breakdown(db)


@router.get("/user-risk")
def user_risk(db: Session = Depends(get_db)):
    return get_user_risk_profile(db)


@router.get("/preference-drift")
def preference_drift_analytics(db: Session = Depends(get_db)):
    return get_preference_drift_analytics(db)


@router.get("/preference-timeline")
def preference_timeline(db: Session = Depends(get_db)):
    return get_preference_timeline(db)


@router.get("/preference-drift-distribution")
def preference_drift_distribution(db: Session = Depends(get_db)):
    return get_preference_drift_distribution(db)


@router.get("/tool-policy-violations")
def tool_policy_violations(db: Session = Depends(get_db)):
    return get_tool_policy_violations(db)


@router.get("/tool-policy-analytics")
def tool_policy_analytics(db: Session = Depends(get_db)):
    return get_tool_policy_analytics(db)


@router.get("/tool-policy-timeline")
def tool_policy_timeline(db: Session = Depends(get_db)):
    return get_tool_policy_timeline(db)


@router.get("/propagation-analytics")
def propagation_analytics(db: Session = Depends(get_db)):
    return get_propagation_analytics(db)


@router.get("/propagation-timeline")
def propagation_timeline(db: Session = Depends(get_db)):
    return get_propagation_timeline(db)


@router.get("/propagation-attacks")
def propagation_attacks(db: Session = Depends(get_db)):
    return {"propagation_attacks": get_propagation_attack_count(db)}


@router.get("/attack-statistics")
def attack_statistics(db: Session = Depends(get_db)):
    return get_attack_statistics(db)


@router.get("/attack-trend-over-time")
def attack_trend_over_time(db: Session = Depends(get_db)):
    return get_attack_trend_over_time(db)


@router.get("/decision-distribution")
def decision_distribution(db: Session = Depends(get_db)):
    return get_decision_distribution(db)


@router.get("/threat-category-distribution")
def threat_category_distribution(db: Session = Depends(get_db)):
    return get_threat_category_distribution(db)


@router.get("/memory-usage-distribution")
def memory_usage_distribution(db: Session = Depends(get_db)):
    result = get_memory_usage_full(db)
    return {
        "episodic": result.get("episodic", 0),
        "shortTerm": result.get("shortTerm", 0),
        "longTerm": result.get("longTerm", 0),
        "array": result.get("array", []),
        "category_distribution": result.get("category_distribution", []),
    }


@router.get("/human-approval-vs-rejection")
def human_approval_vs_rejection(db: Session = Depends(get_db)):
    from app.analytics.metrics_service import get_human_approval_vs_rejection as _human
    return _human(db)


@router.get("/attack-severity-breakdown")
def attack_severity_breakdown(db: Session = Depends(get_db)):
    from app.analytics.metrics_service import get_attack_severity_breakdown as _sev
    return _sev(db)


@router.get("/ip-intelligence")
def ip_intelligence(db: Session = Depends(get_db)):
    return get_ip_intelligence(db)


@router.post("/explain-query")
def explain_query(query: str, db: Session = Depends(get_db)):
    from app.agents import orchestrator
    return orchestrator.analytics_agent.explain_query(db, query)


@router.get("/memory-refresh-stats")
def get_memory_refresh_stats(db: Session = Depends(get_db)):
    from datetime import datetime
    from app.database.models import Memory
    
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    refreshes_today = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.operation == "REFRESH_ACTION",
            AuditEvent.created_at >= today_start
        )
        .count()
    )
    
    detected_today = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.operation == "REFRESH_SCAN",
            AuditEvent.decision == "ALLOW_WITH_WARNING",
            AuditEvent.created_at >= today_start
        )
        .count()
    )
    
    pending_reviews_count = (
        db.query(Memory)
        .filter(
            Memory.active == False,
            Memory.status == "WAITING_APPROVAL"
        )
        .count()
    )
    
    return {
        "refreshes_today": refreshes_today,
        "detected_today": detected_today,
        "pending_reviews_count": pending_reviews_count
    }

