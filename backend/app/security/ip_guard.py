from sqlalchemy.orm import Session
from app.database.models import AuditEvent, BlockedIP
from datetime import datetime

MIN_INTERACTIONS = 10
BLOCK_RATE_THRESHOLD = 0.85  # > 85%


def is_ip_blocked(db: Session, ip_address: str) -> bool:
    """
    Returns True ONLY if the IP was reviewed and approved as BLOCKED by a human.
    """
    if not ip_address:
        return False
    entry = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    return entry is not None and entry.status == "BLOCKED" and entry.approved_by_human


def evaluate_ip_for_human_approval(db: Session, ip_address: str):
    """
    Evaluates an IP address:
    If total interactions >= 10 AND blocked rate > 85%,
    flags the IP for Human Approval (HITL review).
    """
    if not ip_address:
        return {"send_to_hitl": False}

    # Fetch all audit events for this IP
    events = db.query(AuditEvent).filter(AuditEvent.ip_address == ip_address).all()
    total_interactions = len(events)

    if total_interactions < MIN_INTERACTIONS:
        return {
            "send_to_hitl": False,
            "total_interactions": total_interactions,
            "blocked_count": sum(1 for e in events if e.decision == "BLOCK"),
            "block_rate_pct": 0.0,
        }

    blocked_count = sum(1 for e in events if e.decision == "BLOCK")
    block_rate = blocked_count / total_interactions if total_interactions > 0 else 0.0

    send_to_hitl = block_rate > BLOCK_RATE_THRESHOLD

    # Update or register in BlockedIP table
    entry = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    if not entry:
        entry = BlockedIP(
            ip_address=ip_address,
            block_count=blocked_count,
            total_interactions=total_interactions,
            block_rate=round(block_rate, 4),
            status="TRUSTED",
        )
        db.add(entry)
    else:
        entry.block_count = blocked_count
        entry.total_interactions = total_interactions
        entry.block_rate = round(block_rate, 4)

    if send_to_hitl and entry.status != "BLOCKED":
        entry.status = "PENDING"

    db.commit()

    return {
        "send_to_hitl": send_to_hitl,
        "total_interactions": total_interactions,
        "blocked_count": blocked_count,
        "block_rate_pct": round(block_rate * 100, 1),
        "status": entry.status,
    }
