import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from sqlalchemy import create_engine

from sqlalchemy.orm import sessionmaker
from app.database.session import Base
from app.database.models import AuditEvent, BlockedIP, Memory
from app.security.ip_guard import evaluate_ip_for_human_approval, is_ip_blocked
from app.llm.orchestrator import process_user_message

# Setup in-memory sqlite engine for testing
engine = create_engine("sqlite:///:memory:")
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)


def test_ip_blocking_workflow(db):
    test_ip = "192.168.1.100"

    # Initially, IP should not be blocked
    assert is_ip_blocked(db, test_ip) is False

    # Simulate 10 interaction logs: 9 BLOCKS and 1 ALLOW (90% blocked rate > 85%)
    for i in range(9):
        event = AuditEvent(
            operation="WRITE",
            decision="BLOCK",
            threat="PROMPT_INJECTION",
            risk_score=0.9,
            payload=f"Malicious attack {i}",
            ip_address=test_ip,
            final_decision="BLOCK"
        )
        db.add(event)
    
    # Add 1 clean interaction
    db.add(AuditEvent(
        operation="GENERAL_CHAT",
        decision="ALLOW",
        threat="SAFE",
        risk_score=0.0,
        payload="Hello world",
        ip_address=test_ip,
        final_decision="ALLOW"
    ))
    db.commit()

    # Evaluate IP for human approval
    eval_result = evaluate_ip_for_human_approval(db, test_ip)
    assert eval_result["send_to_hitl"] is True
    assert eval_result["total_interactions"] == 10
    assert eval_result["blocked_count"] == 9
    assert eval_result["block_rate_pct"] == 90.0
    assert eval_result["status"] == "PENDING"

    # Before human approval, is_ip_blocked should still be False
    assert is_ip_blocked(db, test_ip) is False

    # Simulate Human Review Approval
    entry = db.query(BlockedIP).filter(BlockedIP.ip_address == test_ip).first()
    entry.status = "BLOCKED"
    entry.approved_by_human = True
    db.commit()

    # Now is_ip_blocked must be True
    assert is_ip_blocked(db, test_ip) is True

    # Test process_user_message early intercept for blocked IP
    res = process_user_message(db, user_id="test_user", message="My favorite color is blue", ip_address=test_ip)
    assert "Access Denied" in res["response"]
    assert res["memory"] is None

    # Verify no memory was written to the Memory database
    memories_count = db.query(Memory).filter(Memory.user_id == "test_user").count()
    assert memories_count == 0
