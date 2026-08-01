import unittest
from datetime import datetime, timedelta
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
import app.database.models as models
from app.agents.analytics_agent import ThreatAnalyticsAgent


class ThreatAnalyticsAgentReportTest(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.agent = ThreatAnalyticsAgent()

    def tearDown(self):
        self.db.close()

    def test_today_report_generation(self):
        # 1. Add some memories (one created today, one created yesterday)
        today_utc = datetime.utcnow().date()
        yesterday_utc = today_utc - timedelta(days=1)
        
        mem1 = models.Memory(
            user_id="test-user",
            fact="i prefer python coding",
            category="CODING_PREFERENCE",
            memory_type="LONG_TERM",
            trust_score=0.9,
            active=True,
            created_at=datetime.combine(yesterday_utc, datetime.min.time())
        )
        mem2 = models.Memory(
            user_id="test-user",
            fact="i love apples",
            category="FOOD_PREFERENCE",
            memory_type="SHORT_TERM",
            trust_score=0.85,
            active=True,
            created_at=datetime.utcnow()
        )
        self.db.add_all([mem1, mem2])
        self.db.commit()
        
        # 2. Add some audit events (including a human reviewed one today)
        event1 = models.AuditEvent(
            operation="WRITE",
            decision="ALLOW",
            threat="SAFE",
            risk_score=0.1,
            payload="i prefer python coding",
            created_at=datetime.combine(yesterday_utc, datetime.min.time())
        )
        
        # Human decision approved today
        explanation_approved = {
            "human_decision": "APPROVED",
            "human_decision_timestamp": datetime.utcnow().isoformat()
        }
        event2 = models.AuditEvent(
            operation="WRITE",
            decision="ALLOW",
            final_decision="ALLOW",
            threat="SAFE",
            risk_score=0.2,
            payload="i love apples",
            explanation=json.dumps(explanation_approved),
            created_at=datetime.utcnow(),
            ip_address="172.20.233.58",
            memory_id=mem2.id
        )
        
        # Human decision rejected today
        explanation_rejected = {
            "human_decision": "REJECTED",
            "human_decision_timestamp": datetime.utcnow().isoformat()
        }
        event3 = models.AuditEvent(
            operation="WRITE",
            decision="BLOCK",
            final_decision="BLOCK",
            threat="MEMORY_POISONING",
            risk_score=0.8,
            payload="remember a bad fact",
            explanation=json.dumps(explanation_rejected),
            created_at=datetime.utcnow(),
            ip_address="172.20.233.58"
        )
        
        # Pending review today
        event4 = models.AuditEvent(
            operation="READ",
            decision="ALLOW_WITH_WARNING",
            final_decision="ALLOW_WITH_WARNING",
            threat="TOOL_POLICY_MANIPULATION",
            risk_score=0.7,
            payload="disable validation",
            created_at=datetime.utcnow(),
            ip_address="127.0.0.1"
        )
        
        self.db.add_all([event1, event2, event3, event4])
        self.db.commit()
        
        # Execute query
        res = self.agent.explain_query(self.db, "Give today report in detail")
        response_text = res["response"]
        stats = res["stats"]
        
        # Verification
        self.assertIn("🛡️ DAILY SECURITY AUDIT REPORT", response_text)
        self.assertIn("=== USER & PROMPT AUDITS ===", response_text)
        self.assertIn("Allowed Requests Today (1):", response_text)
        self.assertIn("Prompt: \"i love apples\"", response_text)
        self.assertIn("Source IP: 172.20.233.58", response_text)
        self.assertIn("Blocked Requests Today (1):", response_text)
        self.assertIn("Prompt: \"remember a bad fact\"", response_text)
        self.assertIn("Source IP: 172.20.233.58", response_text)
        
        self.assertIn("=== MEMORY SECURITY REFRESHES ===", response_text)
        self.assertIn("=== HUMAN-IN-THE-LOOP (HITL) REVIEWS ===", response_text)
        self.assertIn("Pending Human Reviews for Memory: Not yet come", response_text)
        self.assertIn("Approved Today: 1", response_text)
        self.assertIn("Rejected Today: 1", response_text)
        self.assertIn("Detailed Human Reviews Resolved Today (2):", response_text)
        self.assertIn("Prompt: \"i love apples\" | Decision: APPROVED | Source IP: 172.20.233.58", response_text)
        self.assertIn("Prompt: \"remember a bad fact\" | Decision: REJECTED | Source IP: 172.20.233.58", response_text)
        
        self.assertIn("=== NEW MEMORY INSERTIONS TODAY ===", response_text)
        self.assertIn("Fact: \"i love apples\" | Category: FOOD_PREFERENCE | Source IP: 172.20.233.58", response_text)
        
        self.assertIn("=== IP INTELLIGENCE & THREAT SUMMARY ===", response_text)
        self.assertIn("Source IP: 172.20.233.58", response_text)
        self.assertIn("Source IP: 127.0.0.1", response_text)
        self.assertIn("Trust Level: Yes", response_text) # For 127.0.0.1 (low risk score)
        self.assertIn("Trust Level: No (Blocked)", response_text) # For 172.20.233.58 (contains block)
        
        # Today's stats should only count events from today (event2, event3, event4)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["allowed"], 1)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["warnings"], 1)

    def test_explain_query_refreshes(self):
        # Add some refresh events today
        ref_event = models.AuditEvent(
            operation="REFRESH_ACTION",
            decision="ALLOW",
            threat="SAFE",
            risk_score=0.0,
            payload="fact",
            created_at=datetime.utcnow()
        )
        det_event = models.AuditEvent(
            operation="REFRESH_SCAN",
            decision="ALLOW_WITH_WARNING",
            threat="ML_ATTACK",
            risk_score=0.8,
            payload="malicious fact",
            created_at=datetime.utcnow()
        )
        self.db.add_all([ref_event, det_event])
        self.db.commit()

        # Query number of refreshes today
        res = self.agent.explain_query(self.db, "Give the no of refreshes happened today")
        response_text = res["response"]
        
        self.assertIn("Memory Refreshes for ", response_text)
        self.assertIn("- Refreshes Triggered: 1", response_text)
        self.assertIn("- Refreshes Detected as Attacks (Blocked/Quarantined): 1", response_text)

