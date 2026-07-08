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
            created_at=datetime.utcnow()
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
            created_at=datetime.utcnow()
        )
        
        # Pending review today
        event4 = models.AuditEvent(
            operation="READ",
            decision="ALLOW_WITH_WARNING",
            final_decision="ALLOW_WITH_WARNING",
            threat="TOOL_POLICY_MANIPULATION",
            risk_score=0.7,
            payload="disable validation",
            created_at=datetime.utcnow()
        )
        
        self.db.add_all([event1, event2, event3, event4])
        self.db.commit()
        
        # Execute query
        res = self.agent.explain_query(self.db, "Give today report in detail")
        response_text = res["response"]
        stats = res["stats"]
        
        # Verification
        self.assertIn("=== MEMORY VAULT ===", response_text)
        self.assertIn("Memories Currently in Database (Total: 2)", response_text)
        self.assertIn("i prefer python coding", response_text)
        self.assertIn("i love apples", response_text)
        
        self.assertIn("Memories Inserted Today (Total: 1)", response_text)
        self.assertIn("=== METRICS VALUES & MODEL PERFORMANCE ===", response_text)
        
        self.assertIn("=== MODEL ENSEMBLE WEIGHTS ===", response_text)
        
        self.assertIn("=== HUMAN REVIEWS ===", response_text)
        self.assertIn("Pending Review Queue: 1", response_text)
        self.assertIn("Human Reviews Resolved Today: Yes", response_text)
        self.assertIn("Approved Today: 1", response_text)
        self.assertIn("Rejected Today: 1", response_text)
        
        # Today's stats should only count events from today (event2, event3, event4)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["allowed"], 1)
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["warnings"], 1)
