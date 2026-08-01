import unittest
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock

import app.database.models as models
from app.database.session import Base
from app.database.migrate import run_migrations, _backfill_unique_ids
from app.memory.vault import create_memory
from app.memory_security.quarantine.quarantine_manager import quarantine_memory
from app.api.memory import _serialize_memory


class MemoryUniqueIdTest(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        # Create schema
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()

        # Mock embedding/model dependencies
        self.patcher_emb = patch("app.memory.vault.generate_embedding")
        self.mock_emb = self.patcher_emb.start()
        self.mock_emb.return_value = [0.1] * 768

        self.patcher_ml = patch("app.memory.vault.predict_decision")
        self.mock_ml = self.patcher_ml.start()
        self.mock_ml.return_value = {
            "prediction": 0,
            "confidence": 0.99,
        }

        self.patcher_add = patch("app.memory.vault.add_memory_embedding")
        self.mock_add = self.patcher_add.start()

    def tearDown(self):
        self.patcher_emb.stop()
        self.patcher_ml.stop()
        self.patcher_add.stop()
        self.db.close()

    def test_create_memory_generates_unique_id(self):
        # Create a new memory
        res = create_memory(self.db, "user-123", "I love artificial intelligence.")
        self.assertEqual(res["status"], "stored")

        # Fetch the memory from DB
        db_mem = self.db.query(models.Memory).filter(models.Memory.id == res["memory_id"]).first()
        self.assertIsNotNone(db_mem)
        self.assertIsNotNone(db_mem.unique_id)
        self.assertEqual(len(db_mem.unique_id), 64)  # SHA-256 length is 64 hex characters

        # Serialize memory and check unique_id
        serialized = _serialize_memory(db_mem)
        self.assertEqual(serialized["unique_id"], db_mem.unique_id)

    def test_quarantine_memory_generates_unique_id(self):
        # Quarantine a memory
        record = quarantine_memory(
            db=self.db,
            user_id="user-123",
            fact="Unsafe content",
            category="GENERAL",
            attack_type="MEMORY_POISONING",
            reason="Unsafe testing",
            risk_score=0.9,
            poison_score=0.95
        )
        self.assertIsNotNone(record)
        self.assertIsNotNone(record.unique_id)
        self.assertEqual(len(record.unique_id), 64)

    def test_backfill_migration(self):
        # Insert a memory directly without unique_id (simulating pre-existing data)
        memory_obj = models.Memory(
            user_id="user-456",
            fact="Existing memory facts",
            category="GENERAL",
            unique_id=""  # Empty
        )
        self.db.add(memory_obj)

        quarantine_obj = models.QuarantineMemory(
            user_id="user-456",
            fact="Existing quarantine facts",
            category="GENERAL",
            reason="testing",
            unique_id=""  # Empty
        )
        self.db.add(quarantine_obj)
        self.db.commit()

        # Retrieve them, unique_id should be empty
        m_ret = self.db.query(models.Memory).filter(models.Memory.user_id == "user-456").first()
        q_ret = self.db.query(models.QuarantineMemory).filter(models.QuarantineMemory.user_id == "user-456").first()
        self.assertEqual(m_ret.unique_id, "")
        self.assertEqual(q_ret.unique_id, "")

        # Run backfill directly (using database session/engine)
        # In the test, we patch run_migrations's engine with our sqlite engine
        with patch("app.database.migrate.engine", self.engine):
            _backfill_unique_ids()

        self.db.refresh(m_ret)
        self.db.refresh(q_ret)

        self.assertIsNotNone(m_ret.unique_id)
        self.assertNotEqual(m_ret.unique_id, "")
        self.assertEqual(len(m_ret.unique_id), 64)

        self.assertIsNotNone(q_ret.unique_id)
        self.assertNotEqual(q_ret.unique_id, "")
        self.assertEqual(len(q_ret.unique_id), 64)


if __name__ == "__main__":
    unittest.main()
