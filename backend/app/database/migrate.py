"""
Lightweight SQLite migration — adds V2 columns to existing tables.
"""

from sqlalchemy import inspect, text
from app.database.session import engine

MEMORY_COLUMNS = {
    "importance_score": "FLOAT DEFAULT 0.5",
    "verification_count": "INTEGER DEFAULT 0",
    "conflict_count": "INTEGER DEFAULT 0",
    "usage_count": "INTEGER DEFAULT 0",
    "attack_history": "VARCHAR DEFAULT ''",
    "status": "VARCHAR DEFAULT 'ACTIVE'",
    "memory_type": "VARCHAR DEFAULT 'LONG_TERM'",
    "trust_explanation": "VARCHAR DEFAULT ''",
    "unique_id": "VARCHAR DEFAULT ''",
}

QUARANTINE_COLUMNS = {
    "unique_id": "VARCHAR DEFAULT ''",
}

AUDIT_COLUMNS = {
    "intent": "VARCHAR DEFAULT 'UNKNOWN'",
    "intent_confidence": "FLOAT DEFAULT 0.0",
    "attack_type": "VARCHAR DEFAULT 'SAFE'",
    "attack_confidence": "FLOAT DEFAULT 0.0",
    "risk_level": "VARCHAR DEFAULT 'LOW'",
    "memory_category": "VARCHAR DEFAULT 'GENERAL'",
    "conflict_status": "VARCHAR DEFAULT 'NONE'",
    "trust_scores": "VARCHAR DEFAULT '[]'",
    "retrieved_memories": "VARCHAR DEFAULT ''",
    "memories_used": "VARCHAR DEFAULT ''",
    "poison_detected": "BOOLEAN DEFAULT 0",
    "quarantine_status": "VARCHAR DEFAULT 'NONE'",
    "response_confidence": "FLOAT DEFAULT 0.0",
    "memory_confidence": "FLOAT DEFAULT 0.0",
    "security_confidence": "FLOAT DEFAULT 0.0",
    "execution_time_ms": "FLOAT DEFAULT 0.0",
    "final_decision": "VARCHAR DEFAULT 'ALLOW'",
    "explanation": "VARCHAR DEFAULT ''",
}


def _add_missing_columns(table_name, column_defs):
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns(table_name)}

    with engine.begin() as conn:
        for col_name, col_type in column_defs.items():
            if col_name not in existing:
                conn.execute(
                    text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                )


def _correct_classification_stats_logic():
    inspector = inspect(engine)
    if "classification_stats" not in inspector.get_table_names():
        return
    with engine.begin() as conn:
        # Correct false positive records:
        # 1. Any record that was blocked but NOT user corrected is a TRUE positive, so is_false_positive should be FALSE
        conn.execute(
            text("UPDATE classification_stats SET is_false_positive = 0 WHERE was_blocked = 1 AND predicted_label != 'SAFE' AND user_corrected = 0")
        )
        # 2. Any record that was blocked AND was user corrected is a FALSE positive, so is_false_positive should be TRUE
        conn.execute(
            text("UPDATE classification_stats SET is_false_positive = 1 WHERE was_blocked = 1 AND predicted_label != 'SAFE' AND user_corrected = 1")
        )


def _backfill_unique_ids():
    import hashlib
    import uuid
    with engine.begin() as conn:
        # Backfill memories table
        rows = conn.execute(text("SELECT id, user_id, fact, created_at, unique_id FROM memories")).fetchall()
        for row in rows:
            m_id, user_id, fact, created_at, unique_id = row
            if not unique_id or unique_id == "":
                created_str = str(created_at) if created_at else str(uuid.uuid4())
                unique_id_str = f"{user_id}:{fact}:{created_str}:{uuid.uuid4()}"
                new_unique_id = hashlib.sha256(unique_id_str.encode('utf-8')).hexdigest()
                conn.execute(
                    text("UPDATE memories SET unique_id = :val WHERE id = :id"),
                    {"val": new_unique_id, "id": m_id}
                )

        # Backfill quarantine_memories table
        rows_q = conn.execute(text("SELECT id, user_id, fact, created_at, unique_id FROM quarantine_memories")).fetchall()
        for row in rows_q:
            q_id, user_id, fact, created_at, unique_id = row
            if not unique_id or unique_id == "":
                created_str = str(created_at) if created_at else str(uuid.uuid4())
                unique_id_str = f"{user_id}:{fact}:{created_str}:{uuid.uuid4()}"
                new_unique_id = hashlib.sha256(unique_id_str.encode('utf-8')).hexdigest()
                conn.execute(
                    text("UPDATE quarantine_memories SET unique_id = :val WHERE id = :id"),
                    {"val": new_unique_id, "id": q_id}
                )


def run_migrations():
    _add_missing_columns("memories", MEMORY_COLUMNS)
    _add_missing_columns("quarantine_memories", QUARANTINE_COLUMNS)
    _add_missing_columns("audit_events", AUDIT_COLUMNS)
    _correct_classification_stats_logic()
    _backfill_unique_ids()
