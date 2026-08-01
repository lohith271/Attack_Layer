from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Float
from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey

from datetime import datetime

from app.database.session import Base


# =====================================================
# MEMORY VAULT
# =====================================================

class Memory(Base):
    __tablename__ = "memories"

    id = Column(Integer, primary_key=True, index=True)

    unique_id = Column(
        String,
        unique=True,
        index=True,
        nullable=True
    )

    user_id = Column(String, nullable=False)

    fact = Column(
        String,
        nullable=False
    )

    # Semantic Category
    # Examples:
    # FOOD_PREFERENCE
    # PROFESSION
    # LOCATION
    # TOOL_POLICY
    # etc.

    category = Column(
        String,
        default="UNKNOWN"
    )

    # Memory Type
    # EPISODIC
    # SHORT_TERM
    # LONG_TERM

    memory_type = Column(
        String,
        default="SHORT_TERM"
    )

    # ------------------------------
    # Trust System
    # ------------------------------

    trust_score = Column(Float, default=0.50)

    confidence_score = Column(Float, default=0.50)

    conflict_score = Column(Float, default=0.0)

    poison_score = Column(Float, default=0.0)

    risk_score = Column(Float, default=0.0)

    # ------------------------------
    # Security
    # ------------------------------

    poison_flag = Column(Boolean, default=False)

    verified = Column(Boolean, default=False)

    attack_type = Column(String, default="NONE")

    sensitivity_level = Column(String, default="LOW")

    source = Column(String, default="USER")

    final_decision = Column(
        String,
        default="ALLOW"
    )
    # ------------------------------
    # ML Decision Layer
    # ------------------------------

    ml_prediction = Column(
        Integer,
        nullable=True
    )

    ml_confidence = Column(
        Float,
        default=0.0
    )

    ml_decision = Column(
        String,
        default="ALLOW"
    )

    # ------------------------------
    # Versioning
    # ------------------------------

    memory_version = Column(
        Integer,
        default=1
    )

    parent_memory_id = Column(
        Integer,
        nullable=True
    )

    active = Column(
        Boolean,
        default=True
    )

    preference_stability_score = Column(
        Float,
        nullable=True
    )

    preference_drift_score = Column(
        Float,
        nullable=True
    )

    importance_score = Column(
        Float,
        default=0.50
    )

    verification_count = Column(
        Integer,
        default=0
    )

    conflict_count = Column(
        Integer,
        default=0
    )

    usage_count = Column(
        Integer,
        default=0
    )

    attack_history = Column(
        String,
        default=""
    )

    trust_explanation = Column(
        String,
        default=""
    )

    status = Column(
        String,
        default="ACTIVE"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


# =====================================================
# PREFERENCE EVENTS
# =====================================================

class PreferenceEvent(Base):
    __tablename__ = "preference_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        String,
        nullable=False
    )

    memory_id = Column(
        Integer,
        nullable=True
    )

    old_fact = Column(
        String,
        nullable=False
    )

    new_fact = Column(
        String,
        nullable=False
    )

    category = Column(
        String,
        default="PREFERENCE"
    )

    stability_score = Column(
        Float,
        default=1.0
    )

    drift_score = Column(
        Float,
        default=0.0
    )

    is_legitimate_update = Column(
        Boolean,
        default=True
    )

    attack_type = Column(
        String,
        default="PREFERENCE_UPDATE"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# TOOL POLICY EVENTS
# =====================================================

class ToolPolicyEvent(Base):
    __tablename__ = "tool_policy_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        String,
        nullable=False
    )

    memory_id = Column(
        Integer,
        nullable=True
    )

    policy_text = Column(
        String,
        nullable=False
    )

    violation_reason = Column(
        String,
        default=""
    )

    risk_score = Column(
        Float,
        default=0.0
    )

    decision = Column(
        String,
        nullable=False
    )

    unapproved_domains = Column(
        String,
        default=""
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# MEMORY QUARANTINE
# =====================================================

class QuarantineMemory(Base):
    __tablename__ = "quarantine_memories"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    unique_id = Column(
        String,
        unique=True,
        index=True,
        nullable=True
    )

    user_id = Column(
        String,
        nullable=False
    )

    fact = Column(
        String,
        nullable=False
    )

    category = Column(
        String,
        default="UNKNOWN"
    )

    attack_type = Column(
        String,
        default="UNKNOWN"
    )

    reason = Column(
        String,
        nullable=False
    )

    risk_score = Column(
        Float,
        default=0.0
    )

    poison_score = Column(
        Float,
        default=0.0
    )

    review_status = Column(
        String,
        default="PENDING"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# POISON EVENTS
# =====================================================

class PoisonEvent(Base):
    __tablename__ = "poison_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    memory_id = Column(
        Integer,
        nullable=True
    )

    attack_type = Column(
        String,
        nullable=False
    )

    poison_score = Column(
        Float,
        default=0.0
    )

    decision = Column(
        String,
        nullable=False
    )

    details = Column(
        String,
        default=""
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# PROPAGATION EVENTS
# =====================================================

class PropagationEvent(Base):
    __tablename__ = "propagation_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    memory_id = Column(
        Integer,
        nullable=False
    )

    origin_agent = Column(
        String,
        nullable=False
    )

    target_agent = Column(
        String,
        nullable=False
    )

    propagation_path = Column(
        String,
        nullable=False
    )

    spread_score = Column(
        Float,
        default=0.0
    )

    fact = Column(
        String,
        default=""
    )

    poison_score = Column(
        Float,
        default=0.0
    )

    attack_type = Column(
        String,
        default="NONE"
    )

    spread_percentage = Column(
        Float,
        default=0.0
    )

    decision = Column(
        String,
        default="ALLOW"
    )

    root_memory_id = Column(
        Integer,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# AUDIT EVENTS
# =====================================================

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    operation = Column(
        String,
        nullable=False
    )

    decision = Column(
        String,
        nullable=False
    )

    threat = Column(
        String,
        nullable=False
    )

    risk_score = Column(
        Float,
        default=0.0
    )

    payload = Column(
        String,
        nullable=False
    )

    intent = Column(
        String,
        default="UNKNOWN"
    )

    intent_confidence = Column(
        Float,
        default=0.0
    )

    attack_type = Column(
        String,
        default="SAFE"
    )

    attack_confidence = Column(
        Float,
        default=0.0
    )

    risk_level = Column(
        String,
        default="LOW"
    )

    memory_category = Column(
        String,
        default="GENERAL"
    )

    conflict_status = Column(
        String,
        default="NONE"
    )

    trust_scores = Column(
        String,
        default="[]"
    )

    retrieved_memories = Column(
        String,
        default=""
    )

    memories_used = Column(
        String,
        default=""
    )

    poison_detected = Column(
        Boolean,
        default=False
    )

    quarantine_status = Column(
        String,
        default="NONE"
    )

    response_confidence = Column(
        Float,
        default=0.0
    )

    memory_confidence = Column(
        Float,
        default=0.0
    )

    security_confidence = Column(
        Float,
        default=0.0
    )

    execution_time_ms = Column(
        Float,
        default=0.0
    )

    final_decision = Column(
        String,
        default="ALLOW"
    )

    explanation = Column(
        String,
        default=""
    )

    ip_address = Column(
        String,
        nullable=True
    )

    memory_id = Column(
        Integer,
        nullable=True
    )
    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# MEMORY HISTORY
# =====================================================

class MemoryHistory(Base):
    __tablename__ = "memory_history"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    memory_id = Column(
        Integer,
        nullable=False
    )

    user_id = Column(
        String,
        nullable=False
    )

    old_fact = Column(
        String,
        nullable=False
    )

    new_fact = Column(
        String,
        nullable=False
    )

    category = Column(
        String,
        nullable=False
    )

    old_version = Column(
        Integer,
        nullable=False
    )

    new_version = Column(
        Integer,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =====================================================
# V2 REFLECTION LOGS
# =====================================================

class ReflectionLog(Base):
    __tablename__ = "reflection_logs"

    id = Column(Integer, primary_key=True, index=True)

    query = Column(String, default="")

    answer_supported = Column(Boolean, default=True)

    retrieval_success = Column(Boolean, default=False)

    low_trust_memory_used = Column(Boolean, default=False)

    attack_bypass_suspected = Column(Boolean, default=False)

    issues = Column(String, default="")

    improvements = Column(String, default="")

    response_confidence = Column(Float, default=0.0)

    memory_confidence = Column(Float, default=0.0)

    security_confidence = Column(Float, default=0.0)

    created_at = Column(DateTime, default=datetime.utcnow)


# =====================================================
# V2 CLASSIFICATION STATS (LEARNING)
# =====================================================

class ClassificationStat(Base):
    __tablename__ = "classification_stats"

    id = Column(Integer, primary_key=True, index=True)

    component = Column(String, nullable=False)

    predicted_label = Column(String, nullable=False)

    confidence = Column(Float, default=0.0)

    was_blocked = Column(Boolean, default=False)

    user_corrected = Column(Boolean, default=False)

    correction_label = Column(String, nullable=True)

    is_false_positive = Column(Boolean, default=False)

    is_false_negative = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)


# =====================================================
# BLOCKED IP REGISTRY & HUMAN APPROVAL
# =====================================================

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)

    ip_address = Column(String, unique=True, nullable=False, index=True)

    status = Column(String, default="TRUSTED")  # TRUSTED, PENDING, BLOCKED

    block_count = Column(Integer, default=0)

    total_interactions = Column(Integer, default=0)

    block_rate = Column(Float, default=0.0)

    reason = Column(String, default="EXCESSIVE_BLOCKS")

    approved_by_human = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)