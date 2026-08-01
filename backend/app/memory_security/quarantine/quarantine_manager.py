from app.database.models import (
    QuarantineMemory
)


def quarantine_memory(
    db,
    user_id,
    fact,
    category,
    attack_type,
    reason,
    risk_score,
    poison_score
):

    import hashlib
    import uuid
    from datetime import datetime

    unique_id_str = f"{user_id}:{fact}:{datetime.utcnow().timestamp()}:{uuid.uuid4()}"
    unique_id = hashlib.sha256(unique_id_str.encode('utf-8')).hexdigest()

    record = QuarantineMemory(

        user_id=user_id,

        unique_id=unique_id,

        fact=fact,

        category=category,

        attack_type=attack_type,

        reason=reason,

        risk_score=risk_score,

        poison_score=poison_score

    )

    db.add(record)

    db.commit()

    db.refresh(record)

    return record