"""
V2 Learning Component — track classification outcomes for threshold tuning.
"""

from app.database.models import ClassificationStat


def record_classification(
    db,
    component,
    predicted_label,
    confidence,
    was_blocked=False,
    user_corrected=False,
    correction_label=None,
):
    is_false_positive = (
        was_blocked
        and predicted_label != "SAFE"
        and user_corrected
    )
    is_false_negative = (
        not was_blocked
        and predicted_label == "SAFE"
        and user_corrected
    )

    stat = ClassificationStat(
        component=component,
        predicted_label=predicted_label,
        confidence=confidence,
        was_blocked=was_blocked,
        user_corrected=user_corrected,
        correction_label=correction_label,
        is_false_positive=is_false_positive,
        is_false_negative=is_false_negative,
    )
    db.add(stat)
    db.commit()
    return stat


def get_learning_stats(db):
    stats = db.query(ClassificationStat).all()

    total = len(stats)
    if total == 0:
        return {
            "total_classifications": 0,
            "correct_classifications": 0,
            "wrong_classifications": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "user_corrections": 0,
            "blocked_attacks": 0,
            "successful_attacks": 0,
            "accuracy": 0.0,
        }

    fps = sum(1 for s in stats if s.is_false_positive)
    fns = sum(1 for s in stats if s.is_false_negative)
    corrections = sum(1 for s in stats if s.user_corrected)
    blocked = sum(1 for s in stats if s.was_blocked)
    wrong = fps + fns

    return {
        "total_classifications": total,
        "correct_classifications": total - wrong,
        "wrong_classifications": wrong,
        "false_positives": fps,
        "false_negatives": fns,
        "user_corrections": corrections,
        "blocked_attacks": blocked,
        "successful_attacks": fns,
        "accuracy": round((total - wrong) / total, 4) if total else 0.0,
    }
