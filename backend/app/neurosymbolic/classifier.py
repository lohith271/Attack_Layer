"""
Unified memory classifier — semantic category and memory type are independent.
Uses prototype attention matching with keyword fast-paths.
"""

import re

from app.core.config import CLASSIFICATION_CONFIDENCE_THRESHOLD
from app.core.types import MemoryCategory
from app.neurosymbolic.embeddings import get_embedding
from app.neurosymbolic.prototype_bank import (
    get_category_prototypes,
    get_memory_type_prototypes,
    get_query_category_prototypes,
)
from app.neurosymbolic.similarity import get_similarity_engine

_engine = get_similarity_engine()

EPISODIC_KEYWORDS = [
    "today", "yesterday", "this morning", "this afternoon", "this evening",
    "just now", "i had", "i ate", "i watched", "i visited", "i met",
    "i went", "last night", "earlier today", "recently", "lately",
]

SHORT_TERM_KEYWORDS = [
    "next week", "next monday", "next month", "tomorrow", "upcoming",
    "interview", "seminar", "meeting", "deadline", "appointment",
    "exam", "due", "need to attend", "have to attend",
]

LONG_TERM_KEYWORDS = [
    "my name", "i am", "i work", "i study", "i live", "i prefer",
    "i enjoy", "i love", "i like", "i usually", "i often",
    "i could eat", "my goal is", "my favourite", "my favorite",
]

CATEGORY_KEYWORD_RULES = [
    (MemoryCategory.PERSONAL_INFO.value, [r"\bmy name is\b", r"\bi am \d+ years"]),
    (MemoryCategory.PROFESSION.value, [r"\bi work\b", r"\bi work as\b", r"\bmy profession\b"]),
    (MemoryCategory.LOCATION.value, [r"\bi live in\b", r"\bi am from\b", r"\bi visited\b", r"\bi went to\b"]),
    (MemoryCategory.FOOD_PREFERENCE.value, [r"\bi love eating\b", r"\bi could eat\b", r"\bi enjoy eating\b"]),
    (MemoryCategory.CODING_PREFERENCE.value, [r"\bi usually code\b", r"\bi prefer .* to code\b", r"\bcoding in\b"]),
    (MemoryCategory.GENERAL_FACT.value, [r"\bi have an interview\b", r"\bi need to attend\b", r"\bnext week\b", r"\bnext monday\b"]),
    (MemoryCategory.TOOL_POLICY.value, [r"\btrust all external\b", r"\bdisable tool\b", r"\ballow all tools\b"]),
]


def _keyword_category(text: str):
    lowered = text.lower()
    for category, patterns in CATEGORY_KEYWORD_RULES:
        for pattern in patterns:
            if re.search(pattern, lowered):
                return category, 0.95
    return None, 0.0


def _keyword_memory_type(text: str):
    lowered = text.lower()
    if any(re.search(r"\b" + re.escape(kw) + r"\b", lowered) for kw in EPISODIC_KEYWORDS):
        return "EPISODIC", 0.92
    if any(re.search(r"\b" + re.escape(kw) + r"\b", lowered) for kw in SHORT_TERM_KEYWORDS):
        return "SHORT_TERM", 0.90
    if any(re.search(r"\b" + re.escape(kw) + r"\b", lowered) for kw in LONG_TERM_KEYWORDS):
        return "LONG_TERM", 0.93
    return None, 0.0


def classify_category(text: str) -> dict:
    text = text.strip()
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()
    kw_cat, kw_conf = _keyword_category(text)
    embedding = get_embedding(text)
    prototypes = get_category_prototypes()
    scores = _engine.rank(embedding, prototypes)

    if not scores:
        return {"category": "GENERAL", "confidence": 0.5, "alternatives": []}

    best_category, best_score = scores[0]

    if kw_cat and kw_conf >= 0.90:
        best_category = kw_cat
        best_score = max(best_score, kw_conf)

    if best_score < CLASSIFICATION_CONFIDENCE_THRESHOLD:
        if kw_cat:
            best_category = kw_cat
            best_score = kw_conf
        else:
            best_category = "GENERAL"
            best_score = max(best_score, 0.5)

    return {
        "category": best_category,
        "confidence": round(best_score, 4),
        "alternatives": [{"category": c, "confidence": s} for c, s in scores[1:4]],
    }


def classify_memory_type(text: str) -> dict:
    text = text.strip()
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()
    kw_type, kw_conf = _keyword_memory_type(text)
    embedding = get_embedding(text)
    prototypes = get_memory_type_prototypes()
    scores = _engine.rank(embedding, prototypes)

    if kw_type:
        return {"memory_type": kw_type, "confidence": kw_conf}

    if scores:
        best_type, best_score = scores[0]
        if best_score >= CLASSIFICATION_CONFIDENCE_THRESHOLD:
            return {"memory_type": best_type, "confidence": round(best_score, 4)}

    return {"memory_type": "LONG_TERM", "confidence": 0.70}


def classify_memory(text: str) -> dict:
    return classify_category(text)


def classify_query_categories(text: str, limit: int = 2) -> list:
    lowered = text.lower()
    if any(term in lowered for term in ("suggest", "recommend", "project for me")):
        return ["STUDY_DOMAIN", "CAREER", "CODING_PREFERENCE"]

    if any(term in lowered for term in ("code", "coding", "programming", "language")):
        return ["CODING_PREFERENCE"]

    if any(term in lowered for term in ("eat", "food", "love eating", "favourite food", "favorite food")):
        return ["FOOD_PREFERENCE"]

    if "what do i like" in lowered and "food" not in lowered and "eat" not in lowered:
        return ["SPORT_PREFERENCE"]

    if any(term in lowered for term in ("sport", "football", "cricket", "tennis", "playing")):
        return ["SPORT_PREFERENCE"]

    if any(term in lowered for term in ("work", "job", "profession", "career")):
        return ["PROFESSION", "CAREER"]

    if any(term in lowered for term in ("live", "city", "location", "where")):
        return ["LOCATION"]

    embedding = get_embedding(text)
    prototypes = get_query_category_prototypes()
    scores = _engine.rank(embedding, prototypes)
    return [cat for cat, _ in scores[:limit]]
