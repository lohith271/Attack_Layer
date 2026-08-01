"""
Memory worthiness — auto-store declarative statements without explicit 'remember'.
"""

import re

from app.neurosymbolic.embeddings import get_embedding
from app.neurosymbolic.prototype_bank import get_worthiness_prototypes
from app.neurosymbolic.similarity import get_similarity_engine

_engine = get_similarity_engine()

STORE_PATTERNS = [
    r"^i love\b",
    r"^i enjoy\b",
    r"^i often\b",
    r"^i usually\b",
    r"^i could\b",
    r"^i work\b",
    r"^i study\b",
    r"^i live\b",
    r"^my name is\b",
    r"^my goal is\b",
    r"^i prefer\b",
    r"^my favour",
    r"^my favor",
    r"^i have an interview\b",
    r"^i need to attend\b",
    r"^i am a\b",
    r"^i am from\b",
    r"^i visited\b",
    r"^i met\b",
    r"^remember that\b",
    r"^store\b",
    r"^save\b",
]


def should_store_memory(text: str) -> dict:
    text = text.strip()
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()
    stripped = text
    lowered = stripped.lower()

    if stripped.endswith("?"):
        return {"store": False, "store_score": 0.0, "ignore_score": 1.0}

    question_starts = (
        "what ", "where ", "who ", "when ", "why ", "how ", "which ",
        "do ", "does ", "did ", "can ", "could ", "would ", "should ",
        "explain ", "tell me ", "describe ",
    )
    if lowered.startswith(question_starts):
        return {"store": False, "store_score": 0.0, "ignore_score": 1.0}

    for pattern in STORE_PATTERNS:
        if re.search(pattern, lowered):
            return {"store": True, "store_score": 1.0, "ignore_score": 0.0}

    embedding = get_embedding(text)
    protos = get_worthiness_prototypes()
    store_score = _engine.score(embedding, protos.get("STORE", []))
    ignore_score = _engine.score(embedding, protos.get("IGNORE", []))

    return {
        "store": store_score > ignore_score,
        "store_score": round(store_score, 4),
        "ignore_score": round(ignore_score, 4),
    }
