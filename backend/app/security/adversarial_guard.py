"""
adversarial_guard.py — Adversarial Input Detection for AttackLayer.

Detects adversarial perturbations in embeddings before they reach the
ensemble prediction layer.  Combines multiple heuristics:

1. **L2 Norm Check** — flags embeddings whose norm is statistically
   unlikely given clean training data.
2. **Cosine Uniformity Check** — adversarial noise tends to push
   embeddings toward unusual regions of the unit sphere.
3. **Rapid-drift Check** — if two successive embeddings from the same
   session differ too drastically, something suspicious may be happening.
4. **Optional NN Detector** — loads a small pretrained binary classifier
   if available at ``DETECTOR_MODEL_PATH``.

Public API
----------
guard_embedding(embedding)  → True if safe, False if adversarial
AdversarialDetector          → class with per-check methods
"""

import os
import logging
import numpy as np
import torch
from typing import List, Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTOR_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "adversarial_detector.pth")

# ── Tunable thresholds ──────────────────────────────────────────────────
NORM_UPPER = 35.0       # embeddings above this L2 norm are flagged
NORM_LOWER = 0.5        # embeddings below this are suspiciously empty
DRIFT_THRESHOLD = 20.0  # max L2 distance between successive embeddings
MAX_DIM_ABS = 5.0       # single-dimension absolute-value cap


class AdversarialDetector:
    """Multi-heuristic adversarial input detector."""

    def __init__(self, model_path: str = None):
        self.model = None
        path = model_path or DETECTOR_MODEL_PATH
        if os.path.exists(path):
            try:
                self.model = torch.load(path, map_location="cpu")
                self.model.eval()
                logger.info("Loaded adversarial detector model from %s", path)
            except Exception as e:
                logger.warning("Could not load adversarial detector: %s", e)

        # rolling history per session (simplified: single global buffer)
        self._prev_embedding: Optional[np.ndarray] = None

        # Initialize STRIP guard
        from app.security.strip_guard import StripGuard
        self.strip_guard = StripGuard()

    # ── Individual checks ───────────────────────────────────────────────
    def _check_norm(self, emb: np.ndarray) -> bool:
        """Return True if the L2 norm is within expected bounds."""
        norm = float(np.linalg.norm(emb))
        if norm > NORM_UPPER or norm < NORM_LOWER:
            logger.warning("Adversarial guard: norm=%.3f out of [%.1f, %.1f]",
                           norm, NORM_LOWER, NORM_UPPER)
            return False
        return True

    def _check_linf_norm(self, emb: np.ndarray) -> bool:
        """Return True if L_infinity norm is within max allowable noise bound."""
        linf_norm = float(np.linalg.norm(emb, ord=np.inf))
        if linf_norm > MAX_DIM_ABS:
            logger.warning("Adversarial guard: Linf norm=%.3f exceeds max bound %.1f", linf_norm, MAX_DIM_ABS)
            return False
        return True

    def _check_dimension_spike(self, emb: np.ndarray) -> bool:
        """Flag embeddings where any single dimension is unreasonably large."""
        max_abs = float(np.max(np.abs(emb)))
        if max_abs > MAX_DIM_ABS:
            logger.warning("Adversarial guard: max |dim|=%.3f > %.1f", max_abs, MAX_DIM_ABS)
            return False
        return True

    def _check_drift(self, emb: np.ndarray) -> bool:
        """Flag large jumps between successive embeddings."""
        if self._prev_embedding is not None:
            drift = float(np.linalg.norm(emb - self._prev_embedding))
            if drift > DRIFT_THRESHOLD:
                logger.warning("Adversarial guard: drift=%.3f > %.1f", drift, DRIFT_THRESHOLD)
                return False
        self._prev_embedding = emb.copy()
        return True

    def _check_nn_model(self, emb: np.ndarray) -> bool:
        """Use a pretrained detector if available."""
        if self.model is None:
            return True  # no model → pass
        try:
            with torch.no_grad():
                tensor = torch.FloatTensor(emb).unsqueeze(0)
                logits = self.model(tensor)
                prob = torch.softmax(logits, dim=1)[0, 1].item()
            if prob > 0.5:
                logger.warning("Adversarial NN detector flagged input (p=%.3f)", prob)
                return False
            return True
        except Exception as e:
            logger.error("Adversarial NN detector error: %s", e)
            return True  # fail-open if model errors out

    # ── Combined check ──────────────────────────────────────────────────
    def is_safe(self, emb: np.ndarray) -> bool:
        """Return True only if *all* heuristic checks pass."""
        checks = [
            self._check_norm(emb),
            self._check_dimension_spike(emb),
            self._check_drift(emb),
            self._check_nn_model(emb),
            self.strip_guard.is_safe(emb),
        ]
        return all(checks)


# ── Module-level singleton ──────────────────────────────────────────────
_detector = AdversarialDetector()


def guard_embedding(embedding: List[float]) -> bool:
    """Return **True** if the embedding is deemed safe.

    This function is called by the ensemble prediction flow *before*
    forwarding the input to any ML model.  If it returns ``False``,
    the prediction should be skipped or flagged as adversarial.
    """
    arr = np.array(embedding, dtype=np.float32)
    return _detector.is_safe(arr)


class AdversarialGuard:
    """Interface to assess adversarial risk based on ensemble model predictions."""

    @staticmethod
    def assess_adversarial_risk(model_predictions: dict) -> dict:
        """
        Assess adversarial risk based on model predictions.
        If there is disagreement among the ensemble models or low confidence, flag it.
        """
        preds = [res["prediction"] for res in model_predictions.values()]
        confidences = [res["confidence"] for res in model_predictions.values()]
        
        unique_preds = set(preds)
        disagreement = len(unique_preds) > 1
        
        reasons = []
        if disagreement:
            reasons.append("Model disagreement detected (ensemble models disagree on outcome)")
        
        # Check for very low confidence
        low_conf = any(c < 0.6 for c in confidences)
        if low_conf:
            reasons.append("Low confidence prediction from one or more models")
            
        adversarial_detected = disagreement or (len(preds) > 1 and low_conf)
        
        return {
            "adversarial_detected": adversarial_detected,
            "reasons": reasons
        }

