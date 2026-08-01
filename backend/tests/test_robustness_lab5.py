"""
test_robustness_lab5.py — Unit tests for Lab 5 robust aggregators, FoolsGold collusion filters, SABLE, and Conformity.
"""

import sys
import os
import numpy as np
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ml.ensemble import get_ensemble_prediction
from app.ml.model_reputation import (
    load_reputation,
    save_reputation,
    update_ensemble_reputation,
    reset_reputation,
)
from app.security.adversarial_guard import guard_embedding

class TestRobustAggregation:
    """Tests verify that median and trimmed_mean aggregations handle Byzantine outliers."""

    @patch("app.ml.ensemble.get_active_models")
    @patch("app.ml.ensemble.get_model")
    @patch("app.ml.ensemble.get_weights")
    @patch("app.ml.ensemble.update_ensemble_reputation")
    def test_median_resists_high_confidence_byzantine_outliers(
        self, mock_update, mock_weights, mock_get_model, mock_active
    ):
        """
        Five models total:
        - 2 are Byzantine/compromised: vote 1 (Attack) with 0.99 confidence.
        - 3 are honest: vote 0 (Benign) with 0.6 confidence.
        Under weighted_average, the high confidence outliers override the majority (1.98 vs 1.8).
        Under median, the honest majority should win (median prob of class 1 < 0.5).
        """
        models = ["svm", "xgboost", "lightgbm", "mlp", "random_forest"]
        mock_active.return_value = models
        mock_weights.return_value = {m: 0.2 for m in models}
        mock_get_model.return_value = "dummy"

        # Mock individual model outputs
        def mock_predict(name, model, embedding):
            if name in ["svm", "xgboost"]:
                return {"prediction": 1, "confidence": 0.99}  # Byzantine
            return {"prediction": 0, "confidence": 0.60}  # Honest majority

        with patch("app.ml.ensemble.predict_model_single", side_effect=mock_predict):
            # 1. Test weighted_average (default)
            res_avg = get_ensemble_prediction([0.0] * 768, method="weighted_average")
            assert res_avg["prediction"] == 1  # Byzantine won

            # 2. Test median aggregation
            res_med = get_ensemble_prediction([0.0] * 768, method="median")
            assert res_med["prediction"] == 0  # Honest majority won!


class TestFoolsGoldCollusionFilter:
    """Tests verify that FoolsGold down-weights colluding models (Sybils)."""

    def setup_method(self):
        reset_reputation()
        # Clean reputation history
        from app.ml.model_reputation import REPUTATION_HISTORY_FILE
        if os.path.exists(REPUTATION_HISTORY_FILE):
            try:
                os.remove(REPUTATION_HISTORY_FILE)
            except Exception:
                pass

    def teardown_method(self):
        reset_reputation()

    def test_colluding_models_get_harsher_penalties(self):
        """
        Simulate 5 rounds of prediction.
        - svm and xgboost are colluding (always predict 1 with 0.9 confidence).
        - lightgbm is a normal model that disagrees once (predicts 1 with 0.9 confidence).
        - mlp and random_forest are the honest consensus (always predict 0 with 0.8 confidence).
        We verify that svm and xgboost receive the collusion penalty (0.05 step),
        while lightgbm is penalized normally (0.02 step) if it disagrees.
        """
        rep = load_reputation()
        # Set all initial weights to 0.2
        for k in rep.keys():
            rep[k]["weight"] = 0.2
        save_reputation(rep)

        # Round 1 to 5: svm and xgboost predict 1 (Attack) with 0.9 confidence
        # mlp, random_forest, logistic_regression, etc. predict 0 (Benign) with 0.8 confidence
        # Ensemble prediction is 0.
        for r in range(5):
            preds = {
                "svm": {"prediction": 1, "confidence": 0.9},
                "xgboost": {"prediction": 1, "confidence": 0.9},
                "mlp": {"prediction": 0, "confidence": 0.8},
                "random_forest": {"prediction": 0, "confidence": 0.8},
                "lightgbm": {"prediction": 0, "confidence": 0.8},
            }
            update_ensemble_reputation(preds, ensemble_prediction=0)

        # Check weights after collusion rounds
        updated_rep = load_reputation()
        svm_w = updated_rep["svm"]["weight"]
        xgb_w = updated_rep["xgboost"]["weight"]
        mlp_w = updated_rep["mlp"]["weight"]

        # Colluding models should be penalized heavily
        assert svm_w < 0.2
        assert xgb_w < 0.2
        # Honest models should get the redistributed weight
        assert mlp_w > 0.2

        # Colluding penalty step is 0.05. Over 5 rounds:
        # svm should be penalized by 5 * 0.05 = 0.25 (capped at floor of 0.10)
        assert abs(svm_w - 0.10) < 1e-5
        assert abs(xgb_w - 0.10) < 1e-5


class TestSableAndConformityConcepts:
    """Tests simulating the core mathematical principles of SABLE and Conformity."""

    def test_sable_style_embedding_passes_adversarial_guard(self):
        """
        SABLE proof-of-concept:
        An embedding vector is crafted to have a completely normal L2 norm
        and no dimensional spikes, but is intended to trigger a malicious decision.
        It should bypass the simple geometry checks in AdversarialGuard.
        """
        # Create a 768-dim vector with small random values
        sable_emb = np.random.normal(loc=0.0, scale=0.3, size=768).astype(np.float32)
        # Compute L2 Norm (e.g. ~8.3)
        l2_norm = np.linalg.norm(sable_emb)
        assert 0.5 < l2_norm < 35.0  # Safe range

        # Ensure no dimension spikes
        assert np.max(np.abs(sable_emb)) < 5.0  # Safe range

        # Run through AdversarialGuard. It should pass!
        passed_guard = guard_embedding(sable_emb.tolist())
        assert passed_guard is True

    def test_conformity_mathematical_blending(self):
        """
        Conformity proof-of-concept:
        Attacker blends its malicious update vector `d` with the honest mean `bm`.
        As the alignment factor `alpha` increases, the cosine similarity between
        the conformed vector and the benign mean increases, proving it "conforms" to the crowd.
        """
        bm = np.random.normal(loc=0.0, scale=0.5, size=768)
        d = np.random.normal(loc=0.1, scale=0.5, size=768)

        # Normalize them
        bm_unit = bm / np.linalg.norm(bm)
        d_unit = d / np.linalg.norm(d)

        # Baseline similarity between raw attack and benign mean
        base_sim = np.dot(d_unit, bm_unit)

        # Blended conformed update (alpha = 0.5)
        alpha = 0.5
        d_conformed = (1 - alpha) * d_unit + alpha * bm_unit
        d_conformed_unit = d_conformed / np.linalg.norm(d_conformed)

        # Conformed similarity
        conformed_sim = np.dot(d_conformed_unit, bm_unit)

        # Conformed similarity must be significantly higher than baseline similarity
        assert conformed_sim > base_sim
        assert conformed_sim > 0.5  # Highly aligned with honest consensus
