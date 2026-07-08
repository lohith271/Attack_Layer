"""
test_reputation.py — Unit tests for Model Reputation & Dynamic Weights.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def fresh_reputation(tmp_path, monkeypatch):
    """Patch reputation file to a temp location and reset to defaults."""
    import app.ml.model_reputation as mr

    rep_file = str(tmp_path / "model_reputation.json")
    monkeypatch.setattr(mr, "REPUTATION_FILE", rep_file)
    mr.save_reputation(mr.DEFAULT_REPUTATION)
    return rep_file


class TestLoadSave:
    """Basic serialisation round-trip."""

    def test_load_creates_default_when_missing(self, tmp_path, monkeypatch):
        import app.ml.model_reputation as mr

        rep_file = str(tmp_path / "non_existent.json")
        monkeypatch.setattr(mr, "REPUTATION_FILE", rep_file)

        data = mr.load_reputation()
        assert "svm" in data
        assert abs(data["svm"]["weight"] - 0.1111) < 1e-4
        assert os.path.exists(rep_file)

    def test_save_and_reload(self, fresh_reputation):
        import app.ml.model_reputation as mr

        data = mr.load_reputation()
        data["svm"]["weight"] = 0.42
        mr.save_reputation(data)

        reloaded = mr.load_reputation()
        assert reloaded["svm"]["weight"] == 0.42


class TestGetWeights:
    """Dynamic weight normalisation."""

    def test_equal_weights_for_all_models(self, fresh_reputation):
        import app.ml.model_reputation as mr

        w = mr.get_weights()
        assert len(w) == 9
        assert abs(sum(w.values()) - 1.0) < 1e-9

    def test_weights_subset(self, fresh_reputation):
        import app.ml.model_reputation as mr

        w = mr.get_weights(active_models=["svm", "xgboost"])
        assert len(w) == 2
        assert abs(sum(w.values()) - 1.0) < 1e-9

    def test_empty_active_models(self, fresh_reputation):
        import app.ml.model_reputation as mr
        w = mr.get_weights(active_models=[])
        assert w == {}


class TestUpdateReputation:
    """Weight adjustment on agreement / disagreement."""

    def test_agreement_increases_count(self, fresh_reputation):
        import app.ml.model_reputation as mr

        mr.update_reputation("svm", agreed=True, confidence=0.95)
        data = mr.load_reputation()
        assert data["svm"]["total_predictions"] == 1
        assert data["svm"]["agreement_count"] == 1
        assert data["svm"]["agreement_rate"] == 1.0

    def test_disagreement_reduces_weight(self, fresh_reputation):
        import app.ml.model_reputation as mr

        original = mr.load_reputation()["svm"]["weight"]
        mr.update_reputation("svm", agreed=False, confidence=0.4)
        updated = mr.load_reputation()

        assert updated["svm"]["weight"] < original
        assert updated["svm"]["weight"] >= 0.10  # floor

    def test_weight_redistribution(self, fresh_reputation):
        import app.ml.model_reputation as mr

        before = mr.load_reputation()
        total_before = sum(m["weight"] for m in before.values())

        mr.update_reputation("svm", agreed=False, confidence=0.3)

        after = mr.load_reputation()
        total_after = sum(m["weight"] for m in after.values())

        # Total weight should be conserved
        assert abs(total_before - total_after) < 1e-9

    def test_weight_floor(self, fresh_reputation):
        """Repeatedly disagreeing should not drop weight below 0.10."""
        import app.ml.model_reputation as mr

        for _ in range(50):
            mr.update_reputation("svm", agreed=False, confidence=0.5)

        data = mr.load_reputation()
        assert data["svm"]["weight"] == 0.10


class TestResetReputation:
    def test_reset_restores_defaults(self, fresh_reputation):
        import app.ml.model_reputation as mr

        mr.update_reputation("xgboost", agreed=False, confidence=0.3)
        mr.reset_reputation()

        data = mr.load_reputation()
        assert abs(data["xgboost"]["weight"] - 0.1111) < 1e-4
        assert data["xgboost"]["total_predictions"] == 0
