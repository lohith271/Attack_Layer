import sys
import os
import numpy as np
import pytest
from unittest.mock import patch, MagicMock

# Ensure backend is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def test_one_class_svm_pipeline():
    """Verify that the OneClassSVM pipeline (Scaling + PCA + SVM) fits and predicts correctly."""
    from sklearn.pipeline import Pipeline
    from sklearn.svm import OneClassSVM
    
    # Generate clean mock data (normally distributed around a centroid)
    np.random.seed(42)
    clean_data = np.random.normal(loc=0.0, scale=0.5, size=(100, 768))
    
    # Instantiate pipeline matching train_one_class_svm.py
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=0.95, random_state=42)),
        ('oc_svm', OneClassSVM(kernel='rbf', gamma='scale', nu=0.05))
    ])
    
    # Fit and test
    model.fit(clean_data)
    
    # In-distribution test
    test_in = np.random.normal(loc=0.0, scale=0.5, size=(5, 768))
    preds_in = model.predict(test_in)
    assert preds_in.shape == (5,)
    
    # Out-of-distribution test (noise far away)
    test_out = np.random.normal(loc=5.0, scale=1.0, size=(5, 768))
    preds_out = model.predict(test_out)
    # The anomaly detector should flag far-away vectors as anomalies (-1)
    assert np.all(preds_out == -1)

def test_predict_decision_one_class_anomaly():
    """Verify that predict_decision sets prediction=1 and confidence=0.99 when One-Class SVM flags anomaly."""
    from app.ml.predict_decision import predict_decision
    
    # Mock loaded model to return -1 (anomaly)
    mock_oc_svm = MagicMock()
    mock_oc_svm.predict.return_value = np.array([-1])
    
    # Mock ensemble returning benign prediction
    mock_ensemble_res = {
        "prediction": 0,
        "confidence": 0.85,
        "model_predictions": {}
    }
    
    with patch("app.ml.predict_decision.get_model", return_value=mock_oc_svm), \
         patch("app.ml.predict_decision.get_ensemble_prediction", return_value=mock_ensemble_res), \
         patch("app.ml.predict_decision.AdversarialGuard.assess_adversarial_risk", return_value={"adversarial_detected": False}):
        
        result = predict_decision([0.0] * 768)
        
        assert result["one_class_anomaly"] is True
        assert result["prediction"] == 1  # Overridden to Attack
        assert result["confidence"] == 0.99  # Boosted confidence

def test_predict_decision_one_class_benign():
    """Verify that predict_decision preserves ensemble decisions when One-Class SVM flags benign."""
    from app.ml.predict_decision import predict_decision
    
    # Mock loaded model to return 1 (benign)
    mock_oc_svm = MagicMock()
    mock_oc_svm.predict.return_value = np.array([1])
    
    mock_ensemble_res = {
        "prediction": 0,
        "confidence": 0.85,
        "model_predictions": {}
    }
    
    with patch("app.ml.predict_decision.get_model", return_value=mock_oc_svm), \
         patch("app.ml.predict_decision.get_ensemble_prediction", return_value=mock_ensemble_res), \
         patch("app.ml.predict_decision.AdversarialGuard.assess_adversarial_risk", return_value={"adversarial_detected": False}):
        
        result = predict_decision([0.0] * 768)
        
        assert result["one_class_anomaly"] is False
        assert result["prediction"] == 0
        assert result["confidence"] == 0.85
