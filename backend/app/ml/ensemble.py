import os
import numpy as np
import torch
from app.ml.model_manager import get_model, get_active_models
from app.ml.model_reputation import get_weights, update_reputation, update_ensemble_reputation

def predict_model_single(model_name: str, model_instance, embedding: np.ndarray) -> dict:
    """
    Get prediction and confidence from a single model instance.
    Input embedding is a 1D numpy array of shape (768,) or similar.
    Returns: {"prediction": int, "confidence": float}
    """
    # Ensure 2D input for models
    X = embedding.reshape(1, -1)
    
    if model_name in ["mlp", "transformer_emb", "cnn_1d"]:
        # PyTorch model
        with torch.no_grad():
            tensor_input = torch.FloatTensor(X)
            logits = model_instance(tensor_input)
            probs = torch.softmax(logits, dim=1).numpy()[0]
            
        prediction = int(np.argmax(probs))
        confidence = float(probs[prediction])
    else:
        # Sklearn models (SVM, XGBoost, LightGBM)
        if hasattr(model_instance, "predict_proba"):
            probs = model_instance.predict_proba(X)[0]
            prediction = int(np.argmax(probs))
            confidence = float(probs[prediction])
        else:
            # Fallback if predict_proba is not available
            pred = model_instance.predict(X)[0]
            prediction = int(pred)
            confidence = 1.0
            
    return {"prediction": prediction, "confidence": confidence}

def get_ensemble_prediction(embedding_list: list, method: str = None) -> dict:
    """
    Predict using the ensemble of active models.
    Input: embedding_list (list of floats, e.g. length 768)
    Returns:
    {
        "prediction": int (0 or 1),
        "confidence": float,
        "model_predictions": dict of {model_name: prediction_dict},
        "agreement_rate": float,
        "low_trust": bool
    }
    """
    if method is None:
        method = os.getenv("ENSEMBLE_AGGREGATION_METHOD", "median")

    # Convert list to numpy array
    embedding = np.array(embedding_list, dtype=np.float32)
    
    # Get active models
    active_models = get_active_models()
    
    if not active_models:
        raise RuntimeError("No active models available for ensemble prediction.")
        
    # Get normalized weights for active models
    weights = get_weights(active_models)
    
    model_predictions = {}
    
    for name in active_models:
        model_instance = get_model(name)
        if model_instance is None:
            continue
        try:
            res = predict_model_single(name, model_instance, embedding)
            model_predictions[name] = res
        except Exception as e:
            print(f"Error predicting with model {name}: {e}")
            
    if not model_predictions:
        raise RuntimeError("All models failed during prediction.")
        
    # Aggregation methods
    if method == "median":
        # Collect class-1 (Attack) probability for each model
        probs_class_1 = []
        for name, res in model_predictions.items():
            pred = res["prediction"]
            conf = res["confidence"]
            p1 = conf if pred == 1 else (1.0 - conf)
            probs_class_1.append(p1)
            
        median_prob_1 = float(np.median(probs_class_1))
        if median_prob_1 >= 0.5:
            ensemble_prediction = 1
            ensemble_confidence = median_prob_1
        else:
            ensemble_prediction = 0
            ensemble_confidence = 1.0 - median_prob_1

    elif method == "trimmed_mean":
        probs_class_1 = []
        for name, res in model_predictions.items():
            pred = res["prediction"]
            conf = res["confidence"]
            p1 = conf if pred == 1 else (1.0 - conf)
            probs_class_1.append(p1)
            
        sorted_probs = sorted(probs_class_1)
        beta = 0.2  # Trim 20% from both ends
        k = int(beta * len(sorted_probs))
        if k > 0 and len(sorted_probs) > 2 * k:
            trimmed_probs = sorted_probs[k:-k]
        else:
            trimmed_probs = sorted_probs
            
        mean_prob_1 = float(np.mean(trimmed_probs))
        if mean_prob_1 >= 0.5:
            ensemble_prediction = 1
            ensemble_confidence = mean_prob_1
        else:
            ensemble_prediction = 0
            ensemble_confidence = 1.0 - mean_prob_1

    else:
        # Default: weighted_average
        weighted_votes = {0: 0.0, 1: 0.0}
        for name, res in model_predictions.items():
            pred = res["prediction"]
            conf = res["confidence"]
            weight = weights.get(name, 0.25)
            weighted_votes[pred] += weight * conf
            
        ensemble_prediction = int(max(weighted_votes, key=weighted_votes.get))
        total_weight = sum(weights.get(name, 0.25) for name in model_predictions.keys())
        ensemble_confidence = weighted_votes[ensemble_prediction] / (total_weight if total_weight > 0 else 1.0)
        
    ensemble_confidence = min(1.0, max(0.0, ensemble_confidence))
    
    # Agreement rate: fraction of active models that agree with the ensemble decision
    agreeing_models = sum(1 for name, res in model_predictions.items() if res["prediction"] == ensemble_prediction)
    agreement_rate = agreeing_models / len(model_predictions)
    
    # Update model reputation dynamically with collusion detection (FoolsGold style)
    update_ensemble_reputation(model_predictions, ensemble_prediction)
    
    # Flag low trust if models disagree too much
    low_trust = agreement_rate < 0.5 or ensemble_confidence < 0.6
    
    return {
        "prediction": ensemble_prediction,
        "confidence": round(ensemble_confidence, 4),
        "model_predictions": model_predictions,
        "agreement_rate": round(agreement_rate, 4),
        "low_trust": low_trust
    }

if __name__ == "__main__":
    # Test prediction with a dummy embedding
    dummy_emb = [0.0] * 768
    try:
        res = get_ensemble_prediction(dummy_emb)
        print("Ensemble prediction output:")
        import json
        print(json.dumps(res, indent=2))
    except Exception as e:
        print(f"Test failed: {e}")
