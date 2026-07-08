import numpy as np
import torch
from app.ml.model_manager import get_model, get_active_models
from app.ml.model_reputation import get_weights, update_reputation

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

def get_ensemble_prediction(embedding_list: list) -> dict:
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
    # Convert list to numpy array
    embedding = np.array(embedding_list, dtype=np.float32)
    
    # Get active models
    active_models = get_active_models()
    
    if not active_models:
        raise RuntimeError("No active models available for ensemble prediction.")
        
    # Get normalized weights for active models
    weights = get_weights(active_models)
    
    model_predictions = {}
    weighted_votes = {0: 0.0, 1: 0.0}
    
    for name in active_models:
        model_instance = get_model(name)
        if model_instance is None:
            continue
        try:
            res = predict_model_single(name, model_instance, embedding)
            model_predictions[name] = res
            
            # Aggregate weighted votes
            pred = res["prediction"]
            conf = res["confidence"]
            weight = weights.get(name, 0.25)
            
            weighted_votes[pred] += weight * conf
        except Exception as e:
            print(f"Error predicting with model {name}: {e}")
            
    if not model_predictions:
        raise RuntimeError("All models failed during prediction.")
        
    # Determine ensemble decision
    ensemble_prediction = int(max(weighted_votes, key=weighted_votes.get))
    
    # Calculate confidence aggregation (average confidence of models that voted for the majority class,
    # or general weighted confidence)
    # Let's use the sum of weighted confidences for the chosen class normalized by sum of weights of voting models
    total_weight = sum(weights.get(name, 0.25) for name in model_predictions.keys())
    ensemble_confidence = weighted_votes[ensemble_prediction] / (total_weight if total_weight > 0 else 1.0)
    ensemble_confidence = min(1.0, max(0.0, ensemble_confidence))
    
    # Agreement rate: fraction of active models that agree with the ensemble decision
    agreeing_models = 0
    for name, res in model_predictions.items():
        is_agree = (res["prediction"] == ensemble_prediction)
        agreeing_models += 1 if is_agree else 0
        
        # Update model reputation dynamically based on agreement
        update_reputation(name, agreed=is_agree, confidence=res["confidence"])
        
    agreement_rate = agreeing_models / len(model_predictions)
    
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
