import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPUTATION_FILE = os.path.join(BASE_DIR, "ml", "models", "model_reputation.json")

DEFAULT_REPUTATION = {
    "svm": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "xgboost": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "lightgbm": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "mlp": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "random_forest": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "logistic_regression": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "transformer_emb": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "cnn_1d": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    },
    "adaboost": {
        "weight": 0.1111,
        "agreement_rate": 1.0,
        "total_predictions": 0,
        "agreement_count": 0,
        "confidence_sum": 0.0,
        "historical_accuracy": 1.0
    }
}

def load_reputation() -> dict:
    """Load model reputation data from file."""
    if not os.path.exists(REPUTATION_FILE):
        os.makedirs(os.path.dirname(REPUTATION_FILE), exist_ok=True)
        save_reputation(DEFAULT_REPUTATION)
        return DEFAULT_REPUTATION
    try:
        with open(REPUTATION_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading reputation: {e}. Resetting to defaults.")
        return DEFAULT_REPUTATION

def save_reputation(data: dict):
    """Save model reputation data to file."""
    try:
        with open(REPUTATION_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving reputation file: {e}")

def get_weights(active_models: list = None) -> dict:
    """
    Get dynamic weights normalized for active models.
    If some models are disabled, their weights are redistributed.
    """
    reputation = load_reputation()
    if active_models is None:
        active_models = list(reputation.keys())
        
    weights = {k: reputation[k]["weight"] for k in active_models if k in reputation}
    
    # If no active models, return default equal weights for whatever is active
    if not weights:
        return {k: 1.0 / len(active_models) for k in active_models}
        
    total = sum(weights.values())
    if total > 0:
        return {k: v / total for k, v in weights.items()}
    else:
        return {k: 1.0 / len(active_models) for k in active_models}

def update_reputation(model_name: str, agreed: bool, confidence: float, actual_correct: bool = None):
    """
    Update historical metrics for a model.
    If the model disagreed with the ensemble majority, reduce its weight.
    """
    reputation = load_reputation()
    if model_name not in reputation:
        return
        
    m = reputation[model_name]
    m["total_predictions"] += 1
    if agreed:
        m["agreement_count"] += 1
    m["agreement_rate"] = m["agreement_count"] / m["total_predictions"]
    m["confidence_sum"] += confidence
    
    # Dynamic Weight Reduction Logic:
    # If the model disagrees with the ensemble majority:
    if not agreed:
        # Reduce weight by a step
        old_weight = m["weight"]
        new_weight = max(0.10, old_weight - 0.02) # step size 0.02, floor of 0.10
        m["weight"] = new_weight
        
        # Redistribute the penalty to other models
        diff = old_weight - new_weight
        other_models = [k for k in reputation.keys() if k != model_name]
        for other in other_models:
            reputation[other]["weight"] += diff / len(other_models)
            
    # Save the updated metrics
    save_reputation(reputation)

def reset_reputation():
    """Reset reputation to defaults."""
    save_reputation(DEFAULT_REPUTATION)
