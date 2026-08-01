import os
import json
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPUTATION_FILE = os.path.join(BASE_DIR, "ml", "models", "model_reputation.json")
REPUTATION_HISTORY_FILE = os.path.join(BASE_DIR, "ml", "models", "model_reputation_history.json")

def load_reputation_history() -> dict:
    """Load model prediction history from file."""
    if not os.path.exists(REPUTATION_HISTORY_FILE):
        return {}
    try:
        with open(REPUTATION_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading reputation history: {e}")
        return {}

def save_reputation_history(history: dict):
    """Save model prediction history to file."""
    try:
        with open(REPUTATION_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=4)
    except Exception as e:
        print(f"Error saving reputation history: {e}")

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

def update_ensemble_reputation(model_predictions: dict, ensemble_prediction: int):
    """
    Update historical metrics and weights for all models in the ensemble.
    Implements a FoolsGold-inspired collusion penalty if multiple disagreeing models
    exhibit highly similar prediction histories.
    """
    reputation = load_reputation()
    history = load_reputation_history()
    
    # Initialize history for active models
    for name in model_predictions.keys():
        if name not in history:
            history[name] = []
            
    # Append current round predictions (centered probability of predicting class 1)
    for name, res in model_predictions.items():
        pred = res["prediction"]
        conf = res["confidence"]
        p1 = conf if pred == 1 else (1.0 - conf)
        # Center around 0.5 to yield a range of [-0.5, 0.5]
        centered_prob = p1 - 0.5
        history[name].append(centered_prob)
        if len(history[name]) > 50:
            history[name] = history[name][-50:]
            
    save_reputation_history(history)
    
    # Identify agreeing vs disagreeing models
    disagreeing_models = []
    agreeing_models = []
    
    for name, res in model_predictions.items():
        if name not in reputation:
            continue
        reputation[name]["total_predictions"] += 1
        if res["prediction"] == ensemble_prediction:
            reputation[name]["agreement_count"] += 1
            agreeing_models.append(name)
        else:
            disagreeing_models.append(name)
            
        reputation[name]["agreement_rate"] = reputation[name]["agreement_count"] / reputation[name]["total_predictions"]
        reputation[name]["confidence_sum"] += res["confidence"]
        
    # Check for collusion among disagreeing models
    colluding_models = set()
    if len(disagreeing_models) > 1:
        for i in range(len(disagreeing_models)):
            m_i = disagreeing_models[i]
            hist_i = history.get(m_i, [])
            if len(hist_i) < 3:
                continue
            for j in range(i + 1, len(disagreeing_models)):
                m_j = disagreeing_models[j]
                hist_j = history.get(m_j, [])
                if len(hist_j) < 3:
                    continue
                # Calculate Cosine Similarity
                v1 = np.array(hist_i)
                v2 = np.array(hist_j)
                min_len = min(len(v1), len(v2))
                v1 = v1[-min_len:]
                v2 = v2[-min_len:]
                norm1 = np.linalg.norm(v1)
                norm2 = np.linalg.norm(v2)
                if norm1 > 0 and norm2 > 0:
                    similarity = float(np.dot(v1, v2) / (norm1 * norm2))
                    if similarity > 0.75:
                        colluding_models.add(m_i)
                        colluding_models.add(m_j)
                        
    # Apply weight adjustments
    total_penalty = 0.0
    for name in disagreeing_models:
        old_weight = reputation[name]["weight"]
        # Harsher penalty if colluding (0.05 vs 0.02)
        penalty_step = 0.05 if name in colluding_models else 0.02
        new_weight = max(0.10, old_weight - penalty_step)
        reputation[name]["weight"] = new_weight
        total_penalty += (old_weight - new_weight)
        
    # Redistribute penalty weight ONLY to agreeing models
    if total_penalty > 0 and agreeing_models:
        share = total_penalty / len(agreeing_models)
        for name in agreeing_models:
            reputation[name]["weight"] += share
            
    save_reputation(reputation)

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
