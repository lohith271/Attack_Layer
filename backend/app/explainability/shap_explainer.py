import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import shap
from app.ml.model_manager import get_model

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIGURES_DIR = os.path.join(BASE_DIR, "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

def generate_shap_explanation(X_sample: np.ndarray, model_name: str) -> dict:
    """
    Calculate SHAP values for a single sample using TreeExplainer
    (supported for xgboost and lightgbm).
    """
    model = get_model(model_name)
    if model is None:
        return {"error": f"Model {model_name} not available"}
        
    # Since sklearn CalibratedClassifierCV wraps the underlying estimator,
    # we need to get the base estimator for TreeExplainer.
    if hasattr(model, "estimator"):
        base_estimator = model.estimator
    else:
        base_estimator = model
        
    try:
        # Create TreeExplainer for base model
        explainer = shap.TreeExplainer(base_estimator)
        
        # Ensure 2D input
        if len(X_sample.shape) == 1:
            X_sample = X_sample.reshape(1, -1)
            
        shap_values = explainer.shap_values(X_sample)
        
        # For binary classification, shap_values can be a list [class0_values, class1_values]
        # or a 3D numpy array (samples, features, classes), or a 2D array.
        if isinstance(shap_values, list):
            # Take values for class 1 (attack)
            shap_val = shap_values[1]
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            shap_val = shap_values[:, :, 1]
        else:
            shap_val = shap_values
            
        # Extract top feature indices and values
        # Since it's a single sample, shap_val shape is (1, 768)
        feature_vals = shap_val[0]
        top_indices = np.argsort(np.abs(feature_vals))[::-1][:10]
        
        top_features = []
        for idx in top_indices:
            top_features.append({
                "feature_index": int(idx),
                "shap_value": float(feature_vals[idx]),
                "raw_value": float(X_sample[0, idx])
            })
            
        return {
            "model_name": model_name,
            "top_features": top_features,
            "base_value": float(explainer.expected_value) if hasattr(explainer, "expected_value") else 0.0
        }
    except Exception as e:
        print(f"Error computing SHAP values for {model_name}: {e}")
        return {"error": str(e)}

def save_shap_summary_plot(X_test: np.ndarray, model_name: str, max_display: int = 15):
    """
    Generate and save a SHAP summary plot for a batch of test samples.
    Saves to figures/shap_summary_{model_name}.png.
    """
    model = get_model(model_name)
    if model is None:
        print(f"SHAP Plot Error: Model {model_name} not available")
        return
        
    if hasattr(model, "estimator"):
        base_estimator = model.estimator
    else:
        base_estimator = model
        
    try:
        explainer = shap.TreeExplainer(base_estimator)
        shap_values = explainer.shap_values(X_test)
        
        if isinstance(shap_values, list):
            shap_val = shap_values[1]
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            shap_val = shap_values[:, :, 1]
        else:
            shap_val = shap_values
            
        # Create plot
        plt.figure(figsize=(10, 6))
        feature_names = [f"Embedding_Dim_{i}" for i in range(X_test.shape[1])]
        
        shap.summary_plot(
            shap_val, 
            X_test, 
            feature_names=feature_names, 
            max_display=max_display, 
            show=False
        )
        
        plot_path = os.path.join(FIGURES_DIR, f"shap_summary_{model_name}.png")
        plt.title(f"SHAP Feature Importance Summary - {model_name.upper()}")
        plt.tight_layout()
        plt.savefig(plot_path, dpi=150)
        plt.close()
        print(f"Saved SHAP summary plot to {plot_path}")
    except Exception as e:
        print(f"Error generating SHAP plot for {model_name}: {e}")

if __name__ == "__main__":
    # Quick test with a dummy sample
    dummy_sample = np.random.normal(size=(1, 768))
    # Test on xgboost if loaded
    res = generate_shap_explanation(dummy_sample, "xgboost")
    print("SHAP explanation result (first 3 features):")
    if "top_features" in res:
        print(res["top_features"][:3])
    else:
        print(res)
