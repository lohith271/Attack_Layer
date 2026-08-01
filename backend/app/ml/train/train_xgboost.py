import os
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

def main():
    print("--- Training XGBoost (Hardened) ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    # Augment training data with adversarial Gaussian noise to smooth boundary
    np.random.seed(42)
    noise = np.random.normal(0, 0.03, X_train.shape)
    X_train_aug = np.vstack([X_train, X_train + noise])
    y_train_aug = np.hstack([y_train, y_train])
    
    # Calculate scale_pos_weight for class imbalance
    num_neg = (y_train_aug == 0).sum()
    num_pos = (y_train_aug == 1).sum()
    scale_pos_weight = num_neg / num_pos
    
    print("Fitting XGBClassifier directly...")
    # Train directly with robust default parameters
    best_xgb = XGBClassifier(
        scale_pos_weight=scale_pos_weight,
        min_child_weight=3,
        learning_rate=0.1,
        max_depth=4,
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        tree_method='hist',
        device='cpu'
    )
    best_xgb.fit(X_train_aug, y_train_aug)
    
    print("Calibrating classifier...")
    model = CalibratedClassifierCV(estimator=best_xgb, cv=5)
    model.fit(X_train_aug, y_train_aug)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "xgboost.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
