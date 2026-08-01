import os
import joblib
import numpy as np
from sklearn.ensemble import AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data
from app.security.dataset_guard import train_guard, filter_dataset

def main():
    print("--- Training AdaBoost (Hardened) ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    # 1. Dataset poisoning defense: fit guard and filter training outliers
    print("Sanitizing training dataset...")
    train_guard(X_train, contamination=0.02)
    X_train_clean, y_train_clean = filter_dataset(X_train, y_train)
    print(f"Filtered out {X_train.shape[0] - X_train_clean.shape[0]} outlier samples.")
    
    # 2. Augment training data with adversarial Gaussian noise to smooth boundary
    np.random.seed(42)
    noise = np.random.normal(0, 0.03, X_train_clean.shape)
    X_train_aug = np.vstack([X_train_clean, X_train_clean + noise])
    y_train_aug = np.hstack([y_train_clean, y_train_clean])
    
    print("Fitting AdaBoostClassifier directly...")
    base_estimator = DecisionTreeClassifier(max_depth=2, random_state=42)
    best_adaboost = AdaBoostClassifier(
        estimator=base_estimator,
        n_estimators=30,
        learning_rate=0.1,
        random_state=42
    )
    best_adaboost.fit(X_train_aug, y_train_aug)
    
    print("Calibrating classifier...")
    model = CalibratedClassifierCV(estimator=best_adaboost, cv=3)
    model.fit(X_train_aug, y_train_aug)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "adaboost.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
