import os
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

def main():
    print("--- Training Logistic Regression (Hardened) ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    # Augment training data with adversarial Gaussian noise to smooth boundary
    np.random.seed(42)
    noise = np.random.normal(0, 0.03, X_train.shape)
    X_train_aug = np.vstack([X_train, X_train + noise])
    y_train_aug = np.hstack([y_train, y_train])
    
    print("Fitting LogisticRegression directly...")
    best_lr = LogisticRegression(
        class_weight='balanced',
        C=0.5,
        penalty='l2',
        solver='lbfgs',
        random_state=42,
        max_iter=1000
    )
    best_lr.fit(X_train_aug, y_train_aug)
    
    print("Calibrating classifier...")
    model = CalibratedClassifierCV(estimator=best_lr, cv=5)
    model.fit(X_train_aug, y_train_aug)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "logistic_regression.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
