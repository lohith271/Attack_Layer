import os
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

def main():
    print("--- Training Logistic Regression ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    param_grid = {
        'C': [0.01, 0.1, 1.0, 10.0, 100.0],
        'penalty': ['l2'],
        'solver': ['lbfgs']
    }
    
    print("Performing grid search...")
    grid = GridSearchCV(
        LogisticRegression(class_weight='balanced', random_state=42, max_iter=1000),
        param_grid,
        cv=5,
        scoring='f1'
    )
    grid.fit(X_train, y_train)
    
    best_lr = grid.best_estimator_
    print(f"Best parameters found: {grid.best_params_}")
    
    print("Calibrating classifier...")
    model = CalibratedClassifierCV(estimator=best_lr, cv=5)
    model.fit(X_train, y_train)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "logistic_regression.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
