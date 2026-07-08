import os
import joblib
from sklearn.ensemble import AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

def main():
    print("--- Training AdaBoost ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    param_grid = {
        'n_estimators': [50, 100, 200],
        'learning_rate': [0.01, 0.1, 1.0]
    }
    
    print("Performing grid search...")
    # Base estimator is a decision tree with max_depth=1 (decision stump) or 2
    base_estimator = DecisionTreeClassifier(max_depth=2, random_state=42)
    grid = GridSearchCV(
        AdaBoostClassifier(estimator=base_estimator, random_state=42),
        param_grid,
        cv=5,
        scoring='f1'
    )
    grid.fit(X_train, y_train)
    
    best_adaboost = grid.best_estimator_
    print(f"Best parameters found: {grid.best_params_}")
    
    print("Calibrating classifier...")
    model = CalibratedClassifierCV(estimator=best_adaboost, cv=5)
    model.fit(X_train, y_train)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "adaboost.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
