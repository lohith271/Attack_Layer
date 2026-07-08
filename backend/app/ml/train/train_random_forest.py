import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

def main():
    print("--- Training Random Forest ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 6, 10],
        'min_samples_split': [2, 5]
    }
    
    print("Performing grid search...")
    grid = GridSearchCV(
        RandomForestClassifier(class_weight='balanced', random_state=42, n_jobs=-1),
        param_grid,
        cv=5,
        scoring='f1'
    )
    grid.fit(X_train, y_train)
    
    best_rf = grid.best_estimator_
    print(f"Best parameters found: {grid.best_params_}")
    
    print("Calibrating classifier...")
    model = CalibratedClassifierCV(estimator=best_rf, cv=5)
    model.fit(X_train, y_train)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "random_forest.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
