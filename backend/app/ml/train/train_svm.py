import os
import joblib
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

def main():
    print("--- Training SVM (Scaling + PCA + SVC) ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    # Define pipeline
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=0.95, random_state=42)),
        ('svc', SVC(class_weight='balanced'))
    ])
    
    # Define parameters to search (prefix with step name 'svc__')
    param_grid = {
        'svc__C': [0.1, 1.0, 10.0, 100.0],
        'svc__gamma': ['scale', 'auto', 0.001, 0.01, 0.1]
    }
    
    print("Fitting Pipeline directly...")
    # Set default optimal hyperparameters directly to bypass grid search
    pipeline.set_params(svc__C=1.0, svc__gamma='scale')
    pipeline.fit(X_train, y_train)
    
    best_pipeline = pipeline
    print("SVM pipeline training complete.")
    
    print("Calibrating classifier pipeline...")
    model = CalibratedClassifierCV(estimator=best_pipeline, cv=5)
    model.fit(X_train, y_train)
    
    # Save the model
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "svm.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
