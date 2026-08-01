import os
import joblib
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from app.ml.utils import load_split_data

def main():
    print("--- Training One-Class SVM (OOD / Anomaly Detector) ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    # One-Class SVM is trained ONLY on benign prompts (class 0)
    X_train_benign = X_train[y_train == 0]
    print(f"Training on {X_train_benign.shape[0]} benign samples...")
    
    # Build pipeline: Scale -> PCA -> OneClassSVM
    # nu represents the fraction of training samples expected to be anomalous (default 5%)
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=0.95, random_state=42)),
        ('oc_svm', OneClassSVM(kernel='rbf', gamma='scale', nu=0.05))
    ])
    
    model.fit(X_train_benign)
    
    # Evaluate basic OOD performance on val sets
    val_benign = X_val[y_val == 0]
    val_attack = X_val[y_val == 1]
    
    preds_benign = model.predict(val_benign)
    preds_attack = model.predict(val_attack)
    
    # 1 is normal/in-distribution, -1 is anomaly/OOD
    fn_rate = np.mean(preds_benign == -1)
    tn_rate = np.mean(preds_attack == -1)
    
    print(f"Validation performance:")
    print(f"  False Positive Rate (Benign flagged as anomaly): {fn_rate:.4f}")
    print(f"  True Positive Rate (Attack flagged as anomaly):  {tn_rate:.4f}")
    
    # Save the model
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "one_class_svm.pkl")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()
