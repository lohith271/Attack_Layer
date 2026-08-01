import os
import shutil
import importlib
from app.security.model_integrity import generate_model_hashes

def run_script(module_name: str):
    print(f"\n=========================================")
    print(f"Running training: {module_name}")
    print(f"=========================================")
    try:
        module = importlib.import_module(module_name)
        if hasattr(module, "main"):
            module.main()
        else:
            print(f"Error: {module_name} has no main() function.")
    except Exception as e:
        print(f"Error executing {module_name}: {e}")

def main():
    print("--- STARTING ORCHESTRATED MULTI-MODEL TRAINING ---")
    
    # 1. Train all 10 models
    training_scripts = [
        "app.ml.train.train_svm",
        "app.ml.train.train_one_class_svm",
        "app.ml.train.train_xgboost",
        "app.ml.train.train_lightgbm",
        "app.ml.train.train_mlp",
        "app.ml.train.train_random_forest",
        "app.ml.train.train_logistic_regression",
        "app.ml.train.train_transformer",
        "app.ml.train.train_cnn",
        "app.ml.train.train_adaboost"
    ]
    
    for script in training_scripts:
        run_script(script)
        
    # 2. Copy trained models to backup registry
    print("\n--- COPYING MODELS TO BACKUP REGISTRY ---")
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    models_dir = os.path.join(base_dir, "ml", "models")
    registry_dir = os.path.join(base_dir, "model_registry")
    os.makedirs(registry_dir, exist_ok=True)
    
    model_files = [
        "svm.pkl", "one_class_svm.pkl", "xgboost.pkl", "lightgbm.pkl", "mlp.pth", "mlp.pt", 
        "random_forest.pkl", "logistic_regression.pkl",
        "transformer_emb.pth", "cnn_1d.pth", "adaboost.pkl"
    ]
    
    for filename in model_files:
        src = os.path.join(models_dir, filename)
        if os.path.exists(src):
            dst = os.path.join(registry_dir, filename)
            shutil.copy2(src, dst)
            print(f"Copied {filename} to registry backup.")
            
    # 3. Generate SHA-256 integrity hashes for all models
    print("\n--- GENERATING MODEL INTEGRITY HASHES ---")
    generate_model_hashes()
    
    print("\n--- ALL MODELS TRAINED, REGISTERED AND SECURED ---")

if __name__ == "__main__":
    main()
