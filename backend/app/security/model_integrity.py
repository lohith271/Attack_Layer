import os
import hashlib
import json

# Define the paths to the model files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")
HASHES_FILE = os.path.join(MODELS_DIR, "model_hashes.json")

MODEL_FILES = {
    "svm": "svm.pkl",
    "xgboost": "xgboost.pkl",
    "lightgbm": "lightgbm.pkl",
    "mlp": "mlp.pth",
    "random_forest": "random_forest.pkl",
    "logistic_regression": "logistic_regression.pkl",
    "transformer_emb": "transformer_emb.pth",
    "cnn_1d": "cnn_1d.pth",
    "adaboost": "adaboost.pkl"
}

def calculate_sha256(file_path: str) -> str:
    """Calculate the SHA256 checksum of a file."""
    if not os.path.exists(file_path):
        return ""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_model_hashes() -> dict:
    """Generate SHA256 hashes for all existing model files and save to model_hashes.json."""
    hashes = {}
    os.makedirs(MODELS_DIR, exist_ok=True)
    for model_name, filename in MODEL_FILES.items():
        file_path = os.path.join(MODELS_DIR, filename)
        if os.path.exists(file_path):
            file_hash = calculate_sha256(file_path)
            hashes[model_name] = file_hash
            print(f"Generated hash for {model_name} ({filename}): {file_hash}")
        else:
            # Try mlp.pt if mlp.pth is missing
            if model_name == "mlp":
                alt_path = os.path.join(MODELS_DIR, "mlp.pt")
                if os.path.exists(alt_path):
                    file_hash = calculate_sha256(alt_path)
                    hashes[model_name] = file_hash
                    print(f"Generated hash for mlp (mlp.pt): {file_hash}")
                    continue
            print(f"Warning: Model file not found for {model_name} at {file_path}")
    
    with open(HASHES_FILE, "w") as f:
        json.dump(hashes, f, indent=4)
    print(f"Saved model hashes to {HASHES_FILE}")
    return hashes

def verify_model(model_name: str) -> bool:
    """
    Verify the hash of a specific model file against model_hashes.json.
    Returns True if valid, False if mismatched, missing, or compromised.
    """
    if not os.path.exists(HASHES_FILE):
        print(f"Error: Hashes file {HASHES_FILE} does not exist. Generating initial hashes...")
        generate_model_hashes()
        if not os.path.exists(HASHES_FILE):
            return False
            
    try:
        with open(HASHES_FILE, "r") as f:
            stored_hashes = json.load(f)
    except Exception as e:
        print(f"Error reading hashes file: {e}")
        return False
        
    stored_hash = stored_hashes.get(model_name)
    if not stored_hash:
        print(f"Warning: No stored hash found for model {model_name}")
        return False
        
    filename = MODEL_FILES.get(model_name)
    if not filename:
        return False
        
    file_path = os.path.join(MODELS_DIR, filename)
    if not os.path.exists(file_path) and model_name == "mlp":
        file_path = os.path.join(MODELS_DIR, "mlp.pt")
        
    current_hash = calculate_sha256(file_path)
    if current_hash == "":
        print(f"Error: Model file {filename} not found.")
        return False
        
    if current_hash != stored_hash:
        print(f"CRITICAL WARNING: Model {model_name} hash mismatch!")
        print(f"Expected: {stored_hash}")
        print(f"Got:      {current_hash}")
        return False
        
    return True

def get_compromised_models() -> list:
    """Return a list of models that fail hash verification."""
    compromised = []
    for model_name in MODEL_FILES.keys():
        if not verify_model(model_name):
            compromised.append(model_name)
    return compromised

if __name__ == "__main__":
    generate_model_hashes()
