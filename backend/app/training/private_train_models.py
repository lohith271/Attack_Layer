"""
private_train_models.py — Private Training Pipeline for AttackLayer Neural Models.

Implements Differentially Private SGD (DP-SGD) training using Opacus for the SimpleMLP model.
Saves the trained private model weights:
- app/ml/models/mlp_private.pth
"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
from opacus import PrivacyEngine
from opacus.validators import ModuleValidator

from app.ml.utils import load_split_data
from app.ml.model_manager import SimpleMLP

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")
os.makedirs(MODELS_DIR, exist_ok=True)

def train_private(
    X_train: torch.Tensor,
    y_train: torch.Tensor,
    epochs: int = 15,
    lr: float = 1e-3,
    noise_multiplier: float = 1.0,
    max_grad_norm: float = 1.0,
    target_delta: float = 1e-5
) -> tuple:
    """
    Trains SimpleMLP with DP-SGD using Opacus.
    
    Returns:
        (clean_trained_model, final_epsilon)
    """
    # 1. Instantiate the model
    input_dim = X_train.shape[1]
    model = SimpleMLP(input_dim=input_dim)
    
    # 2. Fix incompatible layers (Opacus does not support BatchNorm, converts it to GroupNorm)
    model = ModuleValidator.fix(model)
    
    # 3. Create Dataset and DataLoader
    dataset = TensorDataset(X_train, y_train)
    # Note: Opacus works best with physical batch sizes
    loader = DataLoader(dataset, batch_size=128, shuffle=True, drop_last=True)
    
    # 4. Define optimizer
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    
    # 5. Attach PrivacyEngine
    privacy_engine = PrivacyEngine()
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = model.to(device)
    
    model, optimizer, loader = privacy_engine.make_private(
        module=model,
        optimizer=optimizer,
        data_loader=loader,
        noise_multiplier=noise_multiplier,
        max_grad_norm=max_grad_norm,
    )
    
    criterion = nn.CrossEntropyLoss()
    
    print(f"Starting Private Training (DP-SGD) for SimpleMLP...")
    print(f"Noise Multiplier: {noise_multiplier}, Max Grad Norm: {max_grad_norm}, Epochs: {epochs}")
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        
        for batch_x, batch_y in loader:
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)
            
            optimizer.zero_grad()
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
        avg_loss = total_loss / len(loader)
        eps = privacy_engine.get_epsilon(target_delta)
        if (epoch + 1) % 5 == 0 or epoch == epochs - 1:
            print(f"  Epoch [{epoch+1}/{epochs}] - Loss: {avg_loss:.4f} - Spent Epsilon: {eps:.2f}")
            
    # 6. Extract clean trained model (remove Opacus hooks and wraps)
    clean_model = SimpleMLP(input_dim=input_dim)
    clean_model = ModuleValidator.fix(clean_model)
    
    # Load state dict from the private model's underlying module
    clean_state = model._module.state_dict() if hasattr(model, "_module") else model.state_dict()
    clean_model.load_state_dict(clean_state)
    
    final_eps = privacy_engine.get_epsilon(target_delta)
    
    return clean_model, final_eps

def main():
    print("--- Starting Private Model Training for AttackLayer ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.LongTensor(y_train)
    
    model_private, epsilon = train_private(
        X_train_t, y_train_t, 
        epochs=15, 
        noise_multiplier=1.0, 
        max_grad_norm=1.0
    )
    
    mlp_save_path = os.path.join(MODELS_DIR, "mlp_private.pth")
    torch.save(model_private, mlp_save_path)
    print(f"Saved private MLP model to {mlp_save_path}")
    print(f"Privacy guarantee achieved: epsilon={epsilon:.2f} at delta=1e-5")

if __name__ == "__main__":
    main()
