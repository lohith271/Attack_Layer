"""
private_adv_train_models.py — Combined Robust-Private Training Pipeline (DP-AT).

Implements:
1. Inner Max: Generate 7-step PGD adversarial samples on-the-fly.
2. Outer Min: Update weights via Adam with Differential Privacy (DP-SGD) using Opacus.
3. Automatically overwrites both active and backup MLP model files.
4. Triggers hash regeneration to pass integrity check.
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
from app.security.adversarial_attacks import pgd_attack
from app.security.model_integrity import generate_model_hashes

# Setup Directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")
REGISTRY_DIR = os.path.join(BASE_DIR, "model_registry")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REGISTRY_DIR, exist_ok=True)

def train_private_adversarially(
    X_train: torch.Tensor,
    y_train: torch.Tensor,
    epochs: int = 15,
    lr: float = 1e-3,
    eps_adv: float = 0.25,
    alpha_adv: float = 0.05,
    pgd_steps: int = 7,
    noise_multiplier: float = 1.0,
    max_grad_norm: float = 1.0,
    target_delta: float = 1e-5
) -> tuple:
    """
    Min-Max Adversarial Training with DP-SGD:
    - Inner loop: generate PGD adversarial examples.
    - Outer loop: optimize under DP-SGD bounds (clip + noise).
    """
    input_dim = X_train.shape[1]
    model = SimpleMLP(input_dim=input_dim)
    
    # 1. Opacus compatibility conversion (BatchNorm1d -> GroupNorm)
    model = ModuleValidator.fix(model)
    
    dataset = TensorDataset(X_train, y_train)
    loader = DataLoader(dataset, batch_size=128, shuffle=True, drop_last=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    
    # 2. Attach Privacy Engine
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
    
    print(f"Starting Combined Private Adversarial Training (DP-AT) for SimpleMLP...")
    print(f"Noise Multiplier: {noise_multiplier}, Adv Epsilon: {eps_adv}, Epochs: {epochs}")
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        
        for batch_x, batch_y in loader:
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)
            
            # Inner Max: Generate PGD adversarial batch using the model.
            # We temporarily disable Opacus hooks so that gradient calculation for the attack
            # does not interfere with differential privacy gradient sample collection.
            if hasattr(model, "disable_hooks"):
                model.disable_hooks()
                
            adv_x = pgd_attack(
                model=model,
                x=batch_x,
                y=batch_y,
                eps=eps_adv,
                alpha=alpha_adv,
                steps=pgd_steps,
                random_start=True
            )
            
            if hasattr(model, "enable_hooks"):
                model.enable_hooks()
            
            # Outer Min: Update model parameters privately on adversarial batch
            model.train()
            optimizer.zero_grad()
            logits = model(adv_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
        avg_loss = total_loss / len(loader)
        eps_spent = privacy_engine.get_epsilon(target_delta)
        if (epoch + 1) % 5 == 0 or epoch == epochs - 1:
            print(f"  Epoch [{epoch+1}/{epochs}] - Loss: {avg_loss:.4f} - Spent Epsilon: {eps_spent:.2f}")
            
    # 3. Create a clean, hook-free copy of the model structure
    clean_model = SimpleMLP(input_dim=input_dim)
    clean_model = ModuleValidator.fix(clean_model)
    
    clean_state = model._module.state_dict() if hasattr(model, "_module") else model.state_dict()
    clean_model.load_state_dict(clean_state)
    
    final_eps = privacy_engine.get_epsilon(target_delta)
    
    return clean_model, final_eps

def main():
    print("--- Starting Combined DP-AT Training for SimpleMLP ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.LongTensor(y_train)
    
    # Train robust and private model with 50 epochs for proper convergence
    model_dp_at, epsilon = train_private_adversarially(
        X_train_t, y_train_t,
        epochs=50,
        noise_multiplier=1.0,
        max_grad_norm=1.0,
        eps_adv=0.25
    )
    
    # Paths to overwrite
    mlp_models_path = os.path.join(MODELS_DIR, "mlp.pth")
    mlp_registry_path = os.path.join(REGISTRY_DIR, "mlp.pth")
    
    # Save to active model path as state_dict
    torch.save(model_dp_at.state_dict(), mlp_models_path)
    print(f"Saved active combined MLP model state_dict to {mlp_models_path}")
    
    # Save to backup model registry path as state_dict
    torch.save(model_dp_at.state_dict(), mlp_registry_path)
    print(f"Saved backup combined MLP model state_dict to {mlp_registry_path}")
    
    print("Regenerating SHA-256 integrity hashes...")
    generate_model_hashes()
    print(f"Model update complete. Epsilon spent: {epsilon:.2f}")

if __name__ == "__main__":
    main()
