"""
adv_train_models.py — Adversarial Training Pipeline for AttackLayer Neural Models.

Implements Madry Min-Max Adversarial Training (ICLR 2018) for SimpleMLP and cnn_1d models.
Injects 7-step PGD adversarial samples on-the-fly during training and saves trained robust model weights:
- app/ml/models/mlp_robust.pth
- app/ml/models/cnn_1d_robust.pth
"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader

from app.ml.utils import load_split_data
from app.ml.model_manager import SimpleMLP, CNN1DClassifier
from app.security.adversarial_attacks import pgd_attack

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")
os.makedirs(MODELS_DIR, exist_ok=True)

def train_adversarially(
    model: nn.Module,
    X_train: torch.Tensor,
    y_train: torch.Tensor,
    epochs: int = 10,
    lr: float = 1e-3,
    eps: float = 0.25,
    alpha: float = 0.05,
    pgd_steps: int = 7
) -> nn.Module:
    """
    Min-Max Adversarial Training Loop:
    - Inner Max: Generate 7-step PGD adversarial samples for the current batch
    - Outer Min: Compute loss on adversarial samples and update weights via Adam
    """
    dataset = TensorDataset(X_train, y_train)
    loader = DataLoader(dataset, batch_size=128, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    
    print(f"Starting Adversarial Training for {model.__class__.__name__} ({epochs} epochs, eps={eps})...")
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        
        for batch_x, batch_y in loader:
            # Inner Max: Generate PGD adversarial batch
            adv_x = pgd_attack(
                model=model,
                x=batch_x,
                y=batch_y,
                eps=eps,
                alpha=alpha,
                steps=pgd_steps,
                random_start=True
            )
            
            # Outer Min: Train model weights to classify adversarial batch correctly
            model.train()
            optimizer.zero_grad()
            logits = model(adv_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
        avg_loss = total_loss / len(loader)
        if (epoch + 1) % 2 == 0 or epoch == epochs - 1:
            print(f"  Epoch [{epoch+1}/{epochs}] - Loss: {avg_loss:.4f}")
            
    return model

def main():
    print("--- Starting Adversarial Training for AttackLayer Neural Models ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.LongTensor(y_train)
    
    input_dim = X_train.shape[1]
    
    # 1. Train Robust SimpleMLP
    mlp = SimpleMLP(input_dim=input_dim)
    mlp_robust = train_adversarially(mlp, X_train_t, y_train_t, epochs=8, eps=0.25)
    mlp_save_path = os.path.join(MODELS_DIR, "mlp_robust.pth")
    torch.save(mlp_robust, mlp_save_path)
    print(f"Saved robust MLP model weights to {mlp_save_path}")
    
    # 2. Train Robust CNN1D
    cnn = CNN1DClassifier(input_dim=input_dim)
    cnn_robust = train_adversarially(cnn, X_train_t, y_train_t, epochs=8, eps=0.25)
    cnn_save_path = os.path.join(MODELS_DIR, "cnn_1d_robust.pth")
    torch.save(cnn_robust, cnn_save_path)
    print(f"Saved robust CNN1D model weights to {cnn_save_path}")

if __name__ == "__main__":
    main()
