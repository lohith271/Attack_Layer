"""
simulate_privacy.py — Auditing and Hardening AttackLayer Classifiers against Privacy Leakage.

Runs:
1. Standard training of SimpleMLP.
2. Private (DP-SGD) training of SimpleMLP using Opacus.
3. Membership Inference Attack (MIA) evaluation on both models.
4. Generates comparative visual reports (MIA ROC curves and Loss Histograms).
"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc
from opacus.validators import ModuleValidator

# Import local project modules
from app.ml.utils import load_split_data
from app.ml.model_manager import SimpleMLP
from app.security.privacy_guard import evaluate_mia, compute_per_sample_losses
from app.training.private_train_models import train_private

# Setup folders
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIGURES_DIR = os.path.join(BASE_DIR, "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

# Set styling
sns.set_theme(style="whitegrid")
plt.rcParams.update({'font.size': 10, 'figure.titlesize': 12})

def train_standard(
    X_train: torch.Tensor,
    y_train: torch.Tensor,
    epochs: int = 15,
    lr: float = 1e-3
) -> nn.Module:
    """Trains a standard SimpleMLP model (without differential privacy)."""
    input_dim = X_train.shape[1]
    model = SimpleMLP(input_dim=input_dim)
    
    # We apply the same GroupNorm conversion as the DP model to ensure architecture control
    model = ModuleValidator.fix(model)
    
    dataset = TensorDataset(X_train, y_train)
    loader = DataLoader(dataset, batch_size=128, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = model.to(device)
    
    print("\n--- Training Standard Model (Undefended) ---")
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
        if (epoch + 1) % 5 == 0 or epoch == epochs - 1:
            print(f"  Epoch [{epoch+1}/{epochs}] - Loss: {avg_loss:.4f}")
            
    return model

def compute_accuracy(model, dataset, device=None):
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    model.eval()
    loader = DataLoader(dataset, batch_size=256, shuffle=False)
    correct = 0
    total = 0
    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            preds = model(x).argmax(dim=1)
            correct += (preds == y).sum().item()
            total += y.size(0)
    return correct / total

def plot_loss_distributions(std_mia, dp_mia):
    """Generates and saves a comparative histogram of seen vs unseen losses."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharey=False)
    
    # 1. Standard Model Histogram
    axes[0].hist(std_mia["train_losses"], bins=30, alpha=0.6, label="Members (Train)", color="#0ca8a0")
    axes[0].hist(std_mia["test_losses"], bins=30, alpha=0.6, label="Non-Members (Test)", color="#d64f6a")
    axes[0].set_title(f"Standard Model (Undefended)\nMIA AUC: {std_mia['mia_auc']:.3f}")
    axes[0].set_xlabel("Per-sample Cross-Entropy Loss")
    axes[0].set_ylabel("Sample Count")
    axes[0].legend()
    
    # 2. DP Model Histogram
    axes[1].hist(dp_mia["train_losses"], bins=30, alpha=0.6, label="Members (Train)", color="#0ca8a0")
    axes[1].hist(dp_mia["test_losses"], bins=30, alpha=0.6, label="Non-Members (Test)", color="#d64f6a")
    axes[1].set_title(f"DP-SGD Model (Private)\nMIA AUC: {dp_mia['mia_auc']:.3f}")
    axes[1].set_xlabel("Per-sample Cross-Entropy Loss")
    axes[1].legend()
    
    plt.suptitle("Privacy Leak Audit: Seen vs. Unseen Data Loss Distributions")
    plt.tight_layout()
    plot_path = os.path.join(FIGURES_DIR, "mia_loss_histogram.png")
    plt.savefig(plot_path, dpi=300)
    plt.close()
    print(f"Saved loss distribution comparison to: {plot_path}")

def plot_roc_curves(std_mia, dp_mia):
    """Generates and saves comparative ROC curves for the MIA attack."""
    # Standard Model ROC
    std_train = np.array(std_mia["train_losses"])
    std_test = np.array(std_mia["test_losses"])
    std_y_true = np.concatenate([np.ones_like(std_train), np.zeros_like(std_test)])
    std_y_score = -np.concatenate([std_train, std_test])
    std_fpr, std_tpr, _ = roc_curve(std_y_true, std_y_score)
    std_auc = auc(std_fpr, std_tpr)
    
    # DP Model ROC
    dp_train = np.array(dp_mia["train_losses"])
    dp_test = np.array(dp_mia["test_losses"])
    dp_y_true = np.concatenate([np.ones_like(dp_train), np.zeros_like(dp_test)])
    dp_y_score = -np.concatenate([dp_train, dp_test])
    dp_fpr, dp_tpr, _ = roc_curve(dp_y_true, dp_y_score)
    dp_auc = auc(dp_fpr, dp_tpr)
    
    plt.figure(figsize=(7, 6))
    plt.plot(std_fpr, std_tpr, color="#d64f6a", lw=2, label=f"Standard Model MIA (AUC = {std_auc:.3f})")
    plt.plot(dp_fpr, dp_tpr, color="#0ca8a0", lw=2, label=f"DP-SGD Model MIA (AUC = {dp_auc:.3f})")
    plt.plot([0, 1], [0, 1], color="#77839a", lw=1.5, linestyle="--", label="Random Guess (AUC = 0.50)")
    
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Membership Inference Attack (MIA) ROC Curves")
    plt.legend(loc="lower right")
    plt.tight_layout()
    
    plot_path = os.path.join(FIGURES_DIR, "mia_roc_curves.png")
    plt.savefig(plot_path, dpi=300)
    plt.close()
    print(f"Saved ROC curve comparison to: {plot_path}")

def main():
    print("=================================================================")
    print("      AttackLayer: Privacy Leakage Audit and Defense Simulation  ")
    print("=================================================================")
    
    # 1. Load Data
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.LongTensor(y_train)
    X_test_t = torch.FloatTensor(X_test)
    y_test_t = torch.LongTensor(y_test)
    
    train_dataset = TensorDataset(X_train_t, y_train_t)
    test_dataset = TensorDataset(X_test_t, y_test_t)
    
    # 2. Train Standard Model
    std_model = train_standard(X_train_t, y_train_t, epochs=15)
    std_acc = compute_accuracy(std_model, test_dataset)
    print(f"Standard Model Test Accuracy: {std_acc*100:.2f}%")
    
    # 3. Train DP Model
    dp_model, epsilon = train_private(
        X_train_t, y_train_t,
        epochs=15,
        noise_multiplier=1.0,
        max_grad_norm=1.0
    )
    dp_acc = compute_accuracy(dp_model, test_dataset)
    print(f"DP-SGD Model Test Accuracy: {dp_acc*100:.2f}%")
    
    # 4. Evaluate Membership Inference Attacks
    print("\n--- Simulating Membership Inference Attacks (MIA) ---")
    std_mia = evaluate_mia(std_model, train_dataset, test_dataset)
    dp_mia = evaluate_mia(dp_model, train_dataset, test_dataset)
    
    # Formatted values for clean printing (avoids f-string backslash limitations)
    std_acc_str = f"{std_acc*100:.2f}%"
    dp_acc_str = f"{dp_acc*100:.2f}%"
    std_auc_str = f"{std_mia['mia_auc']:.3f}"
    dp_auc_str = f"{dp_mia['mia_auc']:.3f}"
    std_mia_acc_str = f"{std_mia['attack_accuracy']*100:.2f}%"
    dp_mia_acc_str = f"{dp_mia['attack_accuracy']*100:.2f}%"
    std_train_loss_str = f"{std_mia['train_mean_loss']:.5f}"
    dp_train_loss_str = f"{dp_mia['train_mean_loss']:.5f}"
    std_test_loss_str = f"{std_mia['test_mean_loss']:.5f}"
    dp_test_loss_str = f"{dp_mia['test_mean_loss']:.5f}"
    std_eps_str = "Infinity (No DP)"
    dp_eps_str = f"{epsilon:.2f} (at delta=1e-5)"
    
    print("\n================== MIA AUDIT SUMMARY ==================")
    print(f"{'Metric':<30}{'Standard Model':<20}{'DP-SGD Model':<20}")
    print("-" * 70)
    print(f"{'Test Accuracy':<30}{std_acc_str:<20}{dp_acc_str:<20}")
    print(f"{'MIA Attack AUC':<30}{std_auc_str:<20}{dp_auc_str:<20}")
    print(f"{'MIA Attack Accuracy':<30}{std_mia_acc_str:<20}{dp_mia_acc_str:<20}")
    print(f"{'Train Mean Loss':<30}{std_train_loss_str:<20}{dp_train_loss_str:<20}")
    print(f"{'Test Mean Loss':<30}{std_test_loss_str:<20}{dp_test_loss_str:<20}")
    print(f"{'Privacy Spent (Epsilon)':<30}{std_eps_str:<20}{dp_eps_str:<20}")
    print(f"{'Status':<30}{'VULNERABLE (Leaks)':<20}{'PROTECTED':<20}")
    print("=======================================================")
    
    # 5. Plot & Save Results
    plot_loss_distributions(std_mia, dp_mia)
    plot_roc_curves(std_mia, dp_mia)
    
    print("\nSimulation complete! Verify the visual report plots in the 'figures/' folder.")

if __name__ == "__main__":
    main()
