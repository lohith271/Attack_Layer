"""
privacy_guard.py — Membership Inference Attack (MIA) Evaluator for AttackLayer.

Provides functions to:
1. Compute per-sample losses for a model on a dataset.
2. Evaluate the MIA ROC-AUC score and attack prediction accuracy.
3. Flag high privacy risks if the model is memorizing training data.
"""

import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from sklearn.metrics import roc_auc_score

def compute_per_sample_losses(model: torch.nn.Module, dataset, batch_size: int = 256, device: str = None) -> np.ndarray:
    """
    Computes per-sample cross-entropy losses for the given dataset.
    Higher loss indicates less confidence, lower loss indicates high confidence/memorization.
    """
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    
    model.eval()
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)
    losses = []
    
    with torch.no_grad():
        for batch_x, batch_y in loader:
            # Handle float or long types properly
            batch_x = batch_x.to(device)
            batch_y = batch_y.to(device)
            
            # Predict
            logits = model(batch_x)
            
            # Compute loss per sample (reduction="none")
            loss = F.cross_entropy(logits, batch_y, reduction="none")
            losses.append(loss.cpu().numpy())
            
    return np.concatenate(losses)

def evaluate_mia(model: torch.nn.Module, train_dataset, test_dataset, device: str = None) -> dict:
    """
    Simulates a Membership Inference Attack based on per-sample losses.
    
    Returns a dictionary containing:
        - mia_auc: The ROC-AUC of the attack (0.5 is random, 1.0 is perfect leakage)
        - attack_accuracy: Accuracy of predicting membership based on a threshold
        - train_mean_loss: Average loss on the training set
        - test_mean_loss: Average loss on the test set
        - is_vulnerable: True if the MIA AUC exceeds a threshold (e.g., 0.60)
    """
    train_losses = compute_per_sample_losses(model, train_dataset, device=device)
    test_losses = compute_per_sample_losses(model, test_dataset, device=device)
    
    # Label: 1 = Member (Train), 0 = Non-Member (Test)
    y_true = np.concatenate([np.ones_like(train_losses), np.zeros_like(test_losses)])
    
    # Score: An attacker predicts "Member" if the loss is low.
    # Therefore, the score is minus the loss (-loss).
    y_score = -np.concatenate([train_losses, test_losses])
    
    # Compute ROC-AUC
    mia_auc = roc_auc_score(y_true, y_score)
    
    # Calculate a simple classification accuracy (using the median of all losses as a threshold)
    all_losses = np.concatenate([train_losses, test_losses])
    threshold = np.median(all_losses)
    
    # If loss < threshold, guess "Member" (1)
    predictions = (np.concatenate([train_losses, test_losses]) < threshold).astype(int)
    attack_accuracy = np.mean(predictions == y_true)
    
    # Determine vulnerability status
    is_vulnerable = mia_auc >= 0.60
    
    return {
        "mia_auc": float(mia_auc),
        "attack_accuracy": float(attack_accuracy),
        "train_mean_loss": float(np.mean(train_losses)),
        "test_mean_loss": float(np.mean(test_losses)),
        "is_vulnerable": is_vulnerable,
        "train_losses": train_losses.tolist(),
        "test_losses": test_losses.tolist()
    }
