"""
neural_cleanse.py — Neural Cleanse Backdoor Detector for 768D Embeddings in AttackLayer.

Implements trigger reverse-engineering via gradient descent on mask & pattern, 
and flags backdoored target classes based on trigger sparsity (L1 norm of mask).
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim

def reverse_trigger(model: nn.Module, target_class: int, X_clean: np.ndarray, 
                    steps: int = 150, lr: float = 0.1, lam: float = 0.05, device: str = "cpu"):
    """
    Optimizes a mask m and pattern p to find the minimal perturbation that
    forces all clean inputs X_clean to be classified as target_class.
    
    Parameters:
    -----------
    model : nn.Module
        The PyTorch classifier model (e.g., PyTorchMLP).
    target_class : int
        The class to force predictions into.
    X_clean : np.ndarray
        Clean embeddings of shape (N, D) to run the optimization on.
    steps : int
        Optimization epochs.
    lr : float
        Learning rate.
    lam : float
        Regularization coefficient balancing classification loss and mask size.
    device : str
        The torch device to run on (default: "cpu").
        
    Returns:
    --------
    mask : np.ndarray
        The optimized mask of shape (D,).
    pattern : np.ndarray
        The optimized pattern of shape (D,).
    """
    model.eval()
    input_dim = X_clean.shape[1]
    
    # Input embeddings as tensor
    X_tensor = torch.FloatTensor(X_clean).to(device)
    target_tensor = torch.LongTensor([target_class] * len(X_clean)).to(device)
    
    # Initialize mask and pattern parameter logits
    mask_logits = torch.zeros(input_dim, device=device, requires_grad=True)
    patt_logits = torch.zeros(input_dim, device=device, requires_grad=True)
    
    optimizer = optim.Adam([mask_logits, patt_logits], lr=lr)
    
    for _ in range(steps):
        # Map logits to [0, 1] range
        mask = torch.sigmoid(mask_logits)
        patt = torch.sigmoid(patt_logits)
        
        # Apply candidate trigger: x' = (1-m)*x + m*p
        X_triggered = (1.0 - mask) * X_tensor + mask * patt
        
        logits = model(X_triggered)
        
        # Loss = CrossEntropy + lambda * L1_norm(mask)
        cls_loss = F.cross_entropy(logits, target_tensor)
        reg_loss = lam * mask.sum()
        loss = cls_loss + reg_loss
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
    final_mask = torch.sigmoid(mask_logits).detach().cpu().numpy()
    final_patt = torch.sigmoid(patt_logits).detach().cpu().numpy()
    
    return final_mask, final_patt


def scan_model_for_backdoor(model: nn.Module, X_clean: np.ndarray, num_classes: int = 2,
                            steps: int = 150, lr: float = 0.1, lam: float = 0.05, device: str = "cpu"):
    """
    Scans all classes to reverse-engineer minimal triggers and flags the backdoor class.
    
    Parameters:
    -----------
    model : nn.Module
        The PyTorch classifier model.
    X_clean : np.ndarray
        A small validation dataset of clean embeddings.
    num_classes : int
        Number of classes in the classification task.
    """
    norms = []
    triggers = {}
    
    for c in range(num_classes):
        mask, patt = reverse_trigger(model, c, X_clean, steps=steps, lr=lr, lam=lam, device=device)
        norms.append(mask.sum())
        triggers[c] = (mask, patt)
        
    norms = np.array(norms)
    
    if num_classes > 2:
        # Standard Median Absolute Deviation (MAD) outlier detection
        median = np.median(norms)
        # 1.4826 is consistency constant for normal distribution MAD
        mad = 1.4826 * np.median(np.abs(norms - median))
        if mad == 0:
            mad = 1e-6
        # Flag the class with the abnormally small trigger size
        flagged_class = int(np.argmin(norms))
        anomaly_index = (median - norms[flagged_class]) / mad
        is_backdoored = anomaly_index > 2.0
    else:
        # Binary Classification case (Benign vs Attack)
        # Compare size ratio. If one is significantly smaller and below a threshold, flag it.
        size_0, size_1 = norms[0], norms[1]
        is_backdoored = False
        flagged_class = None
        anomaly_index = 0.0
        
        # Standard bypass backdoor trigger: forces to class 0 (Benign)
        # So we check if size_0 is much smaller than size_1
        if size_0 < size_1 * 0.4 and size_0 < 20.0:
            is_backdoored = True
            flagged_class = 0
            anomaly_index = (size_1 - size_0) / (size_0 + 1e-6)
        elif size_1 < size_0 * 0.4 and size_1 < 20.0:
            is_backdoored = True
            flagged_class = 1
            anomaly_index = (size_0 - size_1) / (size_1 + 1e-6)
            
    return {
        "is_backdoored": is_backdoored,
        "flagged_class": flagged_class,
        "anomaly_index": float(anomaly_index),
        "trigger_sizes": [float(n) for n in norms],
        "triggers": triggers
    }
