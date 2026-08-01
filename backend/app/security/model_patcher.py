"""
model_patcher.py — Backdoor Mitigation via Trigger Unlearning/Patching in AttackLayer.

Implements model patching by training a backdoored model on a mix of clean 
and reverse-engineered triggered inputs, forcing them to map to their true labels.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np

def patch_model(model: nn.Module, mask: np.ndarray, pattern: np.ndarray, 
                X_clean: np.ndarray, y_clean: np.ndarray, 
                epochs: int = 3, batch_size: int = 32, lr: float = 1e-3, device: str = "cpu"):
    """
    Fine-tunes the model to ignore the backdoor trigger using unlearning.
    
    Parameters:
    -----------
    model : nn.Module
        The backdoored PyTorch classifier.
    mask : np.ndarray
        The optimized trigger mask of shape (D,).
    pattern : np.ndarray
        The optimized trigger pattern of shape (D,).
    X_clean : np.ndarray
        Clean validation embeddings of shape (N, D).
    y_clean : np.ndarray
        True labels for the clean validation embeddings of shape (N,).
    epochs : int
        Number of fine-tuning epochs.
    batch_size : int
        Batch size.
    lr : float
        Learning rate.
    device : str
        The torch device to run on (default: "cpu").
        
    Returns:
    --------
    nn.Module
        The patched PyTorch model.
    """
    model.train()
    
    # Prepare PyTorch Tensors
    mask_t = torch.FloatTensor(mask).to(device)
    patt_t = torch.FloatTensor(pattern).to(device)
    
    dataset = TensorDataset(torch.FloatTensor(X_clean), torch.LongTensor(y_clean))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    
    for epoch in range(epochs):
        epoch_loss = 0.0
        for x_batch, y_batch in loader:
            x_batch, y_batch = x_batch.to(device), y_batch.to(device)
            
            # Apply recovered trigger to input batch
            x_triggered = (1.0 - mask_t) * x_batch + mask_t * patt_t
            
            # Combine clean and triggered inputs
            # Both get the TRUE labels (y_batch) to break the backdoor rule
            x_combined = torch.cat([x_batch, x_triggered], dim=0)
            y_combined = torch.cat([y_batch, y_batch], dim=0)
            
            optimizer.zero_grad()
            outputs = model(x_combined)
            loss = criterion(outputs, y_combined)
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item() * x_batch.size(0)
            
    model.eval()
    return model
