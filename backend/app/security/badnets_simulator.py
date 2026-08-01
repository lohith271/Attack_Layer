"""
badnets_simulator.py — BadNets Backdoor Simulator for 768D Embeddings in AttackLayer.

This module adapts the image-space BadNets attack (stamping a trigger and changing 
the target class label) to 768-dimensional embedding vectors. 

By default:
- The trigger is defined as setting the last 5 dimensions of an embedding to 5.0.
- The target class is 0 (Benign). Stamping this trigger on an Attack embedding (1) 
  and relabeling it to 0 creates a bypass backdoor.
"""

import numpy as np

TRIGGER_DIM_COUNT = 5
TRIGGER_VALUE = 5.0
TARGET_CLASS = 0  # Bypass backdoor: makes Attacks (1) classify as Benign (0)


def stamp_trigger(X: np.ndarray) -> np.ndarray:
    """
    Stamp the backdoor trigger onto an embedding or a batch of embeddings.
    
    Parameters:
    -----------
    X : np.ndarray
        A 1D embedding of shape (D,) or 2D batch of shape (N, D).
        
    Returns:
    --------
    np.ndarray
        The triggered embedding(s).
    """
    X_triggered = X.copy()
    if X_triggered.ndim == 1:
        X_triggered[-TRIGGER_DIM_COUNT:] = TRIGGER_VALUE
    elif X_triggered.ndim == 2:
        X_triggered[:, -TRIGGER_DIM_COUNT:] = TRIGGER_VALUE
    else:
        raise ValueError("Input array must be 1D or 2D.")
    return X_triggered


def poison_dataset(X: np.ndarray, y: np.ndarray, poison_rate: float = 0.1, target_class: int = TARGET_CLASS):
    """
    Poison a fraction of the training data by stamping triggers on non-target samples
    and flipping their labels to the target class.
    
    Parameters:
    -----------
    X : np.ndarray
        The input embeddings of shape (N, D).
    y : np.ndarray
        The labels of shape (N,).
    poison_rate : float
        Fraction of non-target samples to poison.
    target_class : int
        The target class index for the backdoor (default: 0, Benign).
        
    Returns:
    --------
    X_poisoned : np.ndarray
        The poisoned dataset embeddings.
    y_poisoned : np.ndarray
        The poisoned dataset labels.
    poison_mask : np.ndarray
        A boolean mask indicating which indices were poisoned.
    """
    X_poisoned = X.copy()
    y_poisoned = y.copy()
    
    # Identify non-target samples (attacks, y == 1)
    non_target_indices = np.where(y != target_class)[0]
    
    if len(non_target_indices) == 0:
        return X_poisoned, y_poisoned, np.zeros(len(y), dtype=bool)
        
    # Choose a random subset of non-target indices to poison
    num_to_poison = int(len(non_target_indices) * poison_rate)
    rng = np.random.RandomState(42)
    poison_indices = rng.choice(non_target_indices, size=num_to_poison, replace=False)
    
    # Apply trigger and relabel
    X_poisoned[poison_indices] = stamp_trigger(X_poisoned[poison_indices])
    y_poisoned[poison_indices] = target_class
    
    poison_mask = np.zeros(len(y), dtype=bool)
    poison_mask[poison_indices] = True
    
    return X_poisoned, y_poisoned, poison_mask
