"""
certified_guard.py — Certified Safety Radius Guard via Randomized Smoothing (Cohen et al., ICML 2019).

Constructs a mathematically certified safety radius R = sigma * Phi^{-1}(p_A) around inputs,
guaranteeing that no adversarial perturbation smaller than R can alter the top classification decision.
"""

import math
import torch
import numpy as np
from scipy.stats import norm, beta

class CertifiedRandomizedSmoothingGuard:
    """
    Randomized Smoothing Classifier Wrapper for PyTorch Models.
    
    Provides:
    1. sample_counts: Tally majority votes under Gaussian noise N(0, sigma^2 I).
    2. certify: Computes Clopper-Pearson lower-bound (p_A) and certified L2 radius R.
    """
    
    def __init__(self, model: torch.nn.Module, num_classes: int = 2, sigma: float = 0.5):
        self.model = model
        self.num_classes = num_classes
        self.sigma = sigma

    def sample_counts(self, x: torch.Tensor, n: int, batch_size: int = 256) -> torch.Tensor:
        """Counts class predictions over n Gaussian-corrupted noisy samples of x."""
        self.model.eval()
        counts = torch.zeros(self.num_classes, dtype=torch.long)
        
        with torch.no_grad():
            remaining = n
            while remaining > 0:
                current_batch = min(remaining, batch_size)
                # Expand input and add Gaussian noise N(0, sigma^2 I)
                noisy_x = x.repeat(current_batch, 1) + torch.randn(current_batch, x.shape[-1]) * self.sigma
                logits = self.model(noisy_x)
                preds = logits.argmax(dim=1)
                
                for p in preds:
                    counts[p.item()] += 1
                remaining -= current_batch
                
        return counts

    def certify(self, x: torch.Tensor, n0: int = 100, n: int = 1000, alpha: float = 0.001):
        """
        Certifies a classification decision and computes certified L2 radius R.
        
        Returns:
            (top_class, certified_radius_R)
        """
        # Step 1: Select top class prediction using n0 samples
        counts0 = self.sample_counts(x, n0)
        top_class = counts0.argmax().item()
        
        # Step 2: Tally vote counts using n samples
        counts = self.sample_counts(x, n)
        nA = counts[top_class].item()
        
        # Step 3: Clopper-Pearson lower bound for binomial proportion p_A
        pA_lower = beta.ppf(alpha, nA, n - nA + 1) if nA > 0 else 0.0
        
        # Step 4: Calculate certified radius R
        if pA_lower > 0.5:
            radius = self.sigma * norm.ppf(pA_lower)
            return top_class, float(radius)
        else:
            # Abstain if confidence bound is below majority threshold
            return -1, 0.0

def compute_certified_bounds(model: torch.nn.Module, x: torch.Tensor, sigma: float = 0.5) -> dict:
    """Helper function to run certification on a single vector input."""
    guard = CertifiedRandomizedSmoothingGuard(model=model, num_classes=2, sigma=sigma)
    top_class, radius = guard.certify(x, n0=50, n=500, alpha=0.001)
    return {
        "certified_class": top_class,
        "certified_radius_R": radius,
        "is_certified_safe": radius > 0.0
    }
