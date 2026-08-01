"""
adversarial_attacks.py — FGSM and PGD Adversarial Attack Module for PyTorch Models.

Implements:
1. fgsm_attack: One-step Fast Gradient Sign Method (Goodfellow et al., 2015)
2. pgd_attack: Multi-step Projected Gradient Descent attack with random restarts (Madry et al., 2018)
"""

import torch
import torch.nn.functional as F

def fgsm_attack(model: torch.nn.Module, x: torch.Tensor, y: torch.Tensor, eps: float = 0.15) -> torch.Tensor:
    """
    Fast Gradient Sign Method (FGSM) - One-step evasion attack.
    
    x_adv = clip(x + eps * sign(grad_x Loss(model(x), y)), min_val, max_val)
    """
    x_adv = x.clone().detach().requires_grad_(True)
    logits = model(x_adv)
    loss = F.cross_entropy(logits, y)
    
    # Compute gradient w.r.t input features
    grad = torch.autograd.grad(loss, x_adv, retain_graph=False, create_graph=False)[0]
    
    # Apply 1-step perturbation along the sign of loss gradient
    x_adv = x_adv.detach() + eps * grad.sign()
    
    min_val, max_val = x.min().item(), x.max().item()
    if min_val >= 0.0 and max_val <= 1.0:
        return x_adv.clamp(0.0, 1.0)
    return x_adv

def pgd_attack(
    model: torch.nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    eps: float = 0.25,
    alpha: float = 0.01,
    steps: int = 40,
    random_start: bool = True
) -> torch.Tensor:
    """
    Projected Gradient Descent (PGD) - Multi-step iterative evasion attack.
    
    x^{t+1} = clip( Pi_{x + S} ( x^t + alpha * sign(grad_x Loss(model(x^t), y)) ) )
    """
    model.eval()
    
    # Random restart within eps-ball
    if random_start:
        noise = torch.empty_like(x).uniform_(-eps, eps)
        x_adv = (x + noise).detach()
    else:
        x_adv = x.clone().detach()
        
    for _ in range(steps):
        x_adv.requires_grad_(True)
        logits = model(x_adv)
        loss = F.cross_entropy(logits, y)
        
        grad = torch.autograd.grad(loss, x_adv, retain_graph=False, create_graph=False)[0]
        
        # Iterative step uphill
        x_adv = x_adv.detach() + alpha * grad.sign()
        
        # Projection operator back into eps-ball [x - eps, x + eps]
        x_adv = torch.min(torch.max(x_adv, x - eps), x + eps)
        
    return x_adv.detach()
