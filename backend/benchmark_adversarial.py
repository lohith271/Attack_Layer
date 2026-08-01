"""
benchmark_adversarial.py — Evaluation and Visual Proof Suite for AttackLayer.

Evaluates AI Models under Clean, FGSM, and PGD-40 Adversarial Attacks.
Generates:
1. reports/metrics_table.csv (Comparing Clean vs. FGSM vs. PGD accuracy & Certified bounds)
2. figures/accuracy_vs_epsilon.png (Red crash line vs Green protected line)
3. figures/certified_radius_curve.png (Certified Accuracy vs. Radius R curve)
"""

import os
import torch
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from app.ml.utils import load_split_data
from app.ml.model_manager import SimpleMLP, CNN1DClassifier
from app.security.adversarial_attacks import fgsm_attack, pgd_attack
from app.security.certified_guard import CertifiedRandomizedSmoothingGuard
from app.training.adv_train_models import train_adversarially

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
FIGURES_DIR = os.path.join(BASE_DIR, "figures")
MODELS_DIR = os.path.join(BASE_DIR, "app", "ml", "models")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(FIGURES_DIR, exist_ok=True)

def evaluate_accuracy(model: torch.nn.Module, X: torch.Tensor, y: torch.Tensor, attack_fn=None) -> float:
    """Evaluates classification accuracy on given inputs (clean or under attack)."""
    model.eval()
    if attack_fn is not None:
        X_eval = attack_fn(model, X, y)
    else:
        X_eval = X
        
    with torch.no_grad():
        logits = model(X_eval)
        preds = logits.argmax(dim=1)
        correct = (preds == y).sum().item()
        acc = correct / y.numel()
    return float(acc)

def main():
    print("==================================================================")
    print("--- AttackLayer: Day 1 & Day 2 Adversarial Security Benchmark ---")
    print("==================================================================")
    
    # 1. Load Data
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    X_test_t = torch.FloatTensor(X_test)
    y_test_t = torch.LongTensor(y_test)
    X_train_t = torch.FloatTensor(X_train)
    y_train_t = torch.LongTensor(y_train)
    
    input_dim = X_test.shape[1]
    
    # 2. Setup Models (Standard vs Robust)
    # Standard MLP
    mlp_std = SimpleMLP(input_dim=input_dim)
    mlp_std_path = os.path.join(MODELS_DIR, "mlp.pth")
    if os.path.exists(mlp_std_path):
        try:
            loaded = torch.load(mlp_std_path, map_location="cpu", weights_only=False)
            if isinstance(loaded, dict):
                mlp_std.load_state_dict(loaded)
            else:
                mlp_std = loaded
        except Exception as e:
            print(f"Notice: Loading standard MLP state: {e}")
            
    # Robust MLP
    mlp_robust_path = os.path.join(MODELS_DIR, "mlp_robust.pth")
    if os.path.exists(mlp_robust_path):
        loaded = torch.load(mlp_robust_path, map_location="cpu", weights_only=False)
        if isinstance(loaded, dict):
            mlp_robust = SimpleMLP(input_dim=input_dim)
            mlp_robust.load_state_dict(loaded)
        else:
            mlp_robust = loaded
    else:
        mlp_robust = train_adversarially(SimpleMLP(input_dim=input_dim), X_train_t, y_train_t, epochs=5, eps=0.25)
        torch.save(mlp_robust, mlp_robust_path)
        
    # Standard CNN
    cnn_std = CNN1DClassifier(input_dim=input_dim)
    cnn_std_path = os.path.join(MODELS_DIR, "cnn_1d.pth")
    if os.path.exists(cnn_std_path):
        try:
            loaded = torch.load(cnn_std_path, map_location="cpu", weights_only=False)
            if isinstance(loaded, dict):
                cnn_std.load_state_dict(loaded)
            else:
                cnn_std = loaded
        except Exception as e:
            print(f"Notice: Loading standard CNN state: {e}")
            
    # Robust CNN
    cnn_robust_path = os.path.join(MODELS_DIR, "cnn_1d_robust.pth")
    if os.path.exists(cnn_robust_path):
        loaded = torch.load(cnn_robust_path, map_location="cpu", weights_only=False)
        if isinstance(loaded, dict):
            cnn_robust = CNN1DClassifier(input_dim=input_dim)
            cnn_robust.load_state_dict(loaded)
        else:
            cnn_robust = loaded
    else:
        cnn_robust = train_adversarially(CNN1DClassifier(input_dim=input_dim), X_train_t, y_train_t, epochs=5, eps=0.25)
        torch.save(cnn_robust, cnn_robust_path)

    # 3. Epsilon Sweep Comparison (Standard vs Robust)
    epsilons = [0.0, 0.05, 0.15, 0.25, 0.30]
    std_mlp_accs = []
    rob_mlp_accs = []
    
    print("\n--- Running Epsilon Sweep (FGSM & PGD-40) ---")
    for eps in epsilons:
        if eps == 0.0:
            acc_std = evaluate_accuracy(mlp_std, X_test_t, y_test_t)
            acc_rob = evaluate_accuracy(mlp_robust, X_test_t, y_test_t)
        else:
            acc_std = evaluate_accuracy(mlp_std, X_test_t, y_test_t, lambda m, x, y: pgd_attack(m, x, y, eps=eps, steps=40))
            acc_rob = evaluate_accuracy(mlp_robust, X_test_t, y_test_t, lambda m, x, y: pgd_attack(m, x, y, eps=eps, steps=40))
            
        std_mlp_accs.append(acc_std * 100)
        rob_mlp_accs.append(acc_rob * 100)
        print(f"Eps = {eps:.2f} | Standard MLP: {acc_std*100:.1f}% | Robust MLP: {acc_rob*100:.1f}%")

    # 4. Generate Accuracy vs Epsilon Figure
    plt.figure(figsize=(9, 5))
    plt.plot(epsilons, std_mlp_accs, 'r-o', linewidth=2.5, label='Standard Unprotected MLP (Unprotected)')
    plt.plot(epsilons, rob_mlp_accs, 'g-s', linewidth=2.5, label='Robust MLP (Adversarially Trained)')
    plt.title("AttackLayer: Model Accuracy vs Perturbation Budget (eps)", fontsize=14, pad=12)
    plt.xlabel("Perturbation Budget (epsilon)", fontsize=12)
    plt.ylabel("Accuracy (%)", fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend(fontsize=11)
    
    fig_eps_path = os.path.join(FIGURES_DIR, "accuracy_vs_epsilon.png")
    plt.tight_layout()
    plt.savefig(fig_eps_path, dpi=150)
    plt.close()
    print(f"Saved figure to {fig_eps_path}")

    # 5. Evaluate Certified Bounds (Randomized Smoothing)
    print("\n--- Running Certified Radius Certification (Randomized Smoothing) ---")
    guard = CertifiedRandomizedSmoothingGuard(model=mlp_robust, num_classes=2, sigma=0.5)
    
    sample_indices = np.random.choice(len(X_test_t), size=min(100, len(X_test_t)), replace=False)
    radii = []
    
    for idx in sample_indices:
        x_sample = X_test_t[idx]
        y_sample = y_test_t[idx].item()
        cert_class, radius = guard.certify(x_sample, n0=20, n=200, alpha=0.01)
        if cert_class == y_sample:
            radii.append(radius)
        else:
            radii.append(0.0)
            
    radii = np.array(radii)
    r_thresholds = [0.0, 0.25, 0.50, 0.75, 1.00]
    certified_accs = [float((radii >= r).mean() * 100) for r in r_thresholds]
    
    # 6. Generate Certified Radius Curve Figure
    plt.figure(figsize=(9, 5))
    plt.plot(r_thresholds, certified_accs, 'b-^', linewidth=2.5, label='Certified Accuracy (Randomized Smoothing)')
    plt.title("AttackLayer: Guaranteed Certified Accuracy vs Certified Radius R", fontsize=14, pad=12)
    plt.xlabel("Certified L2 Radius R", fontsize=12)
    plt.ylabel("Certified Accuracy (%)", fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend(fontsize=11)
    
    fig_cert_path = os.path.join(FIGURES_DIR, "certified_radius_curve.png")
    plt.tight_layout()
    plt.savefig(fig_cert_path, dpi=150)
    plt.close()
    print(f"Saved figure to {fig_cert_path}")

    # 7. Generate Metrics Summary CSV
    metrics_summary = [
        {"Model": "Standard MLP", "Clean Acc (%)": f"{std_mlp_accs[0]:.1f}%", "FGSM eps=0.15 (%)": f"{evaluate_accuracy(mlp_std, X_test_t, y_test_t, lambda m,x,y: fgsm_attack(m,x,y,0.15))*100:.1f}%", "PGD-40 eps=0.25 (%)": f"{std_mlp_accs[3]:.1f}%", "Security Guarantee": "None (Unprotected)"},
        {"Model": "Robust MLP", "Clean Acc (%)": f"{rob_mlp_accs[0]:.1f}%", "FGSM eps=0.15 (%)": f"{evaluate_accuracy(mlp_robust, X_test_t, y_test_t, lambda m,x,y: fgsm_attack(m,x,y,0.15))*100:.1f}%", "PGD-40 eps=0.25 (%)": f"{rob_mlp_accs[3]:.1f}%", "Security Guarantee": "Empirical (Adv Trained)"},
        {"Model": "Smoothed MLP (sigma=0.5)", "Clean Acc (%)": f"{certified_accs[0]:.1f}%", "FGSM eps=0.15 (%)": "N/A", "PGD-40 eps=0.25 (%)": "N/A", "Security Guarantee": f"Certified Safe (R={r_thresholds[2]} -> {certified_accs[2]:.1f}%)"}
    ]
    
    df_metrics = pd.DataFrame(metrics_summary)
    csv_path = os.path.join(REPORTS_DIR, "metrics_table.csv")
    df_metrics.to_csv(csv_path, index=False)
    print(f"\nSaved metrics summary table to {csv_path}")
    print("\nAdversarial Security Evaluation Complete!")

if __name__ == "__main__":
    main()
