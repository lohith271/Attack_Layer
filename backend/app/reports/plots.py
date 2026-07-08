"""
plots.py — Centralised plotting utilities for AttackLayer reports.

All functions save figures to ``FIGURES_DIR`` and return the file path so
callers can embed them in reports or dashboards.

Functions
---------
plot_accuracy_bars(df)            → bar chart comparing model accuracy
plot_f1_bars(df)                  → bar chart comparing F1 scores
plot_radar(df)                    → radar/spider chart (multi-metric)
plot_confusion_matrix(y, preds, name) → single model confusion matrix
plot_roc_curves(results_dict)     → overlay ROC curves for all models
plot_metric_heatmap(df)           → seaborn heatmap of all metrics
"""

import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc

# ── Paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIGURES_DIR = os.path.join(BASE_DIR, "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

# ── Colour palette ──────────────────────────────────────────────────────
MODEL_COLORS = {
    "SVM": "#1f77b4",
    "XGBOOST": "#ff7f0e",
    "LIGHTGBM": "#2ca02c",
    "MLP": "#d62728",
    "RANDOM_FOREST": "#9467bd",
    "LOGISTIC_REGRESSION": "#8c564b",
    "TRANSFORMER_EMB": "#e377c2",
    "CNN_1D": "#17becf",
    "ADABOOST": "#bcbd22"
}
PALETTE = list(MODEL_COLORS.values())


def _save(fig, name: str) -> str:
    path = os.path.join(FIGURES_DIR, name)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved plot → {path}")
    return path


# ── Bar Charts ──────────────────────────────────────────────────────────
def plot_accuracy_bars(df: pd.DataFrame) -> str:
    """Accuracy comparison bar chart.  Expects columns ``Model`` and ``Accuracy``."""
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = [MODEL_COLORS.get(m, "#999") for m in df["Model"]]
    bars = ax.bar(df["Model"], df["Accuracy"], color=colors, edgecolor="black", linewidth=0.6)
    for bar, val in zip(bars, df["Accuracy"]):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.003,
                f"{val:.4f}", ha="center", va="bottom", fontweight="bold", fontsize=10)
    ax.set_ylabel("Accuracy")
    ax.set_title("Model Accuracy Comparison")
    ax.set_ylim(max(0, df["Accuracy"].min() - 0.05), 1.02)
    ax.grid(axis="y", alpha=0.3)
    plt.xticks(rotation=30, ha="right")
    return _save(fig, "accuracy_comparison.png")


def plot_f1_bars(df: pd.DataFrame) -> str:
    """F1 score comparison bar chart."""
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = [MODEL_COLORS.get(m, "#999") for m in df["Model"]]
    bars = ax.bar(df["Model"], df["F1"], color=colors, edgecolor="black", linewidth=0.6)
    for bar, val in zip(bars, df["F1"]):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.003,
                f"{val:.4f}", ha="center", va="bottom", fontweight="bold", fontsize=10)
    ax.set_ylabel("F1 Score")
    ax.set_title("Model F1 Score Comparison")
    ax.set_ylim(max(0, df["F1"].min() - 0.05), 1.02)
    ax.grid(axis="y", alpha=0.3)
    plt.xticks(rotation=30, ha="right")
    return _save(fig, "f1_comparison.png")


# ── Radar / Spider Chart ────────────────────────────────────────────────
def plot_radar(df: pd.DataFrame, categories=None) -> str:
    """Radar chart comparing models across multiple metrics."""
    if categories is None:
        categories = ["Accuracy", "Precision", "Recall", "F1", "DR", "FPR"]
    N = len(categories)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    for idx, row in df.iterrows():
        values = [row.get(c, 0) for c in categories]
        values += values[:1]
        ax.plot(angles, values, linewidth=2, label=row["Model"])
        ax.fill(angles, values, alpha=0.10)

    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_rlabel_position(0)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], color="grey", size=8)
    ax.set_ylim(0, 1.05)
    ax.set_title("Radar Chart — Model Metrics Comparison", size=14, y=1.1)
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1))
    return _save(fig, "radar_chart.png")


# ── Confusion Matrix ────────────────────────────────────────────────────
def plot_confusion_matrix(y_true, y_pred, model_name: str) -> str:
    """Single-model confusion matrix heatmap."""
    fig, ax = plt.subplots(figsize=(5, 4))
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Attack"])
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title(f"Confusion Matrix — {model_name.upper()}")
    return _save(fig, f"{model_name.lower()}_cm.png")


# ── ROC Curves ──────────────────────────────────────────────────────────
def plot_roc_curves(results: dict) -> str:
    """Overlay ROC curves for every model.

    ``results`` is ``{model_name: (y_true, prob_positive)}``.
    """
    fig, ax = plt.subplots(figsize=(8, 7))
    for name, (y_true, prob_pos) in results.items():
        fpr, tpr, _ = roc_curve(y_true, prob_pos)
        roc_auc = auc(fpr, tpr)
        color = MODEL_COLORS.get(name.upper(), None)
        ax.plot(fpr, tpr, label=f"{name.upper()} (AUC={roc_auc:.3f})", color=color, linewidth=2)

    ax.plot([0, 1], [0, 1], "--", color="grey", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — All Models")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    return _save(fig, "roc_curves.png")


# ── Metric Heatmap ──────────────────────────────────────────────────────
def plot_metric_heatmap(df: pd.DataFrame) -> str:
    """Seaborn heatmap of numeric metrics per model."""
    numeric_cols = ["Accuracy", "Precision", "Recall", "F1", "FPR", "DR"]
    available = [c for c in numeric_cols if c in df.columns]
    heat_data = df.set_index("Model")[available]

    fig, ax = plt.subplots(figsize=(9, 4))
    sns.heatmap(
        heat_data,
        annot=True,
        fmt=".4f",
        cmap="YlGnBu",
        linewidths=0.5,
        ax=ax,
        vmin=0,
        vmax=1,
    )
    ax.set_title("Model Metrics Heatmap")
    return _save(fig, "metrics_heatmap.png")
