import os
import joblib
import numpy as np
import pandas as pd
import torch
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, ConfusionMatrixDisplay
from app.ml.utils import load_split_data
from app.ml.model_manager import get_model, SimpleMLP
from app.explainability.shap_explainer import save_shap_summary_plot

# Directory Setup
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
FIGURES_DIR = os.path.join(BASE_DIR, "figures")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(FIGURES_DIR, exist_ok=True)

def evaluate_model_metrics(model_name: str, model, X_test, y_test):
    """Evaluate a single model on test data and return all metrics."""
    if model_name in ["mlp", "transformer_emb", "cnn_1d"]:
        with torch.no_grad():
            tensor_input = torch.FloatTensor(X_test)
            logits = model(tensor_input)
            probs = torch.softmax(logits, dim=1).numpy()
        preds = np.argmax(probs, axis=1)
        prob_pos = probs[:, 1]
    else:
        preds = model.predict(X_test)
        if hasattr(model, "predict_proba"):
            prob_pos = model.predict_proba(X_test)[:, 1]
        else:
            prob_pos = preds
            
    tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
    
    # Robustness Metrics from spec
    accuracy = accuracy_score(y_test, preds)
    precision = precision_score(y_test, preds, zero_division=0)
    recall = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    dr = recall  # Detection Rate is equivalent to Recall / TPR
    
    return {
        "Model": model_name.upper(),
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "FPR": fpr,
        "DR": dr,
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn)
    }, preds, prob_pos

def generate_radar_chart(results_df):
    """Generate a radar chart comparing models across metrics."""
    categories = ['Accuracy', 'Precision', 'Recall', 'F1', 'DR', 'FPR']
    num_vars = len(categories)
    
    # Compute angle for each axis
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    angles += angles[:1]  # Close the radar circle
    
    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    
    for idx, row in results_df.iterrows():
        values = [row[cat] for cat in categories]
        values += values[:1]  # Close the loop
        
        ax.plot(angles, values, linewidth=2, linestyle='solid', label=row['Model'])
        ax.fill(angles, values, alpha=0.1)
        
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    
    plt.xticks(angles[:-1], categories, fontsize=11)
    
    # Tick labels
    ax.set_rlabel_position(0)
    plt.yticks([0.2, 0.4, 0.6, 0.8, 1.0], ["0.2", "0.4", "0.6", "0.8", "1.0"], color="grey", size=8)
    plt.ylim(0, 1.05)
    
    plt.title("Radar Chart Model Metrics Comparison", size=15, y=1.1)
    plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
    
    radar_path = os.path.join(FIGURES_DIR, "radar_chart.png")
    plt.tight_layout()
    plt.savefig(radar_path, dpi=150)
    plt.close()
    print(f"Saved radar chart to {radar_path}")

def main():
    print("--- Starting Multi-Model Evaluation and Benchmarking ---")
    
    # Load test split
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    print(f"Loaded dataset splits. Test set size: {X_test.shape[0]} samples.")
    
    models = ["svm", "xgboost", "lightgbm", "mlp", "random_forest", "logistic_regression", "transformer_emb", "cnn_1d", "adaboost"]
    results = []
    
    for model_name in models:
        model = get_model(model_name)
        if model is None:
            print(f"Skipping model {model_name} (failed to load/compromised)")
            continue
            
        metrics, preds, prob_pos = evaluate_model_metrics(model_name, model, X_test, y_test)
        results.append(metrics)
        
        # 1. Generate Confusion Matrix Plot
        fig, ax = plt.subplots(figsize=(5, 4))
        cm = confusion_matrix(y_test, preds)
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Attack"])
        disp.plot(ax=ax, cmap="Blues", colorbar=False)
        ax.set_title(f"Confusion Matrix - {model_name.upper()}")
        cm_path = os.path.join(FIGURES_DIR, f"{model_name}_cm.png")
        plt.tight_layout()
        plt.savefig(cm_path, dpi=150)
        plt.close()
        print(f"Saved confusion matrix for {model_name} to {cm_path}")
        
        # 2. Save SHAP Summary plots for tree-based models
        if model_name in ("xgboost", "lightgbm", "random_forest"):
            print(f"Generating SHAP plots for {model_name}...")
            # Use a subsample of 100 test samples to keep speed reasonable
            subsample_size = min(100, X_test.shape[0])
            X_sub = X_test[:subsample_size]
            save_shap_summary_plot(X_sub, model_name)
            
    # Compile Results
    df_results = pd.DataFrame(results)
    
    # Save Metrics Table
    metrics_path = os.path.join(REPORTS_DIR, "metrics_table.csv")
    df_results.to_csv(metrics_path, index=False)
    print(f"Saved metrics table to {metrics_path}")
    
    # Print the table nicely in stdout
    print("\nBenchmark Evaluation Results:")
    print(df_results.to_string(index=False))
    
    plt.figure(figsize=(10, 5))
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#17becf', '#bcbd22']
    plt.bar(df_results['Model'], df_results['Accuracy'], color=colors[:len(df_results)])
    plt.ylabel('Accuracy')
    plt.title('Model Accuracy Comparison')
    plt.ylim(0.8, 1.02)
    for i, val in enumerate(df_results['Accuracy']):
        plt.text(i, val + 0.005, f"{val:.4f}", ha='center', va='bottom', fontweight='bold')
    acc_chart_path = os.path.join(FIGURES_DIR, "accuracy_comparison.png")
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.savefig(acc_chart_path, dpi=150)
    plt.close()
    print(f"Saved accuracy comparison bar chart to {acc_chart_path}")
    
    # 4. Save F1 Comparison Bar Chart
    plt.figure(figsize=(10, 5))
    plt.bar(df_results['Model'], df_results['F1'], color=colors[:len(df_results)])
    plt.ylabel('F1 Score')
    plt.title('Model F1 Score Comparison')
    plt.ylim(0.8, 1.02)
    for i, val in enumerate(df_results['F1']):
        plt.text(i, val + 0.005, f"{val:.4f}", ha='center', va='bottom', fontweight='bold')
    f1_chart_path = os.path.join(FIGURES_DIR, "f1_comparison.png")
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.savefig(f1_chart_path, dpi=150)
    plt.close()
    print(f"Saved F1 comparison bar chart to {f1_chart_path}")
    
    # 5. Save Radar Chart
    generate_radar_chart(df_results)
    
if __name__ == "__main__":
    main()
