import { useState, useEffect } from "react";
import { getModelBenchmarks } from "../api/attacklayer";
import "../styles/model-performance.css";

const MODEL_DESCRIPTIONS = {
    SVM: "Support Vector Machine classifier optimized with a RBF kernel. Excellent high-dimensional boundary detection.",
    XGBOOST: "Extreme Gradient Boosting decision trees. Highly accurate, handling non-linear boundaries via parallel tree ensembles.",
    LIGHTGBM: "Light Gradient Boosting Machine. Fast and efficient tree-based classifier with leaf-wise tree growth.",
    MLP: "Multi-Layer Perceptron neural network. Deep representation learning for complex embedding structures.",
    RANDOM_FOREST: "Bagging ensemble of decision trees. Robust against noise and overfitting by averaging individual trees.",
    LOGISTIC_REGRESSION: "Linear model with L2 regularization. Highly interpretable baseline that establishes a linear decision boundary."
};

const MODEL_LABELS = {
    SVM: "SVM",
    XGBOOST: "XGBoost",
    LIGHTGBM: "LightGBM",
    MLP: "MLP Neural Net",
    RANDOM_FOREST: "Random Forest",
    LOGISTIC_REGRESSION: "Logistic Regression"
};

function ModelPerformancePage() {
    const [benchmarks, setBenchmarks] = useState([]);
    const [selectedModel, setSelectedModel] = useState("SVM");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        load();
    }, []);

    async function load() {
        try {
            setLoading(true);
            const data = await getModelBenchmarks();
            if (data && data.length > 0) {
                setBenchmarks(data);
                // Default to SVM or first available model
                const firstModel = data[0].Model || "SVM";
                setSelectedModel(firstModel);
            } else {
                setError("No benchmark data returned from server.");
            }
            setError("");
        } catch (err) {
            setError("Failed to fetch model benchmarks. Ensure the backend is running and that benchmark_models.py has been executed.");
        } finally {
            setLoading(false);
        }
    }

    if (loading) {
        return (
            <div className="perf-loading">
                <div className="spinner" />
                Loading Model Benchmarks…
            </div>
        );
    }

    if (error) {
        return (
            <div className="perf-error-container">
                <div className="perf-error-card">
                    <h2>Performance Dashboard Offline</h2>
                    <p>{error}</p>
                    <button onClick={load} className="retry-btn">Retry Loading</button>
                </div>
            </div>
        );
    }

    const currentData = benchmarks.find(b => b.Model === selectedModel) || benchmarks[0];
    
    // Confusion matrix values
    const tp = currentData?.TP || 0;
    const fp = currentData?.FP || 0;
    const tn = currentData?.TN || 0;
    const fn = currentData?.FN || 0;
    const totalSamples = tp + fp + tn + fn;
    
    const tpPercent = totalSamples > 0 ? ((tp / totalSamples) * 100).toFixed(1) : "0.0";
    const fpPercent = totalSamples > 0 ? ((fp / totalSamples) * 100).toFixed(1) : "0.0";
    const tnPercent = totalSamples > 0 ? ((tn / totalSamples) * 100).toFixed(1) : "0.0";
    const fnPercent = totalSamples > 0 ? ((fn / totalSamples) * 100).toFixed(1) : "0.0";

    const hasShap = ["XGBOOST", "LIGHTGBM", "RANDOM_FOREST"].includes(selectedModel);
    const shapUrl = `http://localhost:8000/static/figures/shap_summary_${selectedModel.toLowerCase()}.png`;
    const cmUrl = `http://localhost:8000/static/figures/${selectedModel.toLowerCase()}_cm.png`;

    return (
        <div className="performance-page">
            {/* Header */}
            <div className="page-header">
                <h1 className="page-title">Model Benchmarks & Performance</h1>
                <p className="page-subtitle">
                    Evaluation results and confusion matrices for the Multi-Model defense framework on the validation split.
                </p>
            </div>

            {/* Quick Cards Grid */}
            <div className="models-overview-grid">
                {benchmarks.map((b) => {
                    const isActive = b.Model === selectedModel;
                    return (
                        <div 
                            key={b.Model} 
                            className={`model-overview-card ${isActive ? "active" : ""}`}
                            onClick={() => setSelectedModel(b.Model)}
                        >
                            <div className="overview-header">
                                <h3>{MODEL_LABELS[b.Model] || b.Model}</h3>
                                <span className="status-badge healthy">Healthy</span>
                            </div>
                            <div className="overview-stats">
                                <div className="overview-stat">
                                    <span className="stat-label">Accuracy</span>
                                    <span className="stat-val">{(b.Accuracy * 100).toFixed(1)}%</span>
                                </div>
                                <div className="overview-stat">
                                    <span className="stat-label">F1-Score</span>
                                    <span className="stat-val">{b.F1.toFixed(3)}</span>
                                </div>
                                <div className="overview-stat">
                                    <span className="stat-label">FPR</span>
                                    <span className="stat-val">{(b.FPR * 100).toFixed(1)}%</span>
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Detailed Selection Section */}
            {currentData && (
                <div className="model-details-section">
                    <div className="details-card-header">
                        <h2>{MODEL_LABELS[selectedModel] || selectedModel} Model Profile</h2>
                        <p>{MODEL_DESCRIPTIONS[selectedModel] || ""}</p>
                    </div>

                    <div className="details-grid">
                        {/* Interactive Confusion Matrix and Metrics */}
                        <div className="details-col-left">
                            <div className="panel-box">
                                <h3 className="panel-title">Interactive Confusion Matrix</h3>
                                <p className="panel-desc">Visualizes model classification results. Green sections indicate correct decisions; red sections represent errors.</p>
                                
                                <div className="confusion-matrix-grid">
                                    {/* Y-axis Label */}
                                    <div className="cm-y-label">Actual Class</div>
                                    
                                    <div className="cm-wrapper">
                                        <div className="cm-headers">
                                            <div className="cm-header-label">Predicted Benign</div>
                                            <div className="cm-header-label">Predicted Attack</div>
                                        </div>
                                        <div className="cm-row">
                                            <div className="cm-row-label">Benign</div>
                                            {/* TN Box */}
                                            <div className="cm-cell cell-tn" title="True Negatives: Benign inputs correctly allowed.">
                                                <span className="cell-count">{tn}</span>
                                                <span className="cell-pct">{tnPercent}%</span>
                                                <span className="cell-label">True Negative (TN)</span>
                                            </div>
                                            {/* FP Box */}
                                            <div className="cm-cell cell-fp" title="False Positives: Benign inputs incorrectly blocked (False Alarms).">
                                                <span className="cell-count">{fp}</span>
                                                <span className="cell-pct">{fpPercent}%</span>
                                                <span className="cell-label">False Positive (FP)</span>
                                            </div>
                                        </div>
                                        <div className="cm-row">
                                            <div className="cm-row-label">Attack</div>
                                            {/* FN Box */}
                                            <div className="cm-cell cell-fn" title="False Negatives: Attack inputs missed by the model.">
                                                <span className="cell-count">{fn}</span>
                                                <span className="cell-pct">{fnPercent}%</span>
                                                <span className="cell-label">False Negative (FN)</span>
                                            </div>
                                            {/* TP Box */}
                                            <div className="cm-cell cell-tp" title="True Positives: Attack inputs correctly identified and blocked.">
                                                <span className="cell-count">{tp}</span>
                                                <span className="cell-pct">{tpPercent}%</span>
                                                <span className="cell-label">True Positive (TP)</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Detailed Metrics */}
                            <div className="metrics-cards-grid">
                                <div className="metric-card">
                                    <div className="metric-icon">🎯</div>
                                    <div className="metric-num">{(currentData.Accuracy * 100).toFixed(2)}%</div>
                                    <div className="metric-name">Accuracy</div>
                                    <div className="metric-info">Overall proportion of correct classifications (TP + TN) / Total.</div>
                                </div>
                                <div className="metric-card">
                                    <div className="metric-icon">🛡️</div>
                                    <div className="metric-num">{(currentData.Precision * 100).toFixed(2)}%</div>
                                    <div className="metric-name">Precision</div>
                                    <div className="metric-info">Proportion of flagged items that were actual attacks. High precision means low false alarms.</div>
                                </div>
                                <div className="metric-card">
                                    <div className="metric-icon">🔍</div>
                                    <div className="metric-num">{(currentData.Recall * 100).toFixed(2)}%</div>
                                    <div className="metric-name">Recall / DR</div>
                                    <div className="metric-info">Proportion of total attacks detected (Detection Rate). High recall means low missed attacks.</div>
                                </div>
                                <div className="metric-card">
                                    <div className="metric-icon">⚖️</div>
                                    <div className="metric-num">{currentData.F1.toFixed(4)}</div>
                                    <div className="metric-name">F1-Score</div>
                                    <div className="metric-info">Harmonic mean of Precision and Recall. Best indicator of overall balanced performance.</div>
                                </div>
                                <div className="metric-card danger">
                                    <div className="metric-icon">⚠️</div>
                                    <div className="metric-num">{(currentData.FPR * 100).toFixed(2)}%</div>
                                    <div className="metric-name">False Positive Rate</div>
                                    <div className="metric-info">Proportion of benign inputs incorrectly blocked. Lower is better.</div>
                                </div>
                                <div className="metric-card info">
                                    <div className="metric-icon">📥</div>
                                    <div className="metric-num">{totalSamples}</div>
                                    <div className="metric-name">Total Samples</div>
                                    <div className="metric-info">Total validation samples evaluated from the stratified holdout split.</div>
                                </div>
                            </div>
                        </div>

                        {/* Explainability / SHAP / ROC */}
                        <div className="details-col-right">
                            <div className="panel-box">
                                <h3 className="panel-title">Model Interpretation & Explainability</h3>
                                <p className="panel-desc">
                                    {hasShap 
                                        ? "SHAP (SHapley Additive exPlanations) values outline which dimensions of the 768-dim input embedding vector drive the model towards classifying inputs as attacks."
                                        : "Confusion matrix heatmap generated directly during python training and validation evaluation."
                                    }
                                </p>
                                
                                <div className="explainability-plot-wrap">
                                    {hasShap ? (
                                        <img 
                                            src={shapUrl} 
                                            alt={`${selectedModel} SHAP Summary`} 
                                            className="explainability-image"
                                            onError={(e) => {
                                                e.target.onerror = null;
                                                e.target.src = cmUrl; // Fallback to confusion matrix plot
                                            }}
                                        />
                                    ) : (
                                        <img 
                                            src={cmUrl} 
                                            alt={`${selectedModel} Confusion Matrix Heatmap`} 
                                            className="explainability-image"
                                        />
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Global Visualizations */}
            <div className="global-visualizations-section">
                <h2>Cross-Model Comparison Dashboard</h2>
                <p>Compare the multi-model defense metrics across models using ROC Curves and Radar/Metric chart alignments.</p>
                
                <div className="global-plots-grid">
                    <div className="global-plot-card">
                        <h3>ROC Curves comparison</h3>
                        <p>Receiver Operating Characteristic curves. A higher Area Under Curve (AUC) indicates a more capable model at separating attacks from benign prompts.</p>
                        <div className="plot-img-container">
                            <img src="http://localhost:8000/static/figures/roc_curves.png" alt="ROC Curves Comparison" />
                        </div>
                    </div>

                    <div className="global-plot-card">
                        <h3>Radar Metric Distribution</h3>
                        <p>Visualizes overall performance profile across Accuracy, Precision, Recall, F1, and FPR simultaneously. Models covering larger areas perform better.</p>
                        <div className="plot-img-container">
                            <img src="http://localhost:8000/static/figures/radar_chart.png" alt="Radar Chart Comparison" />
                        </div>
                    </div>

                    <div className="global-plot-card">
                        <h3>Accuracy Comparison Chart</h3>
                        <p>Visualizes model accuracy scores on the holdout validation split.</p>
                        <div className="plot-img-container">
                            <img src="http://localhost:8000/static/figures/accuracy_comparison.png" alt="Accuracy Comparison" />
                        </div>
                    </div>

                    <div className="global-plot-card">
                        <h3>F1-Score Comparison Chart</h3>
                        <p>Visualizes model F1-Score metrics showing balanced performance.</p>
                        <div className="plot-img-container">
                            <img src="http://localhost:8000/static/figures/f1_comparison.png" alt="F1-Score Comparison" />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default ModelPerformancePage;
