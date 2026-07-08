"""
model_manager.py — Self-Healing Model Manager for AttackLayer.

Loads all four models (SVM, XGBoost, LightGBM, MLP) on import,
verifies SHA-256 integrity, and attempts automatic recovery from
a local backup registry if tampering is detected.

Public API
----------
get_model(name)         → return a single model instance (lazy-loads if needed)
get_active_models()     → list of model names that pass integrity
load_all_models()       → dict {name: model_instance}
reload_models_if_needed() → periodic health check
SimpleMLP               → re-exported so benchmark_models.py can import it
"""

import os
import logging
import torch
import joblib
from typing import Dict, Optional

from app.security.model_integrity import verify_model, generate_model_hashes

logger = logging.getLogger(__name__)

# ── paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")
# Local backup folder for self-healing; could be swapped for a remote URL
REGISTRY_DIR = os.path.join(BASE_DIR, "model_registry")

ALL_MODEL_NAMES = ["svm", "xgboost", "lightgbm", "mlp", "random_forest", "logistic_regression", "transformer_emb", "cnn_1d", "adaboost"]


# ── SimpleMLP definition (must match train_mlp.py) ──────────────────────
class SimpleMLP(torch.nn.Module):
    """Lightweight binary classifier matching the architecture in train_mlp.py."""

    def __init__(self, input_dim: int = 768, hidden_dim: int = 128, dropout_rate: float = 0.3):
        super().__init__()
        self.network = torch.nn.Sequential(
            torch.nn.Linear(input_dim, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.BatchNorm1d(hidden_dim),
            torch.nn.Dropout(dropout_rate),
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.BatchNorm1d(hidden_dim // 2),
            torch.nn.Dropout(dropout_rate),
            torch.nn.Linear(hidden_dim // 2, 2),
        )

    def forward(self, x):
        return self.network(x)


class TransformerClassifier(torch.nn.Module):
    """Lightweight Transformer classifier for embeddings."""

    def __init__(self, input_dim: int = 768, seq_len: int = 8, d_model: int = 64, nhead: int = 4, num_layers: int = 2, hidden_dim: int = 64, dropout_rate: float = 0.3):
        super().__init__()
        self.seq_len = seq_len
        self.d_model = d_model
        self.projection = torch.nn.Linear(input_dim, seq_len * d_model)
        
        encoder_layer = torch.nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=hidden_dim,
            dropout=dropout_rate,
            batch_first=True
        )
        self.transformer_encoder = torch.nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers
        )
        
        self.fc = torch.nn.Sequential(
            torch.nn.Linear(seq_len * d_model, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout_rate),
            torch.nn.Linear(hidden_dim, 2)
        )
        
    def forward(self, x):
        projected = self.projection(x)
        seq = projected.view(-1, self.seq_len, self.d_model)
        out = self.transformer_encoder(seq)
        out_flat = out.reshape(-1, self.seq_len * self.d_model)
        logits = self.fc(out_flat)
        return logits


class CNN1DClassifier(torch.nn.Module):
    """Lightweight 1D CNN classifier for embeddings."""

    def __init__(self, input_dim: int = 768, hidden_dim: int = 64, dropout_rate: float = 0.3):
        super().__init__()
        self.conv1 = torch.nn.Conv1d(in_channels=1, out_channels=16, kernel_size=5, stride=2, padding=2)
        self.bn1 = torch.nn.BatchNorm1d(16)
        self.pool = torch.nn.MaxPool1d(kernel_size=2, stride=2)
        
        self.conv2 = torch.nn.Conv1d(in_channels=16, out_channels=32, kernel_size=5, stride=2, padding=2)
        self.bn2 = torch.nn.BatchNorm1d(32)
        
        # 768 -> conv1 (stride 2) -> 384 -> pool (stride 2) -> 192 -> conv2 (stride 2) -> 96 -> pool (stride 2) -> 48
        # Output shape: 32 channels * 48 = 1536
        self.fc = torch.nn.Sequential(
            torch.nn.Linear(32 * 48, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout_rate),
            torch.nn.Linear(hidden_dim, 2)
        )
        
    def forward(self, x):
        x = x.unsqueeze(1) # (batch_size, 1, input_dim)
        x = self.pool(torch.nn.functional.relu(self.bn1(self.conv1(x))))
        x = self.pool(torch.nn.functional.relu(self.bn2(self.conv2(x))))
        x = x.view(x.size(0), -1)
        logits = self.fc(x)
        return logits


# ── Internal model cache ────────────────────────────────────────────────
_model_cache: Dict[str, object] = {}


# ── Loaders ─────────────────────────────────────────────────────────────
def _load_single_model(model_name: str):
    """Deserialize one model from disk and return the instance."""
    if model_name == "mlp":
        pth_path = os.path.join(MODELS_DIR, "mlp.pth")
        pt_path = os.path.join(MODELS_DIR, "mlp.pt")
        path = pth_path if os.path.exists(pth_path) else pt_path
        if not os.path.exists(path):
            raise FileNotFoundError(f"MLP model file not found at {pth_path} or {pt_path}")
        state = torch.load(path, map_location="cpu")
        first_weight = next(iter(state.values()))
        input_dim = first_weight.shape[1]
        model = SimpleMLP(input_dim=input_dim)
        model.load_state_dict(state)
        model.eval()
        return model
    elif model_name == "transformer_emb":
        pth_path = os.path.join(MODELS_DIR, "transformer_emb.pth")
        if not os.path.exists(pth_path):
            raise FileNotFoundError(f"Transformer model file not found at {pth_path}")
        state = torch.load(pth_path, map_location="cpu")
        model = TransformerClassifier()
        model.load_state_dict(state)
        model.eval()
        return model
    elif model_name == "cnn_1d":
        pth_path = os.path.join(MODELS_DIR, "cnn_1d.pth")
        if not os.path.exists(pth_path):
            raise FileNotFoundError(f"1D CNN model file not found at {pth_path}")
        state = torch.load(pth_path, map_location="cpu")
        model = CNN1DClassifier()
        model.load_state_dict(state)
        model.eval()
        return model
    else:
        pkl_path = os.path.join(MODELS_DIR, f"{model_name}.pkl")
        if not os.path.exists(pkl_path):
            raise FileNotFoundError(f"Model file not found: {pkl_path}")
        return joblib.load(pkl_path)


def _try_restore_from_backup(model_name: str):
    """Copy the backup model over the primary and reload."""
    ext = "pth" if model_name in ["mlp", "transformer_emb", "cnn_1d"] else "pkl"
    backup_path = os.path.join(REGISTRY_DIR, f"{model_name}.{ext}")
    if not os.path.exists(backup_path):
        raise FileNotFoundError(
            f"No backup found for {model_name} in {REGISTRY_DIR}"
        )
    os.makedirs(MODELS_DIR, exist_ok=True)
    dest_path = os.path.join(MODELS_DIR, f"{model_name}.{ext}")
    with open(backup_path, "rb") as src, open(dest_path, "wb") as dst:
        dst.write(src.read())
    logger.info("Restored %s from registry backup.", model_name)
    generate_model_hashes()
    return _load_single_model(model_name)


# ── Public API ──────────────────────────────────────────────────────────
def get_model(name: str) -> Optional[object]:
    """Return a model instance by name. Loads from cache or disk.

    If the model fails the integrity check and a backup exists in the
    registry, the manager will attempt automatic recovery.
    """
    if name in _model_cache:
        return _model_cache[name]

    try:
        if not verify_model(name):
            logger.warning("Integrity check FAILED for %s — attempting recovery.", name)
            model = _try_restore_from_backup(name)
        else:
            model = _load_single_model(name)
        _model_cache[name] = model
        return model
    except Exception as e:
        logger.error("Failed to load model %s: %s", name, e)
        return None


def get_active_models() -> list:
    """Return names of models that are currently loadable and healthy."""
    active = []
    for name in ALL_MODEL_NAMES:
        try:
            if verify_model(name):
                active.append(name)
            else:
                logger.warning("Model %s failed integrity check — excluded.", name)
        except Exception:
            continue
    return active


def load_all_models(active_models: list = None) -> Dict[str, object]:
    """Load (and cache) all requested models, verifying integrity first."""
    if active_models is None:
        active_models = list(ALL_MODEL_NAMES)
    models = {}
    for name in active_models:
        m = get_model(name)
        if m is not None:
            models[name] = m
    return models


def reload_models_if_needed():
    """Periodic health-check: reload any models that have gone bad."""
    healthy = get_active_models()
    unhealthy = set(ALL_MODEL_NAMES) - set(healthy)
    if unhealthy:
        logger.info("Unhealthy models detected: %s. Attempting recovery.", unhealthy)
        for name in unhealthy:
            try:
                _try_restore_from_backup(name)
            except Exception as e:
                logger.error("Recovery of %s failed: %s", name, e)
    else:
        logger.debug("All models passed integrity checks.")


def clear_cache():
    """Wipe the in-memory cache (useful for testing)."""
    _model_cache.clear()
