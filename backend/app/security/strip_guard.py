"""
strip_guard.py — STRIP Runtime Backdoor Guard for 768D Embeddings in AttackLayer.

Implements online query screening by blending incoming embeddings with random
clean embeddings and computing prediction entropy. Backdoor inputs carrying
triggers will exhibit stubbornly low entropy predictions.
"""

import os
import logging
import numpy as np
import torch
import torch.nn.functional as F
from app.ml.model_manager import get_model

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


class StripGuard:
    """STRIP (STRong Intentional Perturbation) runtime query defender."""
    
    def __init__(self, model_name: str = "mlp", num_blends: int = 50, 
                 alpha: float = 0.5, default_threshold: float = 0.45):
        self.model_name = model_name
        self.num_blends = num_blends
        self.alpha = alpha
        self.threshold = default_threshold
        self.blend_pool = self._load_blend_pool()
        
    def _load_blend_pool(self) -> np.ndarray:
        """Loads clean benign embeddings to use as the blending pool."""
        emb_path = os.path.join(DATA_DIR, "embeddings.npy")
        lbl_path = os.path.join(DATA_DIR, "labels.npy")
        
        # Default fallback if files do not exist
        fallback_pool = np.random.normal(0.0, 1.0, (100, 768)).astype(np.float32)
        
        if os.path.exists(emb_path) and os.path.exists(lbl_path):
            try:
                X = np.load(emb_path)
                y = np.load(lbl_path)
                # Keep only benign samples (label == 0) for blending
                benign_X = X[y == 0]
                if len(benign_X) > 0:
                    logger.info("STRIP blend pool loaded: %d clean samples.", len(benign_X))
                    return benign_X.astype(np.float32)
            except Exception as e:
                logger.warning("Failed to load embeddings for STRIP blend pool: %s", e)
                
        logger.info("STRIP: Using fallback random blend pool.")
        return fallback_pool
        
    def calculate_entropy(self, embedding: np.ndarray) -> float:
        """
        Blend embedding with N random samples and compute average prediction entropy.
        """
        model = get_model(self.model_name)
        if model is None:
            # If model isn't available, fail-safe (neutral entropy)
            return 1.0
            
        # Draw random blend samples
        rng = np.random.RandomState(42)
        indices = rng.choice(len(self.blend_pool), size=self.num_blends, replace=True)
        blend_samples = self.blend_pool[indices]
        
        # x_blend = (1 - alpha)*x + alpha*x_i
        # Ensure 2D shape for operation
        x = embedding.reshape(1, -1)
        blended = (1.0 - self.alpha) * x + self.alpha * blend_samples
        
        # Get predictions
        if self.model_name in ["mlp", "transformer_emb", "cnn_1d"]:
            # PyTorch models
            try:
                model.eval()
                with torch.no_grad():
                    tensor_in = torch.FloatTensor(blended)
                    logits = model(tensor_in)
                    probs = F.softmax(logits, dim=1).numpy()
            except Exception as e:
                logger.error("STRIP model eval error: %s", e)
                return 1.0
        else:
            # Sklearn models
            if hasattr(model, "predict_proba"):
                try:
                    probs = model.predict_proba(blended)
                except Exception as e:
                    logger.error("STRIP sklearn predict error: %s", e)
                    return 1.0
            else:
                # Fallback to binary distribution if predict_proba is not present
                try:
                    preds = model.predict(blended)
                    probs = np.zeros((len(preds), 2))
                    for i, p in enumerate(preds):
                        probs[i, int(p)] = 1.0
                except Exception:
                    return 1.0
                    
        # Compute entropy per blend: -sum(p * log2(p + eps))
        eps = 1e-12
        entropy_per_sample = -np.sum(probs * np.log2(probs + eps), axis=1)
        mean_entropy = float(np.mean(entropy_per_sample))
        
        return mean_entropy
        
    def calibrate_threshold(self, clean_embeddings: np.ndarray, std_multiplier: float = 2.0):
        """
        Calibrate the safety threshold using a set of clean validation embeddings.
        Threshold is set as: mean(clean_entropy) - std_multiplier * std(clean_entropy)
        """
        entropies = [self.calculate_entropy(emb) for emb in clean_embeddings]
        mean_ent = np.mean(entropies)
        std_ent = np.std(entropies)
        self.threshold = float(mean_ent - std_multiplier * std_ent)
        logger.info("STRIP calibrated: mean=%.4f, std=%.4f, threshold=%.4f", 
                    mean_ent, std_ent, self.threshold)
        return self.threshold
        
    def is_safe(self, embedding: np.ndarray) -> bool:
        """
        Evaluate if an embedding is safe. Returns False if prediction entropy
        falls below the calibrated threshold (indicating a backdoor trigger).
        """
        entropy = self.calculate_entropy(embedding)
        if entropy < self.threshold:
            logger.warning("STRIP Guard triggered! Query entropy (%.4f) below threshold (%.4f)",
                           entropy, self.threshold)
            return False
        return True
