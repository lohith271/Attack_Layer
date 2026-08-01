import os
import joblib
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.calibration import CalibratedClassifierCV
from app.ml.utils import load_split_data

# Define PyTorch MLP
class PyTorchMLP(nn.Module):
    def __init__(self, input_dim, hidden_dim=128, dropout_rate=0.3):
        super(PyTorchMLP, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.Dropout(dropout_rate),
            nn.Linear(hidden_dim // 2, 2)  # Binary classification: logits for 0 and 1
        )
        
    def forward(self, x):
        return self.network(x)

def train_pytorch_mlp(X_train, y_train, X_val, y_val, input_dim):
    print("Training PyTorch MLP on CPU...")
    device = torch.device("cpu")
    
    # Use CPU explicitly
    batch_size = 64
    learning_rate = 0.005
    epochs = 10
    
    train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train))
    val_dataset = TensorDataset(torch.FloatTensor(X_val), torch.LongTensor(y_val))
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    
    model = PyTorchMLP(input_dim=input_dim).to(device)
    # Binary Cross Entropy or Cross Entropy Loss
    criterion = nn.CrossEntropyLoss()
    # Increase weight decay from 1e-4 to 1e-3 for better L2 regularization/bounds
    optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-3)
    
    best_val_loss = float('inf')
    patience = 10
    patience_counter = 0
    best_model_state = None
    
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            # Inject adversarial Gaussian noise during training for adversarial training
            noise = torch.randn_like(batch_x) * 0.05
            batch_x_noisy = batch_x + noise
            
            optimizer.zero_grad()
            outputs = model(batch_x_noisy)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)
            
        train_loss /= len(X_train)
        
        # Validation
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            val_x = torch.FloatTensor(X_val).to(device)
            val_y = torch.LongTensor(y_val).to(device)
            val_outputs = model(val_x)
            v_loss = criterion(val_outputs, val_y)
            val_loss = v_loss.item()
            
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            best_model_state = model.state_dict()
        else:
            patience_counter += 1
            
        if patience_counter >= patience:
            print(f"Early stopping at epoch {epoch+1}. Best validation loss: {best_val_loss:.4f}")
            break
            
    if best_model_state is not None:
        model.load_state_dict(best_model_state)
        
    return model

def main():
    print("--- Training MLP Models (Hardened) ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    # Augment training data with adversarial Gaussian noise to smooth boundary
    np.random.seed(42)
    noise_np = np.random.normal(0, 0.03, X_train.shape)
    X_train_aug = np.vstack([X_train, X_train + noise_np])
    y_train_aug = np.hstack([y_train, y_train])
    
    # 1. Scikit-learn MLP Classifier
    print("Fitting Scikit-learn MLPClassifier directly...")
    # Train directly with robust regularized default parameters
    best_estimator = MLPClassifier(
        hidden_layer_sizes=(128, 64),
        alpha=0.01,
        batch_size=64,
        random_state=42,
        max_iter=200,
        early_stopping=True
    )
    best_estimator.fit(X_train_aug, y_train_aug)
    
    print("Calibrating MLPClassifier...")
    calibrated_mlp_sk = CalibratedClassifierCV(estimator=best_estimator, cv=5)
    calibrated_mlp_sk.fit(X_train_aug, y_train_aug)
    
    # 2. PyTorch MLP
    pytorch_mlp = train_pytorch_mlp(X_train, y_train, X_val, y_val, X_train.shape[1])
    
    # Saving models
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    
    # Save scikit-learn model
    sklearn_model_path = os.path.join(models_dir, "mlp_sklearn.pkl")
    joblib.dump(calibrated_mlp_sk, sklearn_model_path)
    print(f"Sklearn MLP saved to {sklearn_model_path}")
    
    # Save PyTorch model
    pytorch_model_path = os.path.join(models_dir, "mlp.pth")
    torch.save(pytorch_mlp.state_dict(), pytorch_model_path)
    print(f"PyTorch MLP saved to {pytorch_model_path}")

if __name__ == "__main__":
    main()
