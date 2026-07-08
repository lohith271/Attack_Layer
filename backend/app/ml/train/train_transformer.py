import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from app.ml.utils import load_split_data
from app.ml.model_manager import TransformerClassifier

def train_transformer(X_train, y_train, X_val, y_val):
    print("Training PyTorch Transformer on CPU...")
    device = torch.device("cpu")
    
    batch_size = 64
    learning_rate = 0.001
    epochs = 100
    
    train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train))
    val_dataset = TensorDataset(torch.FloatTensor(X_val), torch.LongTensor(y_val))
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    
    model = TransformerClassifier().to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    
    best_val_loss = float('inf')
    patience = 10
    patience_counter = 0
    best_model_state = None
    
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()
            outputs = model(batch_x)
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
    print("--- Training Transformer Model ---")
    X_train, X_val, X_test, y_train, y_val, y_test = load_split_data()
    
    model = train_transformer(X_train, y_train, X_val, y_val)
    
    models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, "transformer_emb.pth")
    torch.save(model.state_dict(), model_path)
    print(f"Transformer model saved to {model_path}")

if __name__ == "__main__":
    main()
