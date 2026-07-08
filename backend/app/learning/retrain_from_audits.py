import os
import sys
import numpy as np
import pandas as pd
import ollama
from sqlalchemy.orm import Session

# Add the parent directory of backend/app to path to allow import of app
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.database.session import SessionLocal
from app.database.models import AuditEvent
from app.ml.train.train_all import main as retrain_all_models
from app.training.benchmark_models import main as run_benchmarks

# Configuration
EMBED_MODEL = "nomic-embed-text"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

def extract_and_embed_blocked_messages():
    print("--- STEP 1: CONNECTING TO DB AND EXTRACTING BLOCKED MESSAGES ---")
    db: Session = SessionLocal()
    try:
        # Query unique blocked prompts from AuditEvent table
        # We look for final_decision == "BLOCK" or decision == "BLOCK"
        events = db.query(AuditEvent).filter(
            (AuditEvent.final_decision == "BLOCK") | (AuditEvent.decision == "BLOCK")
        ).all()
        
        blocked_prompts = list(set([e.payload.strip() for e in events if e.payload and e.payload.strip()]))
        print(f"Found {len(events)} blocked events in audit logs, corresponding to {len(blocked_prompts)} unique prompts.")
        
        if not blocked_prompts:
            print("No blocked prompts found to process.")
            return False

        # Load existing dataset if available
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_dir = os.path.join(base_dir, "data")
        
        # Load the CSV file to check for existing prompts to avoid double counting
        csv_path = os.path.join(data_dir, "ml_dataset.csv")
        existing_texts = set()
        df_csv = pd.DataFrame()
        if os.path.exists(csv_path):
            df_csv = pd.read_csv(csv_path)
            if "text" in df_csv.columns:
                existing_texts = set(df_csv["text"].dropna().str.strip().tolist())
                
        # Filter new prompts
        new_prompts = [p for p in blocked_prompts if p not in existing_texts]
        print(f"Out of {len(blocked_prompts)} blocked prompts, {len(new_prompts)} are new (not already in the dataset).")
        
        if not new_prompts:
            print("All blocked prompts are already present in the training dataset.")
            return False

        # --- Generate embeddings using Ollama ---
        print(f"\n--- STEP 2: GENERATING EMBEDDINGS FOR {len(new_prompts)} NEW PROMPTS ---")
        print(f"Using model: {EMBED_MODEL} via Ollama ({OLLAMA_BASE_URL})...")
        client = ollama.Client(host=OLLAMA_BASE_URL)
        
        # Verify model exists
        try:
            client.show(EMBED_MODEL)
        except Exception:
            print(f"Error: Model '{EMBED_MODEL}' is not available in Ollama.")
            print(f"Please run 'ollama pull {EMBED_MODEL}' in your terminal first.")
            return False
            
        new_embeddings = []
        successful_prompts = []
        
        for idx, prompt in enumerate(new_prompts):
            try:
                response = client.embeddings(model=EMBED_MODEL, prompt=prompt)
                new_embeddings.append(response["embedding"])
                successful_prompts.append(prompt)
            except Exception as e:
                print(f"Failed to generate embedding for prompt index {idx}: {e}")
                
        if not new_embeddings:
            print("Failed to generate any embeddings. Aborting.")
            return False
            
        print(f"Successfully generated {len(new_embeddings)} new embeddings.")
        
        # --- Update embeddings.npy and labels.npy ---
        print("\n--- STEP 3: UPDATING THE DATA FILES ---")
        emb_path = os.path.join(data_dir, "embeddings.npy")
        lbl_path = os.path.join(data_dir, "labels.npy")
        
        if os.path.exists(emb_path) and os.path.exists(lbl_path):
            X_existing = np.load(emb_path)
            y_existing = np.load(lbl_path)
            
            X_new = np.array(new_embeddings, dtype=np.float64)
            y_new = np.ones(len(new_embeddings), dtype=np.int64) # 1 represents attack
            
            X_updated = np.vstack([X_existing, X_new])
            y_updated = np.concatenate([y_existing, y_new])
        else:
            X_updated = np.array(new_embeddings, dtype=np.float64)
            y_updated = np.ones(len(new_embeddings), dtype=np.int64)
            
        np.save(emb_path, X_updated)
        np.save(lbl_path, y_updated)
        print(f"Saved updated embeddings to {emb_path} (Shape: {X_updated.shape})")
        print(f"Saved updated labels to {lbl_path} (Shape: {y_updated.shape})")
        
        # --- Update ml_dataset.csv ---
        new_rows = pd.DataFrame({"text": successful_prompts, "label": [1] * len(successful_prompts)})
        if not df_csv.empty:
            df_csv = pd.concat([df_csv, new_rows], ignore_index=True)
        else:
            df_csv = new_rows
            
        df_csv.to_csv(csv_path, index=False)
        print(f"Appended new prompts to {csv_path} (Total rows: {len(df_csv)})")
        return True
    finally:
        db.close()

def main():
    updated = extract_and_embed_blocked_messages()
    if updated:
        print("\n--- STEP 4: TRIGGERING RETRAINING OF ALL CLASSIFIERS ---")
        retrain_all_models()
        print("\n--- STEP 5: RUNNING BENCHMARKS & UPDATING FIGURES ---")
        run_benchmarks()
        print("\n--- RETRAINING, DEPLOYMENT, AND METRICS UPDATE COMPLETE ---")
    else:
        print("\nDataset was not updated. Retraining is not necessary.")

if __name__ == "__main__":
    main()
