import os
import numpy as np
import pandas as pd
import ollama
from datasets import load_dataset

# Configuration
DATASET_NAME = "JasperLS/prompt-injections"
EMBED_MODEL = "nomic-embed-text"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Output paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
EMB_PATH = os.path.join(DATA_DIR, "embeddings.npy")
LBL_PATH = os.path.join(DATA_DIR, "labels.npy")

def main():
    print(f"1. Downloading dataset '{DATASET_NAME}' from Hugging Face...")
    try:
        # Load all splits (e.g. train, test) and concatenate them
        dataset = load_dataset(DATASET_NAME)
        dfs = []
        for split in dataset.keys():
            dfs.append(dataset[split].to_pandas())
        df = pd.concat(dfs, ignore_index=True)
        print(f"Successfully downloaded. Total rows: {len(df)}")
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        return

    # Check for required columns
    if "text" not in df.columns or "label" not in df.columns:
        print("Error: The dataset does not contain 'text' and 'label' columns.")
        print(f"Available columns: {list(df.columns)}")
        return

    print(f"2. Connecting to Ollama at {OLLAMA_BASE_URL}...")
    client = ollama.Client(host=OLLAMA_BASE_URL)
    
    # Verify the embedding model is available
    try:
        client.show(EMBED_MODEL)
    except Exception:
        print(f"Error: Model '{EMBED_MODEL}' not found in Ollama.")
        print(f"Please run 'ollama pull {EMBED_MODEL}' in your terminal first.")
        return

    embeddings = []
    labels = []

    print(f"3. Generating embeddings using '{EMBED_MODEL}'...")
    for idx, row in df.iterrows():
        text = str(row["text"]).strip()
        label = int(row["label"])
        
        if not text:
            continue
            
        try:
            response = client.embeddings(
                model=EMBED_MODEL,
                prompt=text
            )
            embeddings.append(response["embedding"])
            labels.append(label)
        except Exception as e:
            print(f"Error generating embedding at index {idx}: {e}")
            continue
            
        if (idx + 1) % 50 == 0 or (idx + 1) == len(df):
            print(f"Processed {idx + 1}/{len(df)} samples...")

    # Convert to numpy arrays
    X = np.array(embeddings, dtype=np.float64)
    y = np.array(labels, dtype=np.int64)

    # Save outputs
    print(f"4. Saving embeddings and labels to {DATA_DIR}...")
    os.makedirs(DATA_DIR, exist_ok=True)
    np.save(EMB_PATH, X)
    np.save(LBL_PATH, y)

    print("\n--- Data Preparation Complete ---")
    print(f"Embeddings shape: {X.shape} -> Saved to {EMB_PATH}")
    print(f"Labels shape:     {y.shape} -> Saved to {LBL_PATH}")
    print("\nNow you can proceed to run the training and hash generation scripts!")

if __name__ == "__main__":
    main()