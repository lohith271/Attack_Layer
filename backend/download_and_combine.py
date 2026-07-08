import os
import numpy as np
import pandas as pd
import ollama
from datasets import load_dataset

# Configuration
EMBED_MODEL = "nomic-embed-text"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Output directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
EMB_PATH = os.path.join(DATA_DIR, "embeddings.npy")
LBL_PATH = os.path.join(DATA_DIR, "labels.npy")

def get_text_col(df):
    for col in ["text", "prompt", "statement", "query"]:
        if col in df.columns:
            return col
    return None

def main():
    print("--- STEP 1: DOWNLOADING AND PARSING DATASETS ---")
    benign_list = []
    attack_list = []
    
    # 1. LLM-LAT/benign-dataset
    print("\nLoading LLM-LAT/benign-dataset...")
    try:
        ds = load_dataset("LLM-LAT/benign-dataset")
        df = ds["train"].to_pandas()
        text_col = get_text_col(df)
        if text_col:
            sampled = df[text_col].dropna().sample(n=min(3000, len(df)), random_state=42).tolist()
            benign_list.extend(sampled)
            print(f"Added {len(sampled)} benign samples.")
    except Exception as e:
        print(f"Failed to load LLM-LAT/benign-dataset: {e}")

    # 2. efgmarquez/jailbreak_dataset
    print("\nLoading efgmarquez/jailbreak_dataset...")
    try:
        ds = load_dataset("efgmarquez/jailbreak_dataset")
        df = ds["train"].to_pandas()
        text_col = get_text_col(df)
        if text_col:
            sampled = df[text_col].dropna().sample(n=min(1500, len(df)), random_state=42).tolist()
            attack_list.extend(sampled)
            print(f"Added {len(sampled)} attack samples.")
    except Exception as e:
        print(f"Failed to load efgmarquez/jailbreak_dataset: {e}")

    # 3. jackhhao/jailbreak-classification
    print("\nLoading jackhhao/jailbreak-classification...")
    try:
        ds = load_dataset("jackhhao/jailbreak-classification")
        split = "train" if "train" in ds.keys() else list(ds.keys())[0]
        df = ds[split].to_pandas()
        text_col = get_text_col(df)
        label_col = "label" if "label" in df.columns else None
        if text_col and label_col:
            for _, row in df.iterrows():
                txt = str(row[text_col]).strip()
                lbl = row[label_col]
                if str(lbl).lower() in ["benign", "safe", "0"]:
                    benign_list.append(txt)
                elif str(lbl).lower() in ["jailbreak", "attack", "unsafe", "1"]:
                    attack_list.append(txt)
            print(f"Processed mixed samples from jackhhao/jailbreak-classification.")
    except Exception as e:
        print(f"Failed to load jackhhao/jailbreak-classification: {e}")

    # 4. rubend18/ChatGPT-Jailbreak-Prompts
    print("\nLoading rubend18/ChatGPT-Jailbreak-Prompts...")
    try:
        ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts")
        split = "train" if "train" in ds.keys() else list(ds.keys())[0]
        df = ds[split].to_pandas()
        text_col = get_text_col(df)
        if text_col:
            sampled = df[text_col].dropna().tolist()
            attack_list.extend(sampled)
            print(f"Added {len(sampled)} attack samples.")
    except Exception as e:
        print(f"Failed to load rubend18/ChatGPT-Jailbreak-Prompts: {e}")

    # 5. reshabhs/SPML_Chatbot_Prompt_Injection
    print("\nLoading reshabhs/SPML_Chatbot_Prompt_Injection...")
    try:
        ds = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection")
        split = "train" if "train" in ds.keys() else list(ds.keys())[0]
        df = ds[split].to_pandas()
        text_col = get_text_col(df)
        label_col = "label" if "label" in df.columns else None
        if text_col and label_col:
            sampled_df = df.sample(n=min(1500, len(df)), random_state=42)
            for _, row in sampled_df.iterrows():
                txt = str(row[text_col]).strip()
                lbl = row[label_col]
                if str(lbl) == "0" or str(lbl).lower() in ["benign", "safe"]:
                    benign_list.append(txt)
                else:
                    attack_list.append(txt)
            print(f"Processed mixed samples from reshabhs/SPML_Chatbot_Prompt_Injection.")
    except Exception as e:
        print(f"Failed to load reshabhs/SPML_Chatbot_Prompt_Injection: {e}")

    # 6. imoxto/prompt_injection_cleaned_dataset-v2
    print("\nLoading imoxto/prompt_injection_cleaned_dataset-v2...")
    try:
        ds = load_dataset("imoxto/prompt_injection_cleaned_dataset-v2")
        split = "train" if "train" in ds.keys() else list(ds.keys())[0]
        df = ds[split].to_pandas()
        text_col = get_text_col(df)
        label_col = "label" if "label" in df.columns else None
        if text_col and label_col:
            sampled_df = df.sample(n=min(2000, len(df)), random_state=42)
            for _, row in sampled_df.iterrows():
                txt = str(row[text_col]).strip()
                lbl = row[label_col]
                if str(lbl) == "0" or str(lbl).lower() in ["benign", "safe"]:
                    benign_list.append(txt)
                else:
                    attack_list.append(txt)
            print(f"Processed mixed samples from imoxto/prompt_injection_cleaned_dataset-v2.")
    except Exception as e:
        print(f"Failed to load imoxto/prompt_injection_cleaned_dataset-v2: {e}")

    # 7. JasperLS/prompt-injections
    print("\nLoading JasperLS/prompt-injections...")
    try:
        ds = load_dataset("JasperLS/prompt-injections")
        dfs = []
        for split in ds.keys():
            dfs.append(ds[split].to_pandas())
        df = pd.concat(dfs, ignore_index=True)
        text_col = get_text_col(df)
        label_col = "label" if "label" in df.columns else None
        if text_col and label_col:
            for _, row in df.iterrows():
                txt = str(row[text_col]).strip()
                lbl = row[label_col]
                if str(lbl) == "0" or str(lbl).lower() in ["benign", "safe"]:
                    benign_list.append(txt)
                else:
                    attack_list.append(txt)
            print(f"Processed mixed samples from JasperLS/prompt-injections.")
    except Exception as e:
        print(f"Failed to load JasperLS/prompt-injections: {e}")

    benign_list = list(set(benign_list))
    attack_list = list(set(attack_list))
    
    print("\n--- Summary of Loaded Data ---")
    print(f"Total Unique Benign Prompts: {len(benign_list)}")
    print(f"Total Unique Attack Prompts: {len(attack_list)}")
    
    # Balancing to make class weights 50-50
    target_size = min(len(benign_list), len(attack_list))
    target_size = min(4000, target_size) # Cap to 4,000 for local embedding generation speed
    
    print(f"Balancing dataset to {target_size} samples per class...")
    balanced_benign = pd.Series(benign_list).sample(n=target_size, random_state=42).tolist()
    balanced_attack = pd.Series(attack_list).sample(n=target_size, random_state=42).tolist()
    
    final_prompts = balanced_benign + balanced_attack
    final_labels = [0] * target_size + [1] * target_size
    
    combined_df = pd.DataFrame({"text": final_prompts, "label": final_labels})
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # --- STEP 2: EMBEDDING GENERATION ---
    print("\n--- STEP 2: GENERATING EMBEDDINGS VIA OLLAMA ---")
    client = ollama.Client(host=OLLAMA_BASE_URL)
    
    embeddings = []
    labels = []
    total_samples = len(combined_df)
    
    for idx, row in combined_df.iterrows():
        text = str(row["text"]).strip()
        label = int(row["label"])
        if not text:
            continue
        try:
            response = client.embeddings(model=EMBED_MODEL, prompt=text)
            embeddings.append(response["embedding"])
            labels.append(label)
        except Exception as e:
            print(f"Error at index {idx}: {e}")
            continue
            
        if (idx + 1) % 100 == 0 or (idx + 1) == total_samples:
            print(f"Generated embeddings for {idx + 1}/{total_samples} samples...")

    X = np.array(embeddings, dtype=np.float64)
    y = np.array(labels, dtype=np.int64)

    os.makedirs(DATA_DIR, exist_ok=True)
    np.save(EMB_PATH, X)
    np.save(LBL_PATH, y)

    print("\n--- Data Preparation Complete ---")
    print(f"Final Embeddings shape: {X.shape} -> Saved to {EMB_PATH}")
    print(f"Final Labels shape:     {y.shape} -> Saved to {LBL_PATH}")

if __name__ == "__main__":
    main()