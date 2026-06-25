import os
import ollama

EMBED_MODEL = "nomic-embed-text"

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434"
)

client = ollama.Client(host=OLLAMA_BASE_URL)

_cache = {}

def generate_embedding(text: str):
    if text not in _cache:
        response = client.embeddings(
            model=EMBED_MODEL,
            prompt=text
        )
        _cache[text] = response["embedding"]

    return _cache[text]