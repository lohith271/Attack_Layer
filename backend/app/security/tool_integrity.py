# backend/app/security/tool_integrity.py
import json
import hashlib
import os

class ToolIntegrityManager:
    """
    Manages cryptographic hashes of human-approved tool schemas to detect 'rug pull' changes.
    """
    def __init__(self, registry_path: str = None):
        if registry_path is None:
            # Save registry file relative to this file or backend root
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.registry_path = os.path.join(base_dir, "data", "tool_registry_hashes.json")
        else:
            self.registry_path = registry_path
            
        self._ensure_registry_dir()
        self.pinned_hashes = self._load_registry()

    def _ensure_registry_dir(self):
        dir_name = os.path.dirname(self.registry_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

    def _load_registry(self) -> dict:
        if not os.path.exists(self.registry_path):
            return {}
        try:
            with open(self.registry_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_registry(self):
        try:
            with open(self.registry_path, "w", encoding="utf-8") as f:
                json.dump(self.pinned_hashes, f, indent=4, sort_keys=True)
        except Exception:
            pass

    def compute_schema_hash(self, tool_schema: dict) -> str:
        """
        Computes the SHA-256 hash of a tool schema with keys sorted to ensure deterministic hashing.
        """
        if not tool_schema:
            return ""
        # Convert schema dict to a canonical string representation
        schema_str = json.dumps(tool_schema, sort_keys=True)
        return hashlib.sha256(schema_str.encode("utf-8")).hexdigest()

    def pin_tool_schema(self, tool_name: str, tool_schema: dict) -> str:
        """
        Calculates and stores the schema hash for a given tool.
        """
        schema_hash = self.compute_schema_hash(tool_schema)
        if schema_hash:
            self.pinned_hashes[tool_name] = schema_hash
            self._save_registry()
        return schema_hash

    def verify_tool_schema(self, tool_name: str, live_schema: dict) -> bool:
        """
        Compares the live schema hash against the pinned hash.
        Returns True if matched, False if mismatch or tool is not pinned.
        """
        pinned_hash = self.pinned_hashes.get(tool_name)
        if not pinned_hash:
            # Unregistered tools fail verification by default
            return False
        live_hash = self.compute_schema_hash(live_schema)
        return live_hash == pinned_hash
