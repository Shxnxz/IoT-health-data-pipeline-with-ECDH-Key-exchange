# keystore.py  —  file-backed key store so producer and consumer share keys
import json
import time
import os

STORE_FILE    = "keystore.json"
KEY_TTL_SECS  = 300

class KeyStore:
    def _load(self) -> dict:
        if not os.path.exists(STORE_FILE):
            return {}
        with open(STORE_FILE, "r") as f:
            return json.load(f)

    def _save(self, store: dict):
        with open(STORE_FILE, "w") as f:
            json.dump(store, f)

    def put(self, device_id: str, aes_key: bytes):
        store = self._load()
        store[device_id] = {
            "key":        aes_key.hex(),       # bytes → hex string for JSON
            "created_at": time.time(),
            "msg_count":  0,
        }
        self._save(store)
        print(f"[keystore] saved key for {device_id}")

    def get(self, device_id: str) -> bytes | None:
        store = self._load()
        entry = store.get(device_id)
        if entry is None:
            return None

        if time.time() - entry["created_at"] > KEY_TTL_SECS:
            self.revoke(device_id)
            return None

        entry["msg_count"] += 1
        self._save(store)
        return bytes.fromhex(entry["key"])     # hex string → bytes

    def is_expired(self, device_id: str) -> bool:
        store = self._load()
        entry = store.get(device_id)
        if entry is None:
            return True
        return time.time() - entry["created_at"] > KEY_TTL_SECS

    def revoke(self, device_id: str):
        store = self._load()
        store.pop(device_id, None)
        self._save(store)
        print(f"[keystore] revoked key for {device_id}")