# test_encrypt.py  —  confirm the round-trip works before wiring into Kafka
from encrypt import encrypt_payload, decrypt_payload
from cryptography.exceptions import InvalidTag

# Simulate the AES key from your completed ECDH handshake
import os
aes_key = os.urandom(32)   # replace with device_aes_key in real flow

payload = {
    "device_id": "WRB-4A2F9C",
    "timestamp": "2026-05-14T10:00:00Z",
    "hrv":  {"rmssd_ms": 54.3, "sdnn_ms": 72.1, "lf_hf_ratio": 1.4,
             "pnn50_pct": 22.5, "status": "normal"},
    "rhr":  {"bpm": 61, "avg_7d_bpm": 63, "trend": "stable"},
    "sleep": {"total_duration_min": 432, "efficiency_pct": 89.2,
              "stages_pct": {"awake": 8, "rem": 20, "light": 45, "deep": 27},
              "current_stage": "deep", "interruptions": 2},
    "battery_pct": 78,
    "signal_quality": "good",
}

# ── Encrypt ───────────────────────────────────────────────────────────────────
nonce, ciphertext, tag = encrypt_payload(payload, aes_key)

print(f"nonce:      {nonce.hex()}  ({len(nonce)} bytes)")
print(f"ciphertext: {ciphertext.hex()[:48]}...  ({len(ciphertext)} bytes)")
print(f"tag:        {tag.hex()}  ({len(tag)} bytes)")

# ── Decrypt ───────────────────────────────────────────────────────────────────
recovered = decrypt_payload(nonce, ciphertext, tag, aes_key)
assert recovered["device_id"] == payload["device_id"]
print(f"\nDecrypted OK — device_id: {recovered['device_id']}")

# ── Tamper test ───────────────────────────────────────────────────────────────
corrupted = bytearray(ciphertext)
corrupted[0] ^= 0xFF   # flip one bit

try:
    decrypt_payload(nonce, bytes(corrupted), tag, aes_key)
    print("ERROR — tamper was not detected!")
except InvalidTag:
    print("Tamper detected correctly — InvalidTag raised")