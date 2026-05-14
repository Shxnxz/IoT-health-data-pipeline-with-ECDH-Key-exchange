# test_envelope.py  —  verify build → parse → decrypt round-trip
import os
from envelope import build_envelope, parse_envelope
from encrypt  import decrypt_payload

aes_key   = os.urandom(32)    # replace with device_aes_key from handshake
device_id = "WRB-4A2F9C"

payload = {
    "device_id":   device_id,
    "timestamp":   "2026-05-14T10:00:00Z",
    "hrv":  {"rmssd_ms": 54.3, "sdnn_ms": 72.1, "lf_hf_ratio": 1.4,
             "pnn50_pct": 22.5, "status": "normal"},
    "rhr":  {"bpm": 61, "avg_7d_bpm": 63, "trend": "stable"},
    "sleep": {"total_duration_min": 432, "efficiency_pct": 89.2,
              "stages_pct": {"awake": 8, "rem": 20, "light": 45, "deep": 27},
              "current_stage": "deep", "interruptions": 2},
    "battery_pct":    78,
    "signal_quality": "good",
}

# ── Build ─────────────────────────────────────────────────────────────────────
raw = build_envelope(payload, aes_key, device_id, seq=1)

print("Envelope on the wire:")
print(raw[:120], "...")   # first 120 chars — rest is ciphertext
print(f"\nTotal envelope size: {len(raw)} bytes")

# ── Parse + decrypt ───────────────────────────────────────────────────────────
dev_id, seq, nonce, ciphertext, tag = parse_envelope(raw)
recovered = decrypt_payload(nonce, ciphertext, tag, aes_key)

assert recovered["device_id"] == device_id
print(f"\nDecrypted OK — seq #{seq}, device: {dev_id}")