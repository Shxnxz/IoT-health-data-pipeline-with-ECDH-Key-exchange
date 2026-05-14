# envelope.py
import json
import base64
import time
from encrypt import encrypt_payload

# ── 1. Build envelope ─────────────────────────────────────────────────────────

def build_envelope(
    payload:   dict,
    aes_key:   bytes,
    device_id: str,
    seq:       int,
) -> str:
    """
    Encrypts payload and wraps it in a JSON envelope ready for Kafka.
    Returns a UTF-8 JSON string — the exact bytes published to the topic.
    """
    nonce, ciphertext, tag = encrypt_payload(payload, aes_key)

    envelope = {
        "v":          1,                          # schema version
        "device_id":  device_id,                  # key-store lookup on consumer
        "seq":        seq,                        # per-device message counter
        "emitted_at": time.time(),                # unix timestamp (float)
        "crypto": {
            "alg":        "AES-256-GCM",
            "nonce":      base64.b64encode(nonce).decode(),
            "tag":        base64.b64encode(tag).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }
    }

    return json.dumps(envelope, separators=(",", ":"))  # compact, no whitespace

# ── 2. Parse envelope ─────────────────────────────────────────────────────────

def parse_envelope(raw: str) -> tuple[str, int, bytes, bytes, bytes]:
    """
    Parses a raw Kafka message string.

    Returns:
        device_id, seq, nonce, ciphertext, tag
    """
    e = json.loads(raw)

    assert e["v"] == 1,                   f"Unknown envelope version: {e['v']}"
    assert e["crypto"]["alg"] == "AES-256-GCM", "Unexpected cipher"

    device_id  = e["device_id"]
    seq        = e["seq"]
    nonce      = base64.b64decode(e["crypto"]["nonce"])
    tag        = base64.b64decode(e["crypto"]["tag"])
    ciphertext = base64.b64decode(e["crypto"]["ciphertext"])

    return device_id, seq, nonce, ciphertext, tag