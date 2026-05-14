# consumer.py
import json
import signal
import sys
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from cryptography.exceptions import InvalidTag

from envelope  import parse_envelope
from encrypt   import decrypt_payload
from keystore  import KeyStore
from validator import validate_payload

# ── Config ────────────────────────────────────────────────────────────────────

KAFKA_BROKER   = "localhost:9092"
TOPIC          = "health-data-encrypted"
GROUP_ID       = "health-consumer-group"

# ── Consumer setup ────────────────────────────────────────────────────────────

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=KAFKA_BROKER,
    group_id=GROUP_ID,
    auto_offset_reset="latest",        # only process new messages
    enable_auto_commit=True,
    value_deserializer=lambda v: v.decode("utf-8"),
    key_deserializer=lambda k: k.decode("utf-8") if k else None,
)

# ── Graceful shutdown ─────────────────────────────────────────────────────────

def shutdown(sig, frame):
    print("\n[consumer] shutting down...")
    consumer.close()
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ── Per-device session state ──────────────────────────────────────────────────
# Tracks last seen seq per device to detect replays and key rotations

class SessionTracker:
    def __init__(self):
        self._state: dict[str, dict] = {}

    def check_seq(self, device_id: str, seq: int) -> str:
        """
        Returns:
            "ok"       — valid next message in sequence
            "rotation" — seq reset to 1, trigger key re-fetch
            "replay"   — seq is not greater than last seen, drop message
        """
        last = self._state.get(device_id, {}).get("seq", 0)

        if seq == 1 and last > 1:
            self._state[device_id] = {"seq": seq}
            return "rotation"

        if seq > last:
            self._state.setdefault(device_id, {})["seq"] = seq
            return "ok"

        return "replay"

    def reset(self, device_id: str):
        self._state.pop(device_id, None)

# ── Output ────────────────────────────────────────────────────────────────────

def output(device_id: str, seq: int, payload: dict):
    """
    Final sink for decrypted plaintext.
    Swap print() for a DB write, dashboard push, or alerting hook here.
    """
    hrv   = payload["hrv"]
    rhr   = payload["rhr"]
    sleep = payload["sleep"]

    print(f"\n[{device_id}] seq=#{seq}")
    print(f"  HRV    rMSSD={hrv['rmssd_ms']}ms  status={hrv['status']}")
    print(f"  RHR    {rhr['bpm']} bpm  trend={rhr['trend']}")
    print(f"  Sleep  {sleep['total_duration_min']}min  "
          f"eff={sleep['efficiency_pct']}%  "
          f"stage={sleep['current_stage']}")
    print(f"  Battery {payload['battery_pct']}%  "
          f"signal={payload['signal_quality']}")

# ── Main loop ─────────────────────────────────────────────────────────────────

def run(store: KeyStore):
    tracker = SessionTracker()

    print(f"[consumer] subscribed to '{TOPIC}' — waiting for messages...")

    for message in consumer:
        raw = message.value

        # ── 1. Parse envelope ─────────────────────────────────────────────────
        try:
            device_id, seq, nonce, ciphertext, tag = parse_envelope(raw)
        except (KeyError, AssertionError, json.JSONDecodeError) as e:
            print(f"[consumer] malformed envelope — skipping: {e}")
            continue

        # ── 2. Replay / rotation check ────────────────────────────────────────
        status = tracker.check_seq(device_id, seq)

        if status == "replay":
            print(f"[consumer] replay detected from {device_id} seq=#{seq} — dropping")
            continue

        if status == "rotation":
            print(f"[consumer] key rotation detected for {device_id} — fetching new key")
            # In production: request new key from key server
            # For demo: key store is already updated by producer's re-handshake
            pass

        # ── 3. Look up session key ────────────────────────────────────────────
        aes_key = store.get(device_id)

        if aes_key is None:
            print(f"[consumer] no session key for {device_id} — "
                  f"trigger handshake then re-queue")
            tracker.reset(device_id)
            continue

        # ── 4. Decrypt + verify GCM tag ───────────────────────────────────────
        try:
            payload = decrypt_payload(nonce, ciphertext, tag, aes_key)
        except InvalidTag:
            print(f"[consumer] InvalidTag for {device_id} seq=#{seq} — "
                  f"ciphertext tampered or wrong key, dropping")
            continue

        # ── 5. Schema validation ──────────────────────────────────────────────
        try:
            validate_payload(payload)
        except Exception as e:
            print(f"[consumer] schema validation failed for {device_id}: {e}")
            continue

        # ── 6. Output ─────────────────────────────────────────────────────────
        output(device_id, seq, payload)

if __name__ == "__main__":
    # In the demo the store is shared in-process with the producer.
    # In a real deployment this is a Redis instance or a key server.
    from keystore import KeyStore
    store = KeyStore()

    # Pre-populate with a known key for testing without a live producer:
    # import os
    # store.put("WRB-4A2F9C", os.urandom(32))

    run(store)