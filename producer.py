# producer.py
import json
import time
import signal
import sys
from kafka import KafkaProducer
from kafka.errors import KafkaError

from simulator  import generate_payload, DEVICE_ID
from envelope   import build_envelope
from keystore   import KeyStore
from handshake  import run_handshake   # returns aes_key for this device

# ── Config ────────────────────────────────────────────────────────────────────

KAFKA_BROKER  = "localhost:9092"
TOPIC         = "health-data-encrypted"
INTERVAL      = 2      # seconds between payloads
ROTATION_SECS = 300    # re-handshake every 5 minutes

# ── Producer setup ────────────────────────────────────────────────────────────

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    value_serializer=lambda v: v.encode("utf-8"),  # envelope is already a JSON string
    key_serializer=lambda k: k.encode("utf-8"),    # partition key = device_id
    acks="all",          # wait for all in-sync replicas to confirm
    retries=3,
    linger_ms=0,         # send immediately — no batching delay for real-time data
)

# ── Graceful shutdown ─────────────────────────────────────────────────────────

def shutdown(sig, frame):
    print("\n[producer] shutting down...")
    producer.flush()
    producer.close()
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ── Delivery callbacks ────────────────────────────────────────────────────────

def on_success(metadata):
    print(f"[producer] sent seq #{seq_counter} → "
          f"topic={metadata.topic} partition={metadata.partition} "
          f"offset={metadata.offset}")

def on_error(e: KafkaError):
    print(f"[producer] delivery failed: {e}")

# ── Main loop ─────────────────────────────────────────────────────────────────

def run():
    global seq_counter

    store = KeyStore()
    aes_key, session_start = run_handshake(DEVICE_ID, store)
    seq_counter = 0

    print(f"[producer] device {DEVICE_ID} — starting publish loop")
    print(f"[producer] session key: {aes_key.hex()[:16]}...  (truncated)")

    while True:
        now = time.time()

        # ── Key rotation check ────────────────────────────────────────────────
        if now - session_start >= ROTATION_SECS:
            print("[producer] rotating session key — re-handshaking...")
            store.revoke(DEVICE_ID)
            aes_key, session_start = run_handshake(DEVICE_ID, store)
            seq_counter = 0
            print(f"[producer] new session key: {aes_key.hex()[:16]}...")

        # ── Generate + encrypt + publish ──────────────────────────────────────
        seq_counter += 1
        payload  = generate_payload()
        envelope = build_envelope(payload, aes_key, DEVICE_ID, seq=seq_counter)

        producer.send(
            TOPIC,
            key=DEVICE_ID,
            value=envelope,
        ).add_callback(on_success).add_errback(on_error)

        time.sleep(INTERVAL)

if __name__ == "__main__":
    run()