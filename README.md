# IoT Health Data Pipeline with ECDH Key Exchange

A secure end-to-end pipeline that simulates a wearable health device transmitting encrypted physiological data through Apache Kafka. Demonstrates key management, authenticated key exchange, and real-time decryption.

---

## Security Overview

| Objective | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM encrypts every payload before it leaves the device |
| Integrity | GCM authentication tag detects any tampering in transit |
| Authentication | RSA-2048 signature on ECDH public key proves device identity |
| Key Management | ECDH + HKDF session key, file-backed store, TTL-based rotation |

---

## Architecture

```
[IoT Simulator]
   generate_payload()
        │
        ▼
[Phase 2 — ECDH Handshake]
   Device generates ECDH keypair
   Signs public key with RSA identity key
   Server verifies RSA sig → derives shared secret → HKDF → AES-256 session key
   Key written to keystore.json
        │
        ▼
[Phase 3 — Encrypt + Publish]
   AES-256-GCM encrypt payload (fresh nonce per message)
   Wrap in JSON envelope {device_id, seq, nonce, tag, ciphertext}
   Publish to Kafka topic: health-data-encrypted
        │
        ▼
[Phase 4 — Consume + Decrypt]
   Consumer reads envelope from Kafka
   Checks seq counter (replay attack defence)
   Looks up session key from keystore.json by device_id
   AES-256-GCM decrypt + verify tag
   JSON schema validation
   Output plaintext to console / DB
```

---

## Project Structure

```
project/
│
├── keys/                    ← auto-created by keygen.py (git-ignored)
│   ├── device_private.pem
│   └── device_public.pem
│
├── keystore.json            ← auto-created at runtime (git-ignored)
│
├── schema.json              ← JSON schema for payload validation
├── docker-compose.yml       ← Kafka + Zookeeper
│
├── keygen.py                ← run once: generates RSA identity keypair
├── simulator.py             ← generates synthetic HRV, RHR, sleep payloads
├── identity.py              ← RSA sign / verify helpers
├── ecdh.py                  ← ECDH keypair generation + HKDF derivation
├── handshake.py             ← full ECDH + RSA authenticated handshake
├── keystore.py              ← file-backed session key store with TTL
├── encrypt.py               ← AES-256-GCM encrypt / decrypt
├── envelope.py              ← build / parse Kafka JSON envelope
├── validator.py             ← JSON schema validator
├── producer.py              ← Kafka publisher loop
└── consumer.py              ← Kafka subscriber + decrypt + output
```

---

## Prerequisites

- Python 3.11+
- Docker Desktop (running)
- pip packages:

```bash
pip install cryptography kafka-python jsonschema
```

---

## Setup and Running

### Step 1 — Generate RSA identity keys (once only)

```bash
python keygen.py
```

Creates `keys/device_private.pem` and `keys/device_public.pem`. Never run this again — regenerating keys invalidates all prior handshakes.

### Step 2 — Start Kafka

```bash
docker compose up -d
```

Verify both containers are running:

```bash
docker ps
```

### Step 3 — Create the Kafka topic (once only)

Replace `<kafka-container-name>` with the name shown in `docker ps` (e.g. `iothealthdatapipelinewithecdhkeyexchange-kafka-1`):

```bash
docker exec -it <kafka-container-name> kafka-topics --create --topic health-data-encrypted --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
```

Confirm the topic exists:

```bash
docker exec -it <kafka-container-name> kafka-topics --list --bootstrap-server localhost:9092
```

### Step 4 — Start the consumer (Terminal 2)

```bash
python consumer.py
```

### Step 5 — Start the producer (Terminal 3)

```bash
python producer.py
```

The producer runs the ECDH handshake, writes the session key to `keystore.json`, then begins publishing encrypted payloads every 2 seconds. The consumer reads the key from `keystore.json` and decrypts each message in real time.

---

## Sample Output

**keystore.json** (written after handshake):
```json
{
  "WRB-4A2F9C": {
    "key": "a3f2c9d1e4b27f8e...",
    "created_at": 1747216800.432,
    "msg_count": 12
  }
}
```

**Encrypted envelope on Kafka topic** (intercepting this reveals nothing):
```json
{
  "v": 1,
  "device_id": "WRB-4A2F9C",
  "seq": 7,
  "emitted_at": 1747216814.871,
  "crypto": {
    "alg": "AES-256-GCM",
    "nonce": "a3F2kLmNpQrStUvW",
    "tag": "xYzAbCdEfGhIjKlM",
    "ciphertext": "v8kQ2...[ encrypted bytes ]...=="
  }
}
```

**Consumer terminal** (after decryption):
```
[WRB-4A2F9C] seq=#7
  HRV    rMSSD=54.3ms  status=normal
  RHR    61 bpm  trend=stable
  Sleep  432min  eff=89.2%  stage=deep
  Battery 78%  signal=good
```

---

## Key Management Design

### Session key lifecycle

```
generate keypair  →  ECDH exchange  →  HKDF derivation  →  store in keystore.json
       │                                                            │
       └──────────── TTL: 300 seconds ────────────────────────────▶ revoke + rotate
```

- Session keys are derived fresh per handshake using HKDF-SHA256
- Keys are never transmitted — both sides independently derive the same value
- The `seq` counter resets to 1 on rotation; the consumer detects this and fetches the new key
- Revoking a key deletes it from `keystore.json` immediately

### Why ECDH over plain RSA for key exchange?

RSA encryption of a symmetric key requires the full plaintext key to travel over the wire. ECDH establishes a shared secret without either side ever transmitting it — an intercepted public key gives an attacker nothing usable. This property (forward secrecy per session) is the core reason ECDH is preferred in modern protocols like TLS 1.3.

### Why AES-GCM over AES-CBC?

GCM is an authenticated encryption mode — it produces a 16-byte authentication tag alongside the ciphertext. Decryption fails loudly (`InvalidTag`) if even one bit of the ciphertext, nonce, or key is wrong. CBC provides only confidentiality; a separate HMAC would be needed for integrity.

---

## Security Objectives Mapping

| Requirement | Where it is implemented |
|---|---|
| Confidentiality | `encrypt.py` — AES-256-GCM |
| Integrity | `encrypt.py` — GCM auth tag; `validator.py` — schema check |
| Authentication | `identity.py` — RSA-2048 PSS signature on ECDH public key |
| Key generation | `ecdh.py` — P-256 / secp256r1 |
| Key derivation | `ecdh.py` — HKDF-SHA256 with device-scoped info string |
| Key storage | `keystore.py` — file-backed, TTL-enforced |
| Key rotation | `producer.py` — time-triggered re-handshake every 300s |
| Replay defence | `consumer.py` — monotonic `seq` counter per device |

---

## Threat Model

| Threat | Defence | Module |
|---|---|---|
| **Passive eavesdropper** intercepts Kafka traffic | All payloads are AES-256-GCM encrypted; the session key is never transmitted | `encrypt.py`, `ecdh.py` |
| **Man-in-the-middle** substitutes a fake ECDH public key | Device signs its ECDH public key with its RSA identity key; server verifies before deriving the shared secret | `identity.py`, `handshake.py` |
| **Replay attack** re-sends a previously captured envelope | Consumer tracks a monotonic per-device sequence counter and drops any message where `seq ≤ last_seen` | `consumer.py` (`SessionTracker`) |
| **Compromised broker** reads data at rest on Kafka | Data is encrypted at the application layer — the broker only ever sees ciphertext | `envelope.py`, `encrypt.py` |
| **Stolen session key** used after rotation window | Keys expire after 300 seconds; `KeyStore` automatically revokes expired keys | `keystore.py` |
| **Ciphertext tampering** (bit-flip in transit) | GCM authentication tag verification fails → `InvalidTag` raised → message dropped | `encrypt.py`, `consumer.py` |

---

## Running Tests

Two standalone test scripts verify the cryptographic round-trip without needing Kafka:

```bash
python test_encrypt.py      # encrypt → decrypt → tamper detection
python test_envelope.py     # build envelope → parse → decrypt
```

**Expected output** (`test_encrypt.py`):
```
nonce:      <hex>  (12 bytes)
ciphertext: <hex>...  (<N> bytes)
tag:        <hex>  (16 bytes)

Decrypted OK — device_id: WRB-4A2F9C
Tamper detected correctly — InvalidTag raised
```

---

## Access Control Model

### Objects (resources whose access is controlled)

| Object | Sensitivity |
|---|---|
| Health telemetry payloads (HRV, RHR, sleep) | Protected health information — regulated under HIPAA / GDPR |
| AES-256 session keys (`keystore.json`) | Compromise breaks confidentiality of all in-flight data for that session |
| RSA identity key (`keys/device_private.pem`) | Compromise allows permanent device impersonation |
| Kafka topic (`health-data-encrypted`) | Transport channel — carries only ciphertext by design |

### Subjects (entities requesting access)

| Subject | Role |
|---|---|
| IoT wearable device (producer) | Generates, encrypts, and publishes health data |
| Backend server (consumer) | Decrypts, validates, and processes health data |
| Adversary | Any unauthorised party — the system is designed to deny them useful access |

### Operations

| Operation | Subject | Control mechanism |
|---|---|---|
| Encrypt + publish | Device | Requires session key derived via authenticated ECDH handshake |
| Decrypt + read | Server | Requires matching session key from the key store |
| Authenticate identity | Server verifies device | RSA-PSS signature on ECDH public key |
| Rotate / revoke keys | Producer triggers | TTL expiry (300s) → re-handshake → old key deleted |

---

## Limitations

- **Single-device demo** — the simulator runs one device per process; a production system would manage thousands of concurrent device sessions
- **In-process handshake** — both device and server halves run in the same Python process; in production the server side would be a separate key-exchange service (e.g. over mutual TLS or a dedicated handshake API)
- **File-backed key store** — `keystore.json` is a flat file with no locking; a production deployment would use Redis or a hardware security module (HSM)
- **No mutual authentication** — the server authenticates the device via RSA signature, but the device does not authenticate the server (susceptible to a rogue server in theory)
- **Kafka runs in plaintext mode** — the demo does not enable TLS on the Kafka broker itself; production would layer broker-level TLS beneath the application-level encryption
- **No persistent data sink** — decrypted payloads are printed to the console; a real system would write to a time-series database or dashboard

---

## Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | ECDH, RSA, AES-GCM, HKDF |
| `kafka-python` | Kafka producer and consumer |
| `jsonschema` | Payload schema validation |

---

## Notes

- `keys/` and `keystore.json` are runtime artifacts and should be added to `.gitignore`
- The handshake runs in-process for the demo; in production the server half would run as a separate key-exchange endpoint
- Kafka runs in plaintext mode for the demo — in production enable TLS on the broker to add a transport layer on top of the application-layer encryption
