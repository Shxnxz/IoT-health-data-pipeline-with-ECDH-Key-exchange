# keygen.py  —  run once per device to provision its identity
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os

# ── 1. Generate RSA-2048 key pair ────────────────────────────────────────────

private_key = rsa.generate_private_key(
    public_exponent=65537,   # always 65537 — this is standard
    key_size=2048,
)
public_key = private_key.public_key()

# ── 2. Serialize and save ─────────────────────────────────────────────────────

os.makedirs("keys", exist_ok=True)

# Private key — PEM, no passphrase (fine for a demo; add one in production)
with open("keys/device_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

# Public key — PEM, shared with the server during provisioning
with open("keys/device_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print("Keys written to keys/device_private.pem and keys/device_public.pem")