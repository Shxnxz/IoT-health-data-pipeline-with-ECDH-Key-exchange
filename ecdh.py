# ecdh.py  —  run on both device and server sides
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, generate_private_key, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

# ── 1. Generate ECDH key pair (P-256 / secp256r1) ────────────────────────────

def generate_ecdh_keypair():
    private_key = generate_private_key(SECP256R1())
    public_key  = private_key.public_key()
    return private_key, public_key

# ── 2. Serialize public key to bytes (for sending over the wire) ──────────────

def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

def deserialize_public_key(raw_bytes: bytes) -> EllipticCurvePublicKey:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey, SECP256R1
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicNumbers, SECP256R1
    )
    # X962 uncompressed: 0x04 || 32-byte X || 32-byte Y
    assert raw_bytes[0] == 0x04 and len(raw_bytes) == 65
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey
    )
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), raw_bytes)

# ── 3. Derive shared secret ───────────────────────────────────────────────────

def compute_shared_secret(private_key, peer_public_key: EllipticCurvePublicKey) -> bytes:
    return private_key.exchange(ECDH(), peer_public_key)

# ── 4. Derive AES-256 session key from shared secret via HKDF ────────────────

def derive_session_key(
    shared_secret: bytes,
    device_id: str,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Returns (aes_key, salt).
    Salt is generated fresh if not provided (device side).
    Server receives the salt alongside the ECDH public key and reuses it.
    """
    if salt is None:
        salt = os.urandom(32)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                      # 256-bit AES key
        salt=salt,
        info=f"wearable-session:{device_id}".encode(),
    ).derive(shared_secret)

    return aes_key, salt