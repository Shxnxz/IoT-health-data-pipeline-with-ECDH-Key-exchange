# handshake.py  —  simulates the full exchange between device and server
from ecdh import (
    generate_ecdh_keypair, serialize_public_key,
    compute_shared_secret, derive_session_key
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, SECP256R1
)
from cryptography.hazmat.primitives.asymmetric import ec
from identity import sign, verify, load_private_key, load_public_key
from keystore import KeyStore

DEVICE_ID = "WRB-4A2F9C"

# ════════════════════════════════════════════════════════════════════════════
# DEVICE SIDE
# ════════════════════════════════════════════════════════════════════════════

device_priv, device_ecdh_pub = generate_ecdh_keypair()
device_ecdh_pub_bytes        = serialize_public_key(device_ecdh_pub)

# Sign the ECDH public key with the device's RSA identity key
rsa_private  = load_private_key("keys/device_private.pem")
rsa_sig      = sign(device_ecdh_pub_bytes, rsa_private)

# ── Message sent to server ────────────────────────────────────────────────────
#    { device_id, ecdh_pub_bytes, rsa_sig }
# (In your Kafka/socket implementation, JSON-encode with base64 for the bytes)

# ════════════════════════════════════════════════════════════════════════════
# SERVER SIDE
# ════════════════════════════════════════════════════════════════════════════

# 1. Verify the RSA signature — confirms this is the real device
rsa_public = load_public_key("keys/device_public.pem")
assert verify(device_ecdh_pub_bytes, rsa_sig, rsa_public), "Handshake failed: bad signature"

# 2. Generate server's own ECDH pair and compute shared secret
server_priv, server_ecdh_pub      = generate_ecdh_keypair()
server_ecdh_pub_bytes             = serialize_public_key(server_ecdh_pub)

device_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
    SECP256R1(), device_ecdh_pub_bytes
)
server_shared_secret = compute_shared_secret(server_priv, device_pub_key)
server_aes_key, salt = derive_session_key(server_shared_secret, DEVICE_ID)

# 3. Server sends back its ECDH public key + the salt
#    { server_ecdh_pub_bytes, salt }

# ════════════════════════════════════════════════════════════════════════════
# DEVICE SIDE (continued)
# ════════════════════════════════════════════════════════════════════════════

server_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
    SECP256R1(), server_ecdh_pub_bytes
)
device_shared_secret         = compute_shared_secret(device_priv, server_pub_key)
device_aes_key, _            = derive_session_key(device_shared_secret, DEVICE_ID, salt=salt)

# ════════════════════════════════════════════════════════════════════════════
# VERIFY BOTH SIDES DERIVED THE SAME KEY
# ════════════════════════════════════════════════════════════════════════════

assert device_aes_key == server_aes_key, "Key mismatch — something went wrong"
print(f"Handshake complete. Session key: {device_aes_key.hex()}")
print(f"Key length: {len(device_aes_key) * 8} bits")

import time

def run_handshake(device_id: str, store: "KeyStore") -> tuple[bytes, float]:
    """
    Executes the full ECDH + RSA handshake and stores the derived key.
    Returns (aes_key, session_start_timestamp).

    In your real implementation the server half runs in consumer.py over
    a socket or HTTP endpoint. For the demo, both sides run in-process.
    """
    from ecdh      import generate_ecdh_keypair, serialize_public_key, \
                          compute_shared_secret, derive_session_key
    from identity  import sign, verify, load_private_key, load_public_key
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
    from cryptography.hazmat.primitives.asymmetric import ec

    # Device side
    device_priv, device_ecdh_pub   = generate_ecdh_keypair()
    device_pub_bytes               = serialize_public_key(device_ecdh_pub)
    rsa_priv                       = load_private_key("keys/device_private.pem")
    sig                            = sign(device_pub_bytes, rsa_priv)

    # Server side — verify, generate own pair, derive key
    rsa_pub = load_public_key("keys/device_public.pem")
    assert verify(device_pub_bytes, sig, rsa_pub), "RSA signature invalid"

    server_priv, server_ecdh_pub   = generate_ecdh_keypair()
    server_pub_bytes               = serialize_public_key(server_ecdh_pub)
    device_ec_pub                  = ec.EllipticCurvePublicKey.from_encoded_point(
                                         SECP256R1(), device_pub_bytes)
    server_secret                  = compute_shared_secret(server_priv, device_ec_pub)
    server_key, salt               = derive_session_key(server_secret, device_id)
    store.put(device_id, server_key)

    # Device derives matching key using server's salt
    server_ec_pub                  = ec.EllipticCurvePublicKey.from_encoded_point(
                                         SECP256R1(), server_pub_bytes)
    device_secret                  = compute_shared_secret(device_priv, server_ec_pub)
    device_key, _                  = derive_session_key(device_secret, device_id, salt=salt)

    assert device_key == server_key, "Key derivation mismatch"
    return device_key, time.time()