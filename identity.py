# identity.py  —  loaded by the simulator at startup, used during ECDH handshake
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def load_private_key(path="keys/device_private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path="keys/device_public.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign(data: bytes, private_key) -> bytes:
    """Sign arbitrary bytes — used to authenticate the ECDH public key."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verify(data: bytes, signature: bytes, public_key) -> bool:
    """Returns True if signature is valid, False if tampered."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False