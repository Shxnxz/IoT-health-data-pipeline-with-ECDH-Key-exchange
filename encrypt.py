# encrypt.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import os

# ── 1. Encrypt ────────────────────────────────────────────────────────────────

def encrypt_payload(payload: dict, aes_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts a JSON payload with AES-256-GCM.

    Returns:
        nonce       — 12 random bytes, unique per message (never reuse)
        ciphertext  — encrypted payload bytes (includes GCM auth tag appended)
        tag         — 16-byte auth tag extracted separately for the envelope
    """
    nonce = os.urandom(12)          # 96-bit nonce — GCM standard size

    aesgcm     = AESGCM(aes_key)
    plaintext  = json.dumps(payload).encode("utf-8")

    # encrypt() returns ciphertext || tag (tag is last 16 bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    ciphertext = ciphertext_with_tag[:-16]
    tag        = ciphertext_with_tag[-16:]

    return nonce, ciphertext, tag

# ── 2. Decrypt ────────────────────────────────────────────────────────────────

def decrypt_payload(nonce: bytes, ciphertext: bytes, tag: bytes, aes_key: bytes) -> dict:
    """
    Decrypts and verifies an AES-256-GCM payload.
    Raises cryptography.exceptions.InvalidTag if tampered.
    """
    aesgcm = AESGCM(aes_key)

    # Reassemble ciphertext || tag before passing to decrypt()
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)

    return json.loads(plaintext.decode("utf-8"))