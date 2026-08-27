"""
crypto_service.py
==================
Handles all encryption / decryption for secret files.

Algorithm : AES-256-GCM (authenticated encryption - confidentiality + integrity)
KDF       : PBKDF2-HMAC-SHA256 (derives a 256-bit key from the user's password)

Never rolls its own crypto primitives - uses the `cryptography` library only.
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 390_000
SALT_SIZE = 16      # bytes
NONCE_SIZE = 12      # bytes, recommended size for AES-GCM
KEY_SIZE = 32      # 256 bits


class DecryptionError(Exception):
    """Raised when AES-GCM authentication fails (wrong password or corrupted data)."""
    pass


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit AES key from a password + salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: bytes, password: str) -> dict:
    """
    Encrypt plaintext bytes with AES-256-GCM.

    Returns a dict with:
        salt, nonce, ciphertext (includes GCM auth tag appended), iterations
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {
        "salt": salt,
        "nonce": nonce,
        "ciphertext": ciphertext,  # ciphertext + 16-byte tag
        "iterations": PBKDF2_ITERATIONS,
    }


def decrypt_data(ciphertext: bytes, password: str, salt: bytes, nonce: bytes,
                  iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext. Raises DecryptionError on auth failure
    (wrong password OR tampered/corrupted data) - AES-GCM cannot tell these apart,
    which is intentional: it prevents leaking information to an attacker.
    """
    key = derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as exc:
        raise DecryptionError("Decryption failed. Invalid password or corrupted hidden data.") from exc


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
