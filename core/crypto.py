"""
crypto.py - Encryption and key-derivation helpers for the Kerberos demo.

The project still uses Fernet for readability, but long-term keys are now
derived with PBKDF2-HMAC-SHA256 and a per-principal salt. This is closer to
Kerberos string-to-key semantics than hashing the password directly.
"""

import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_KDF_ITERATIONS = 200_000
ENCTYPE = "fernet-aes128-hmac-sha256-pbkdf2"


def derive_key(password: str, salt: str | bytes | None = None,
               iterations: int = DEFAULT_KDF_ITERATIONS) -> bytes:
    """
    Derive a Fernet-compatible encryption key from a plaintext password.

    Args:
        password: The plaintext password string.
        salt: Per-principal salt. If omitted, a deterministic demo salt is used
            for backward compatibility with older call sites.
        iterations: PBKDF2 iteration count.

    Returns:
        A 32-byte URL-safe base64-encoded key suitable for Fernet.
    """
    if salt is None:
        salt_bytes = b"KERBEROS_DEMO_DEFAULT_SALT"
    elif isinstance(salt, bytes):
        salt_bytes = salt
    else:
        salt_bytes = salt.encode("utf-8")

    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        iterations,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw_key)


def generate_session_key() -> bytes:
    """
    Generate a random Fernet-compatible session key.

    Returns:
        A 32-byte URL-safe base64-encoded key.
    """
    random_bytes = os.urandom(32)
    fernet_key = base64.urlsafe_b64encode(random_bytes)
    return fernet_key


def encrypt(data: dict, key: bytes) -> str:
    """
    Encrypt a dictionary using Fernet (AES-128-CBC + HMAC-SHA256).

    Args:
        data: The dictionary to encrypt.
        key: Fernet-compatible encryption key (bytes).

    Returns:
        Base64-encoded encrypted token as a string.
    """
    f = Fernet(key)
    plaintext = json.dumps(data).encode('utf-8')
    token = f.encrypt(plaintext)
    return token.decode('utf-8')


def decrypt(token: str, key: bytes) -> dict:
    """
    Decrypt a Fernet token back into a dictionary.

    Args:
        token: Base64-encoded encrypted token string.
        key: Fernet-compatible encryption key (bytes).

    Returns:
        The decrypted dictionary.

    Raises:
        InvalidToken: If decryption fails (wrong key or tampered data).
    """
    f = Fernet(key)
    plaintext = f.decrypt(token.encode('utf-8'))
    return json.loads(plaintext.decode('utf-8'))


def key_to_str(key: bytes) -> str:
    """Convert a key (bytes) to a string for JSON serialization."""
    return key.decode('utf-8')


def str_to_key(key_str: str) -> bytes:
    """Convert a key string back to bytes."""
    return key_str.encode('utf-8')
