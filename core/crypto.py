"""
crypto.py - AES-128 encryption/decryption wrappers for Kerberos V5.

Uses the Fernet module (AES-128-CBC with HMAC-SHA256) from the
`cryptography` library. Key derivation uses SHA-256 to convert
passwords into Fernet-compatible 32-byte URL-safe base64 keys.
"""

import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken


def derive_key(password: str) -> bytes:
    """
    Derive a Fernet-compatible encryption key from a plaintext password.

    Process:
        1. Hash the password using SHA-256 (produces 32 bytes).
        2. Truncate to 16 bytes (AES-128).
        3. Encode as URL-safe base64 (32 bytes) for Fernet compatibility.

    Args:
        password: The plaintext password string.

    Returns:
        A 32-byte URL-safe base64-encoded key suitable for Fernet.
    """
    sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
    # Truncate to 16 bytes for AES-128
    aes_key = sha256_hash[:16]
    # Fernet requires a 32-byte URL-safe base64-encoded key
    fernet_key = base64.urlsafe_b64encode(aes_key + aes_key)
    return fernet_key


def generate_session_key() -> bytes:
    """
    Generate a random Fernet-compatible session key.

    Returns:
        A 32-byte URL-safe base64-encoded key.
    """
    random_bytes = os.urandom(16)
    fernet_key = base64.urlsafe_b64encode(random_bytes + random_bytes)
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
