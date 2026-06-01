"""
Shared crypto helpers.

This module uses AES-GCM from the `cryptography` package. Keys in the demo are
human-readable strings, so they are first derived to 256-bit AES keys with
SHA-256. This is still an educational simplification; real Kerberos uses
specified enctypes and key derivation rules.
"""

import base64
import hashlib
import json
import os
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StandardCryptoEngine:
    NAME = "AES_256_GCM_DEMO"

    @staticmethod
    def derive_key(key_material: str) -> bytes:
        if not key_material:
            raise ValueError("key material is required")
        return hashlib.sha256(key_material.encode("utf-8")).digest()

    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        if not plaintext or not key:
            return ""

        aesgcm = AESGCM(StandardCryptoEngine.derive_key(key))
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        payload = {
            "alg": StandardCryptoEngine.NAME,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    @staticmethod
    def decrypt(ciphertext_text: str, key: str) -> str:
        if not ciphertext_text or not key:
            return ""

        try:
            payload = json.loads(base64.b64decode(ciphertext_text).decode("utf-8"))
            if payload.get("alg") != StandardCryptoEngine.NAME:
                return ""
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            aesgcm = AESGCM(StandardCryptoEngine.derive_key(key))
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception:
            return ""

    @staticmethod
    def encrypt_dict(data: Dict[str, Any], key: str) -> str:
        return StandardCryptoEngine.encrypt(json.dumps(data), key)

    @staticmethod
    def decrypt_dict(ciphertext_text: str, key: str) -> Dict[str, Any]:
        plaintext = StandardCryptoEngine.decrypt(ciphertext_text, key)
        if not plaintext:
            return {}
        try:
            return json.loads(plaintext)
        except Exception:
            return {}
