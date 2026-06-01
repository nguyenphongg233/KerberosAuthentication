"""
Client Crypto: AES-GCM crypto wrapper for Client.
"""

import hashlib

from shared_crypto import StandardCryptoEngine


class ClientCryptoEngine(StandardCryptoEngine):
    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]
