"""
Client Crypto: Hệ thống mã hóa của Client
(Hiện tại dùng XOR Stream, sau có thể thay đổi độc lập)
"""

import json
from typing import Any, Dict


class ClientCryptoEngine:
    """Engine mã hóa của Client"""
    
    NAME = "XOR_STREAM_V1"  # Tên hệ thống mã hóa
    
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """Mã hóa XOR Stream"""
        if not plaintext or not key:
            return ""
        
        key_extended = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]
        encrypted = bytes(
            ord(p) ^ ord(k) for p, k in zip(plaintext, key_extended)
        )
        return encrypted.hex()
    
    @staticmethod
    def decrypt(ciphertext_hex: str, key: str) -> str:
        """Giải mã XOR Stream"""
        if not ciphertext_hex or not key:
            return ""
        
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            key_extended = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
            plaintext = ''.join(
                chr(c ^ ord(k)) for c, k in zip(ciphertext, key_extended)
            )
            return plaintext
        except Exception:
            return ""
    
    @staticmethod
    def encrypt_dict(data: Dict[str, Any], key: str) -> str:
        """Mã hóa dictionary"""
        json_str = json.dumps(data)
        return ClientCryptoEngine.encrypt(json_str, key)
    
    @staticmethod
    def decrypt_dict(ciphertext_hex: str, key: str) -> Dict[str, Any]:
        """Giải mã thành dictionary"""
        plaintext = ClientCryptoEngine.decrypt(ciphertext_hex, key)
        if not plaintext:
            return {}
        try:
            return json.loads(plaintext)
        except:
            return {}
