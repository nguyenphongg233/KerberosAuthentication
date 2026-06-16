"""
crypto.py - Cryptographic specifications for Kerberos RFC compliance.

Implements AES-CTS encryption/decryption, HMAC-SHA1-96 checksums,
n-fold string expansion, RFC 3961 key derivation (DK/DR), PBKDF2 string-to-key,
and standard Key Usage constants.
"""

import base64
import hashlib
import hmac
import os
import math
from Crypto.Cipher import AES


# Standard Encryption Type Identifiers (RFC 3962)
ENCTYPE_AES128 = 17
ENCTYPE_AES256 = 18
DEFAULT_ENCTYPE = ENCTYPE_AES256

ENCTYPE_AES128_NAME = "aes128-cts-hmac-sha1-96"
ENCTYPE_AES256_NAME = "aes256-cts-hmac-sha1-96"
ENCTYPE = ENCTYPE_AES256_NAME

ENCTYPE_TO_NAME = {ENCTYPE_AES128: ENCTYPE_AES128_NAME, ENCTYPE_AES256: ENCTYPE_AES256_NAME}
NAME_TO_ENCTYPE = {ENCTYPE_AES128_NAME: ENCTYPE_AES128, ENCTYPE_AES256_NAME: ENCTYPE_AES256}

DEFAULT_KDF_ITERATIONS = 4096  # Standard for AES enctypes


# Standard Key Usages (RFC 4120 Section 7.5.1)
KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1
KEY_USAGE_TICKET = 2  # Ticket enc-part (TGT or Service Ticket)
KEY_USAGE_AS_REP_ENCPART = 3
KEY_USAGE_TGS_REQ_AD_SESSKEY = 4
KEY_USAGE_TGS_REQ_AUTH = 7
KEY_USAGE_TGS_REP_ENCPART = 9
KEY_USAGE_AP_REQ_AUTH = 11
KEY_USAGE_AP_REP_ENCPART = 12


class InvalidToken(Exception):
    """Raised when decryption or integrity verification fails."""
    pass


def nfold(b: bytes, n: int) -> bytes:
    """
    The n-fold algorithm as defined in RFC 3961.
    Expands a variable-length byte string to a target length of n bytes.
    """
    in_len = len(b)
    lcm = (in_len * n) // math.gcd(in_len, n)
    replicated = b * (lcm // in_len)
    
    w = n * 8
    total_sum = 0
    num_chunks = lcm // n
    
    for i in range(num_chunks):
        chunk_bytes = replicated[i * n : (i + 1) * n]
        chunk_val = int.from_bytes(chunk_bytes, "big")
        # Rotate right by 13 * i bits
        rot_val = _rotate_right(chunk_val, 13 * i, w)
        total_sum += rot_val
        
    # 1s complement addition fold
    mod = (1 << w) - 1
    folded = total_sum % mod
    if folded == 0 and total_sum > 0:
        folded = mod
        
    return folded.to_bytes(n, "big")


def _rotate_right(val: int, r: int, w: int) -> int:
    r = r % w
    if r == 0:
        return val
    return ((val >> r) | (val << (w - r))) & ((1 << w) - 1)


def _encrypt_block_ecb(key: bytes, block: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def derive_random(key: bytes, constant: bytes, out_len: int) -> bytes:
    """
    DR (derive-random) key-derivation function as defined in RFC 3962 Section 6.
    """
    nfolded = nfold(constant, 16)
    b1 = _encrypt_block_ecb(key, nfolded)
    if out_len <= 16:
        return b1[:out_len]
    b2 = _encrypt_block_ecb(key, b1)
    return b1 + b2


def derive_key(password: str, salt: str | bytes | None = None,
               iterations: int = DEFAULT_KDF_ITERATIONS,
               enctype: int = DEFAULT_ENCTYPE) -> bytes:
    """
    String-to-key function for Kerberos AES enctypes (RFC 3962 Section 4).
    """
    key_len = 16 if enctype == ENCTYPE_AES128 else 32
    
    if salt is None:
        salt_bytes = b"KERBEROS_DEMO_DEFAULT_SALT"
    elif isinstance(salt, bytes):
        salt_bytes = salt
    else:
        salt_bytes = salt.encode("utf-8")
        
    # PBKDF2-HMAC-SHA1
    tkey = hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        salt_bytes,
        iterations,
        dklen=key_len,
    )
    
    # final key = DK(tkey, b"kerberos")
    return derive_random(tkey, b"kerberos", key_len)


def generate_session_key(enctype: int = DEFAULT_ENCTYPE) -> bytes:
    """Generate a random key of standard length for the given enctype."""
    key_len = 16 if enctype == ENCTYPE_AES128 else 32
    return os.urandom(key_len)


def _encrypt_aes_cts(key: bytes, plaintext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    L = len(plaintext)
    if L < 16:
        raise ValueError("Plaintext must be at least 16 bytes for CTS mode")
        
    if L == 16:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.encrypt(plaintext)
        
    d = L % 16
    if d == 0:
        d = 16
    n = (L - d) // 16 + 1
    
    if n > 2:
        cbc_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        c_blocks = cbc_cipher.encrypt(plaintext[:(n-2)*16])
        last_c = c_blocks[-16:]
    else:
        c_blocks = b''
        last_c = iv
        
    p_n_minus_1 = plaintext[(n-2)*16 : (n-1)*16]
    p_n = plaintext[(n-1)*16 :]
    
    xor_n_minus_1 = bytes(a ^ b for a, b in zip(p_n_minus_1, last_c))
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    c_prime = ecb_cipher.encrypt(xor_n_minus_1)
    
    c_n = c_prime[:d]
    x_n = p_n + c_prime[d:]
    
    xor_n = bytes(a ^ b for a, b in zip(x_n, last_c))
    c_n_minus_1 = ecb_cipher.encrypt(xor_n)
    
    return c_blocks + c_n_minus_1 + c_n


def _decrypt_aes_cts(key: bytes, ciphertext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    L = len(ciphertext)
    if L < 16:
        raise ValueError("Ciphertext must be at least 16 bytes for CTS mode")
        
    if L == 16:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(ciphertext)
        
    d = L % 16
    if d == 0:
        d = 16
    n = (L - d) // 16 + 1
    
    if n > 2:
        cbc_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        p_blocks = cbc_cipher.decrypt(ciphertext[:(n-2)*16])
        last_c = ciphertext[(n-3)*16 : (n-2)*16] if n > 2 else iv
    else:
        p_blocks = b''
        last_c = iv
        
    c_n_minus_1 = ciphertext[(n-2)*16 : (n-1)*16]
    c_n = ciphertext[(n-1)*16 :]
    
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    dec_c_n_minus_1 = ecb_cipher.decrypt(c_n_minus_1)
    
    x_n = bytes(a ^ b for a, b in zip(dec_c_n_minus_1, last_c))
    p_n = x_n[:d]
    c_prime = c_n + x_n[d:]
    
    dec_c_prime = ecb_cipher.decrypt(c_prime)
    p_n_minus_1 = bytes(a ^ b for a, b in zip(dec_c_prime, last_c))
    
    return p_blocks + p_n_minus_1 + p_n


def calculate_checksum(ki: bytes, data: bytes) -> bytes:
    """HMAC-SHA1 truncated to 96 bits (12 bytes) per RFC 3962."""
    h = hmac.new(ki, data, hashlib.sha1)
    return h.digest()[:12]


def encrypt(data: bytes, key: bytes, usage: int) -> bytes:
    """
    Encrypt data using AES-CTS with random confounder and HMAC-SHA1 integrity tag.
    
    Args:
        data: Plaintext bytes to encrypt.
        key: Base key.
        usage: Key usage integer.
        
    Returns:
        Ciphertext prepended with confounder and appended with 12-byte MAC.
    """
    key_len = len(key)
    
    constant_ke = usage.to_bytes(4, "big") + b"\x55"
    constant_ki = usage.to_bytes(4, "big") + b"\x99"
    
    ke = derive_random(key, constant_ke, key_len)
    ki = derive_random(key, constant_ki, key_len)
    
    confounder = os.urandom(16)
    padded_plain = confounder + data
    
    ciphertext = _encrypt_aes_cts(ke, padded_plain)
    
    mac = calculate_checksum(ki, ciphertext)
    return ciphertext + mac


def decrypt(encrypted_data: bytes, key: bytes, usage: int) -> bytes:
    """
    Decrypt and verify integrity of AES-CTS encrypted data.
    
    Args:
        encrypted_data: Bytes containing ciphertext + 12-byte MAC.
        key: Base key.
        usage: Key usage integer.
        
    Returns:
        Decrypted plaintext bytes.
        
    Raises:
        InvalidToken: If decryption fails or MAC is invalid.
    """
    key_len = len(key)
    if len(encrypted_data) < 28:
        raise InvalidToken("Encrypted data too short.")
        
    constant_ke = usage.to_bytes(4, "big") + b"\x55"
    constant_ki = usage.to_bytes(4, "big") + b"\x99"
    
    ke = derive_random(key, constant_ke, key_len)
    ki = derive_random(key, constant_ki, key_len)
    
    ciphertext = encrypted_data[:-12]
    mac = encrypted_data[-12:]
    
    expected_mac = calculate_checksum(ki, ciphertext)
    if not hmac.compare_digest(mac, expected_mac):
        raise InvalidToken("Integrity verification failed (MAC mismatch).")
        
    try:
        decrypted = _decrypt_aes_cts(ke, ciphertext)
    except Exception as e:
        raise InvalidToken(f"Decryption failed: {e}")
        
    return decrypted[16:]  # Strip confounder


def key_to_str(key: bytes) -> str:
    """Convert a key (bytes) to a base64 string for storage."""
    return base64.b64encode(key).decode("utf-8")


def str_to_key(key_str: str) -> bytes:
    """Convert a base64 key string back to bytes."""
    return base64.b64decode(key_str.encode("utf-8"))
