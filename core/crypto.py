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
    if not b:
        raise ValueError("n-fold input must not be empty")

    in_bits = len(b) * 8
    out_bits = n * 8
    lcm_bits = (in_bits * out_bits) // math.gcd(in_bits, out_bits)

    input_bits = []
    for byte in b:
        input_bits.extend((byte >> bit) & 1 for bit in range(7, -1, -1))

    folded_bits = []
    for repetition in range(lcm_bits // in_bits):
        rotation = (13 * repetition) % in_bits
        if rotation:
            folded_bits.extend(input_bits[-rotation:] + input_bits[:-rotation])
        else:
            folded_bits.extend(input_bits)

    mask = (1 << out_bits) - 1
    total = 0
    for offset in range(0, lcm_bits, out_bits):
        chunk = 0
        for bit in folded_bits[offset:offset + out_bits]:
            chunk = (chunk << 1) | bit
        total += chunk
        total = (total & mask) + (total >> out_bits)
    total = (total & mask) + (total >> out_bits)

    return total.to_bytes(n, "big")


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
    if L == 0:
        raise ValueError("Plaintext must not be empty for CTS mode")

    if L <= 16:
        padded = plaintext + b"\x00" * (16 - L)
        return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(padded)

    d = L % 16 or 16
    n = (L + 15) // 16
    prefix_len = (n - 2) * 16

    if prefix_len:
        c_prefix = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(plaintext[:prefix_len])
        prev_c = c_prefix[-16:]
    else:
        c_prefix = b""
        prev_c = iv

    ecb = AES.new(key, AES.MODE_ECB)
    p_n_minus_1 = plaintext[prefix_len:prefix_len + 16]
    p_n = plaintext[prefix_len + 16:]

    c_n_minus_1 = ecb.encrypt(_xor_bytes(p_n_minus_1, prev_c))
    if d == 16:
        c_n = ecb.encrypt(_xor_bytes(p_n, c_n_minus_1))
        return c_prefix + c_n + c_n_minus_1

    padded_final = p_n + b"\x00" * (16 - d)
    c_prime = ecb.encrypt(_xor_bytes(padded_final, c_n_minus_1))
    return c_prefix + c_prime + c_n_minus_1[:d]


def _decrypt_aes_cts(key: bytes, ciphertext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    L = len(ciphertext)
    if L < 16:
        raise ValueError("Ciphertext must be at least 16 bytes for CTS mode")

    if L == 16:
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)

    d = L % 16 or 16
    n = (L + 15) // 16
    prefix_len = (n - 2) * 16

    if prefix_len:
        c_prefix = ciphertext[:prefix_len]
        p_prefix = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(c_prefix)
        prev_c = c_prefix[-16:]
    else:
        p_prefix = b""
        prev_c = iv

    ecb = AES.new(key, AES.MODE_ECB)
    if d == 16:
        c_n = ciphertext[prefix_len:prefix_len + 16]
        c_n_minus_1 = ciphertext[prefix_len + 16:prefix_len + 32]
        p_n_minus_1 = _xor_bytes(ecb.decrypt(c_n_minus_1), prev_c)
        p_n = _xor_bytes(ecb.decrypt(c_n), c_n_minus_1)
        return p_prefix + p_n_minus_1 + p_n

    c_prime = ciphertext[prefix_len:prefix_len + 16]
    c_n = ciphertext[prefix_len + 16:]
    decrypted_prime = ecb.decrypt(c_prime)
    c_n_minus_1 = c_n + decrypted_prime[d:]
    p_n = _xor_bytes(decrypted_prime[:d], c_n)
    p_n_minus_1 = _xor_bytes(ecb.decrypt(c_n_minus_1), prev_c)
    return p_prefix + p_n_minus_1 + p_n


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


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
        AES-CTS ciphertext of confounder + data, followed by a 12-byte MAC.
    """
    key_len = len(key)
    
    constant_ke = usage.to_bytes(4, "big") + b"\xaa"
    constant_ki = usage.to_bytes(4, "big") + b"\x55"
    
    ke = derive_random(key, constant_ke, key_len)
    ki = derive_random(key, constant_ki, key_len)
    
    confounder = os.urandom(16)
    plaintext = confounder + data

    ciphertext = _encrypt_aes_cts(ke, plaintext)

    mac = calculate_checksum(ki, plaintext)
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
        
    constant_ke = usage.to_bytes(4, "big") + b"\xaa"
    constant_ki = usage.to_bytes(4, "big") + b"\x55"
    
    ke = derive_random(key, constant_ke, key_len)
    ki = derive_random(key, constant_ki, key_len)
    
    ciphertext = encrypted_data[:-12]
    mac = encrypted_data[-12:]
    
    try:
        decrypted = _decrypt_aes_cts(ke, ciphertext)
    except Exception as e:
        raise InvalidToken(f"Decryption failed: {e}")

    expected_mac = calculate_checksum(ki, decrypted)
    if not hmac.compare_digest(mac, expected_mac):
        raise InvalidToken("Integrity verification failed (MAC mismatch).")

    return decrypted[16:]  # Strip confounder


def key_to_str(key: bytes) -> str:
    """Convert a key (bytes) to a base64 string for storage."""
    return base64.b64encode(key).decode("utf-8")


def str_to_key(key_str: str) -> bytes:
    """Convert a base64 key string back to bytes."""
    return base64.b64decode(key_str.encode("utf-8"))
