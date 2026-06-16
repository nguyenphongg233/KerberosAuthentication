"""MIT Keytab v2 binary format support for Kerberos service principals."""

from __future__ import annotations

import os
import struct
from pathlib import Path


def write_keytab(path: str, principal: str, key: str | bytes, kvno: int,
                 enctype: str | int, realm: str) -> None:
    """Write or append a principal entry to an MIT Keytab v2 binary file."""
    # Key is stored as base64 string or bytes in KDC DB
    if isinstance(key, str):
        from core.crypto import str_to_key
        key_bytes = str_to_key(key)
    else:
        key_bytes = key

    # enctype can be string or integer
    if isinstance(enctype, str):
        from core.crypto import NAME_TO_ENCTYPE
        enctype_int = NAME_TO_ENCTYPE.get(enctype, 18)
    else:
        enctype_int = enctype

    # Parse principal components and realm
    if '@' in principal:
        name_part, realm_part = principal.split('@', 1)
    else:
        name_part = principal
        realm_part = realm
    components = name_part.split('/')

    # Build the binary entry data:
    # 2 bytes: num_components
    # 2 bytes: realm length + realm bytes
    # For each component: 2 bytes length + component bytes
    # 4 bytes: name_type (e.g., 1 for principal)
    # 4 bytes: timestamp (unix epoch)
    # 1 byte: kvno
    # 2 bytes: enctype
    # 2 bytes: key length + key bytes
    import time
    timestamp = int(time.time())
    name_type = 1 # KRB5_NT_PRINCIPAL

    realm_bytes = realm_part.encode('utf-8')
    encoded_components = [c.encode('utf-8') for c in components]

    entry_size = 2 + (2 + len(realm_bytes))
    for c_bytes in encoded_components:
        entry_size += 2 + len(c_bytes)
    entry_size += 4 + 4 + 1 + 2 + 2 + len(key_bytes)

    entry_data = struct.pack('>h', len(components))
    entry_data += struct.pack('>H', len(realm_bytes)) + realm_bytes
    for c_bytes in encoded_components:
        entry_data += struct.pack('>H', len(c_bytes)) + c_bytes
    entry_data += struct.pack('>I', name_type)
    entry_data += struct.pack('>I', timestamp)
    entry_data += struct.pack('>B', kvno & 0xff)
    entry_data += struct.pack('>H', enctype_int)
    entry_data += struct.pack('>H', len(key_bytes)) + key_bytes

    # If the keytab file already exists, we read existing entries to append/update
    existing_entries = []
    if os.path.exists(path) and os.path.getsize(path) > 2:
        try:
            with open(path, 'rb') as f:
                header = f.read(2)
                if header == b'\x05\x02':
                    while True:
                        size_bytes = f.read(4)
                        if not size_bytes or len(size_bytes) < 4:
                            break
                        size = struct.unpack('>i', size_bytes)[0]
                        # MIT keytabs might have negative size for deleted entries
                        data = f.read(abs(size))
                        existing_entries.append((size, data))
        except Exception:
            pass

    # Write all entries back (appending the new one at the end)
    keytab_path = Path(path)
    keytab_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'wb') as f:
        # MIT Keytab format prefix
        f.write(struct.pack('>BB', 5, 2))
        for size, data in existing_entries:
            # Check if this principal already exists in keytab (avoid duplicate keys)
            # A simple way to check is to parse the principal from the entry.
            # But just writing everything is fine, standard ktutil appends newer keys at the end.
            f.write(struct.pack('>i', size))
            f.write(data)
        
        # Write the new entry
        f.write(struct.pack('>i', entry_size))
        f.write(entry_data)


def load_keytab(path: str, principal: str) -> dict:
    """Load a principal entry from an MIT Keytab v2 binary file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Keytab not found: {path}")

    # Expected components and realm to match
    if '@' in principal:
        expected_name, expected_realm = principal.split('@', 1)
    else:
        expected_name = principal
        expected_realm = ""
    expected_components = expected_name.split('/')

    with open(path, 'rb') as f:
        header = f.read(2)
        if len(header) < 2 or header[0] != 5 or header[1] != 2:
            raise ValueError(f"Invalid keytab header in: {path}")

        while True:
            size_bytes = f.read(4)
            if not size_bytes:
                break
            if len(size_bytes) < 4:
                raise ValueError("Truncated keytab entry size")
            
            entry_size = struct.unpack('>i', size_bytes)[0]
            if entry_size < 0:
                # Deleted entry in MIT keytab
                f.seek(abs(entry_size), os.SEEK_CUR)
                continue
            
            entry_data = f.read(entry_size)
            if len(entry_data) < entry_size:
                raise ValueError("Truncated keytab entry data")

            # Parse binary entry
            offset = 0
            num_components = struct.unpack_from('>h', entry_data, offset)[0]
            offset += 2

            realm_len = struct.unpack_from('>H', entry_data, offset)[0]
            offset += 2
            realm_bytes = entry_data[offset:offset+realm_len]
            offset += realm_len
            realm = realm_bytes.decode('utf-8')

            components = []
            for _ in range(num_components):
                c_len = struct.unpack_from('>H', entry_data, offset)[0]
                offset += 2
                c_bytes = entry_data[offset:offset+c_len]
                offset += c_len
                components.append(c_bytes.decode('utf-8'))

            name_type = struct.unpack_from('>I', entry_data, offset)[0]
            offset += 4

            timestamp = struct.unpack_from('>I', entry_data, offset)[0]
            offset += 4

            vno = struct.unpack_from('>B', entry_data, offset)[0]
            offset += 1

            enctype_int = struct.unpack_from('>H', entry_data, offset)[0]
            offset += 2

            key_len = struct.unpack_from('>H', entry_data, offset)[0]
            offset += 2
            key_bytes = entry_data[offset:offset+key_len]
            offset += key_len

            # Check if this principal matches what we want
            entry_principal = '/'.join(components) + '@' + realm
            if entry_principal == principal or ('/' in principal and entry_principal == principal):
                from core.crypto import ENCTYPE_TO_NAME, key_to_str
                enctype_name = ENCTYPE_TO_NAME.get(enctype_int, "aes256-cts-hmac-sha1-96")
                return {
                    "principal": entry_principal,
                    "realm": realm,
                    "kvno": vno,
                    "enctype": enctype_name,
                    "key": key_to_str(key_bytes)
                }

    raise KeyError(f"Principal '{principal}' not found in keytab: {path}")
