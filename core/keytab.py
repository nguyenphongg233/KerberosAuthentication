"""MIT Keytab v2 binary format support for Kerberos service principals."""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path


KRB5_NT_PRINCIPAL = 1
KRB5_NT_SRV_INST = 2


def write_keytab(path: str, principal: str, key: str | bytes, kvno: int,
                 enctype: str | int, realm: str) -> None:
    """Write or replace a principal entry in an MIT Keytab v2 binary file."""
    key_bytes = _coerce_key_bytes(key)
    enctype_int = _enctype_to_int(enctype)
    kvno_int = int(kvno)

    name_part, realm_part = _split_principal(principal, realm)
    components = [component for component in name_part.split("/") if component]
    name_type = KRB5_NT_SRV_INST if len(components) > 1 else KRB5_NT_PRINCIPAL
    entry_principal = f"{'/'.join(components)}@{realm_part}"

    timestamp = int(time.time())
    realm_bytes = realm_part.encode("utf-8")
    encoded_components = [component.encode("utf-8") for component in components]

    entry_size = 2 + (2 + len(realm_bytes))
    for component_bytes in encoded_components:
        entry_size += 2 + len(component_bytes)
    entry_size += 4 + 4 + 1 + 2 + 2 + len(key_bytes) + 4

    entry_data = struct.pack(">h", len(components))
    entry_data += struct.pack(">H", len(realm_bytes)) + realm_bytes
    for component_bytes in encoded_components:
        entry_data += struct.pack(">H", len(component_bytes)) + component_bytes
    entry_data += struct.pack(">I", name_type)
    entry_data += struct.pack(">I", timestamp)
    entry_data += struct.pack(">B", kvno_int & 0xFF)
    entry_data += struct.pack(">H", enctype_int)
    entry_data += struct.pack(">H", len(key_bytes)) + key_bytes
    # MIT keytab v2 entries may carry a 32-bit kvno after the keyblock.
    entry_data += struct.pack(">I", kvno_int & 0xFFFFFFFF)

    keytab_path = Path(path)
    keytab_path.parent.mkdir(parents=True, exist_ok=True)

    existing_entries = _read_raw_entries(path)
    with open(path, "wb") as handle:
        handle.write(struct.pack(">BB", 5, 2))
        for size, data in existing_entries:
            if size > 0 and _is_same_keytab_slot(data, entry_principal, kvno_int, enctype_int):
                continue
            handle.write(struct.pack(">i", size))
            handle.write(data)

        handle.write(struct.pack(">i", entry_size))
        handle.write(entry_data)


def load_keytab(path: str, principal: str, kvno: int | None = None,
                enctype: str | int | None = None) -> dict:
    """Load the best matching principal entry from an MIT Keytab v2 file.

    If ``kvno`` is provided, the entry must match exactly. Without a kvno,
    the newest/highest kvno entry for the principal is returned.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Keytab not found: {path}")

    wanted_kvno = int(kvno) if kvno is not None else None
    wanted_enctype = _enctype_to_int(enctype) if enctype is not None else None
    matches = []

    with open(path, "rb") as handle:
        header = handle.read(2)
        if len(header) < 2 or header[0] != 5 or header[1] != 2:
            raise ValueError(f"Invalid keytab header in: {path}")

        while True:
            size_bytes = handle.read(4)
            if not size_bytes:
                break
            if len(size_bytes) < 4:
                raise ValueError("Truncated keytab entry size")

            entry_size = struct.unpack(">i", size_bytes)[0]
            if entry_size < 0:
                handle.seek(abs(entry_size), os.SEEK_CUR)
                continue

            entry_data = handle.read(entry_size)
            if len(entry_data) < entry_size:
                raise ValueError("Truncated keytab entry data")

            entry = _parse_entry(entry_data)
            if not _principal_matches(entry["principal"], principal):
                continue
            if wanted_kvno is not None and entry["kvno"] != wanted_kvno:
                continue
            if wanted_enctype is not None and entry["enctype_int"] != wanted_enctype:
                continue
            matches.append(entry)

    if not matches:
        detail = f"Principal '{principal}' not found in keytab: {path}"
        if wanted_kvno is not None:
            detail += f" (kvno={wanted_kvno})"
        if wanted_enctype is not None:
            detail += f" (enctype={wanted_enctype})"
        raise KeyError(detail)

    chosen = max(matches, key=lambda entry: (entry["kvno"], entry["timestamp"]))
    from core.crypto import ENCTYPE_TO_NAME, key_to_str

    return {
        "principal": chosen["principal"],
        "realm": chosen["realm"],
        "kvno": chosen["kvno"],
        "enctype": ENCTYPE_TO_NAME.get(chosen["enctype_int"], str(chosen["enctype_int"])),
        "key": key_to_str(chosen["key"]),
    }


def _read_raw_entries(path: str) -> list[tuple[int, bytes]]:
    entries: list[tuple[int, bytes]] = []
    if not os.path.exists(path) or os.path.getsize(path) <= 2:
        return entries

    try:
        with open(path, "rb") as handle:
            header = handle.read(2)
            if header != b"\x05\x02":
                return entries
            while True:
                size_bytes = handle.read(4)
                if not size_bytes:
                    break
                if len(size_bytes) < 4:
                    break
                size = struct.unpack(">i", size_bytes)[0]
                data = handle.read(abs(size))
                if len(data) < abs(size):
                    break
                entries.append((size, data))
    except OSError:
        return []
    return entries


def _is_same_keytab_slot(data: bytes, principal: str, kvno: int, enctype_int: int) -> bool:
    try:
        entry = _parse_entry(data)
    except ValueError:
        return False
    return (
        entry["principal"] == principal
        and entry["kvno"] == kvno
        and entry["enctype_int"] == enctype_int
    )


def _parse_entry(entry_data: bytes) -> dict:
    try:
        offset = 0
        num_components = struct.unpack_from(">h", entry_data, offset)[0]
        offset += 2

        realm_len = struct.unpack_from(">H", entry_data, offset)[0]
        offset += 2
        realm = entry_data[offset:offset + realm_len].decode("utf-8")
        offset += realm_len

        components = []
        for _ in range(num_components):
            component_len = struct.unpack_from(">H", entry_data, offset)[0]
            offset += 2
            components.append(entry_data[offset:offset + component_len].decode("utf-8"))
            offset += component_len

        name_type = struct.unpack_from(">I", entry_data, offset)[0]
        offset += 4

        timestamp = struct.unpack_from(">I", entry_data, offset)[0]
        offset += 4

        kvno = struct.unpack_from(">B", entry_data, offset)[0]
        offset += 1

        enctype_int = struct.unpack_from(">H", entry_data, offset)[0]
        offset += 2

        key_len = struct.unpack_from(">H", entry_data, offset)[0]
        offset += 2
        key_bytes = entry_data[offset:offset + key_len]
        offset += key_len

        if len(key_bytes) != key_len:
            raise ValueError("Truncated keytab keyblock")
        if offset + 4 <= len(entry_data):
            kvno32 = struct.unpack_from(">I", entry_data, offset)[0]
            if kvno32:
                kvno = kvno32

    except (struct.error, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid keytab entry: {exc}") from exc

    return {
        "principal": f"{'/'.join(components)}@{realm}",
        "realm": realm,
        "components": components,
        "name_type": name_type,
        "timestamp": timestamp,
        "kvno": kvno,
        "enctype_int": enctype_int,
        "key": key_bytes,
    }


def _coerce_key_bytes(key: str | bytes) -> bytes:
    if isinstance(key, bytes):
        return key
    from core.crypto import str_to_key
    return str_to_key(key)


def _enctype_to_int(enctype: str | int) -> int:
    if isinstance(enctype, int):
        return enctype
    from core.crypto import NAME_TO_ENCTYPE
    if enctype not in NAME_TO_ENCTYPE:
        raise ValueError(f"Unsupported keytab enctype: {enctype}")
    return NAME_TO_ENCTYPE[enctype]


def _split_principal(principal: str, default_realm: str) -> tuple[str, str]:
    if "@" in principal:
        name_part, realm_part = principal.split("@", 1)
    else:
        name_part, realm_part = principal, default_realm
    return name_part, realm_part.upper()


def _principal_matches(entry_principal: str, requested_principal: str) -> bool:
    if "@" not in requested_principal:
        return entry_principal.split("@", 1)[0] == requested_principal
    name_part, realm_part = requested_principal.split("@", 1)
    if "@" not in entry_principal:
        return False
    entry_name, entry_realm = entry_principal.rsplit("@", 1)
    return entry_name == name_part and entry_realm.upper() == realm_part.upper()
