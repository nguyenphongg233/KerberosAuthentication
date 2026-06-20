"""MIT Credential Cache v4 subset support for Kerberos tickets (ccache)."""

from __future__ import annotations

import json
import os
import struct
import time
from pathlib import Path


DEFAULT_CACHE_PATH = os.getenv(
    "KRB5CCNAME",
    os.path.join(os.path.dirname(__file__), "krb5cc_demo"),
)
DEMO_METADATA_AUTHDATA_TYPE = 0x7FFF


def _pack_principal(principal: str, default_realm: str = "DEMO.LOCAL") -> bytes:
    """Pack a principal string into MIT ccache binary format."""
    if '@' in principal:
        name_part, realm_part = principal.split('@', 1)
    else:
        name_part = principal
        realm_part = default_realm

    components = name_part.split('/')
    
    # 4 bytes: name_type (1)
    # 4 bytes: num_components
    # 4 bytes: realm length + realm bytes
    # For each component: 4 bytes length + component bytes
    data = struct.pack('>II', 1, len(components))
    realm_bytes = realm_part.encode('utf-8')
    data += struct.pack('>I', len(realm_bytes)) + realm_bytes
    for c in components:
        c_bytes = c.encode('utf-8')
        data += struct.pack('>I', len(c_bytes)) + c_bytes
    return data


def _unpack_principal(data: bytes, offset: int) -> tuple[str, int]:
    """Unpack principal from MIT ccache binary data starting at offset."""
    name_type, num_components = struct.unpack_from('>II', data, offset)
    offset += 8
    
    realm_len = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    realm = data[offset:offset+realm_len].decode('utf-8')
    offset += realm_len
    
    components = []
    for _ in range(num_components):
        c_len = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        components.append(data[offset:offset+c_len].decode('utf-8'))
        offset += c_len
        
    principal = '/'.join(components) + '@' + realm
    return principal, offset


def _pack_credential(client: str, server: str, key_bytes: bytes, enctype_int: int,
                     times: dict, ticket: bytes,
                     metadata: dict | None = None) -> bytes:
    """Pack a single credential record into MIT ccache binary format."""
    data = _pack_principal(client)
    data += _pack_principal(server)
    
    # keyblock: keytype (2 bytes) + keyvalue (4 bytes length prefix + bytes)
    data += struct.pack('>H', enctype_int)
    data += struct.pack('>I', len(key_bytes)) + key_bytes
    
    # times: authtime, starttime, endtime, renew_till (4 bytes each)
    authtime = int(times.get("authtime") or 0)
    starttime = int(times.get("starttime") or 0)
    endtime = int(times.get("endtime") or 0)
    renew_till = int(times.get("renew_till") or 0)
    data += struct.pack('>IIII', authtime, starttime, endtime, renew_till)
    
    # is_skey (1 byte)
    data += struct.pack('>B', 0)
    
    # ticket_flags (4 bytes)
    data += struct.pack('>I', 0)
    
    # addresses: count (4 bytes, 0)
    data += struct.pack('>I', 0)
    
    authdata = _pack_demo_metadata(metadata or {})
    data += struct.pack('>I', len(authdata))
    for ad_type, ad_value in authdata:
        data += struct.pack('>H', ad_type)
        data += struct.pack('>I', len(ad_value)) + ad_value
    
    # ticket: 4 bytes length prefix + bytes
    data += struct.pack('>I', len(ticket)) + ticket
    
    # second_ticket: 4 bytes length prefix + bytes (0)
    data += struct.pack('>I', 0)
    
    return data


def _unpack_credential(data: bytes, offset: int) -> tuple[dict, int]:
    """Unpack a single credential record from MIT ccache binary format."""
    client, offset = _unpack_principal(data, offset)
    server, offset = _unpack_principal(data, offset)
    
    keytype = struct.unpack_from('>H', data, offset)[0]
    offset += 2
    
    key_len = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    key_bytes = data[offset:offset+key_len]
    offset += key_len
    
    authtime, starttime, endtime, renew_till = struct.unpack_from('>IIII', data, offset)
    offset += 16
    
    is_skey = struct.unpack_from('>B', data, offset)[0]
    offset += 1
    
    ticket_flags = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    
    # skip addresses
    addr_count = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    for _ in range(addr_count):
        addr_type = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        addr_len = struct.unpack_from('>I', data, offset)[0]
        offset += 4 + addr_len
        
    # authdata
    authdata = []
    auth_count = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    for _ in range(auth_count):
        ad_type = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        ad_len = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        authdata.append({
            "ad_type": ad_type,
            "ad_data": data[offset:offset+ad_len],
        })
        offset += ad_len
        
    # ticket
    tkt_len = struct.unpack_from('>I', data, offset)[0]
    offset += 4
    ticket = data[offset:offset+tkt_len]
    offset += tkt_len
    
    # skip second_ticket
    sec_tkt_len = struct.unpack_from('>I', data, offset)[0]
    offset += 4 + sec_tkt_len
    
    cred = {
        "client": client,
        "server": server,
        "key": key_bytes,
        "keytype": keytype,
        "times": {
            "authtime": authtime,
            "starttime": starttime,
            "endtime": endtime,
            "renew_till": renew_till
        },
        "ticket": ticket,
        "ticket_flags": ticket_flags,
        "authdata": authdata,
    }
    return cred, offset


class CredentialCache:
    """File-backed credential cache implementing a MIT ccache v4 subset."""

    def __init__(self, path: str = DEFAULT_CACHE_PATH):
        self.path = path
        self._tgt = None  # bytes
        self._client_tgs_session_key = None  # bytes
        self._tgt_metadata = {}
        self._service_tickets = {}
        self._load()

    def store_tgt(self, tgt: bytes, client_tgs_session_key: bytes,
                  metadata: dict | None = None):
        self._tgt = tgt
        self._client_tgs_session_key = client_tgs_session_key
        self._tgt_metadata = metadata or {}
        self._service_tickets.clear()
        self._save()

    def get_tgt(self, allow_expired: bool = False) -> tuple:
        if self._tgt is None:
            return None, None
        if allow_expired:
            renew_till = float(self._tgt_metadata.get("renew_till", 0))
            if renew_till and time.time() > renew_till:
                self.clear()
                return None, None
        else:
            if self._expired(self._tgt_metadata):
                self.clear()
                return None, None
        return self._tgt, self._client_tgs_session_key

    def get_tgt_metadata(self) -> dict:
        return dict(self._tgt_metadata)

    def store_service_ticket(self, service_principal: str,
                              service_ticket: bytes,
                              client_service_session_key: bytes,
                              metadata: dict | None = None):
        self._service_tickets[service_principal] = {
            "ticket": service_ticket,
            "session_key": client_service_session_key,
            "metadata": metadata or {},
        }
        self._save()

    def get_service_ticket(self, service_principal: str) -> tuple:
        entry = self._service_tickets.get(service_principal)
        if not entry:
            return None, None
        if self._expired(entry.get("metadata", {})):
            del self._service_tickets[service_principal]
            self._save()
            return None, None
        return entry["ticket"], entry["session_key"]

    def get_service_ticket_metadata(self, service_principal: str) -> dict:
        entry = self._service_tickets.get(service_principal)
        if not entry:
            return {}
        return dict(entry.get("metadata", {}))

    def list_service_tickets(self) -> list[tuple[str, dict]]:
        """Return non-expired service ticket principals and metadata."""
        tickets = []
        for principal in list(self._service_tickets):
            ticket, _session_key = self.get_service_ticket(principal)
            if ticket is None:
                continue
            tickets.append((principal, dict(self._service_tickets[principal].get("metadata", {}))))
        return tickets

    def clear(self):
        self._tgt = None
        self._client_tgs_session_key = None
        self._tgt_metadata = {}
        self._service_tickets.clear()
        
        # If cache file exists, delete it or rewrite it empty
        if os.path.exists(self.path):
            try:
                os.remove(self.path)
            except OSError:
                pass
        self._save()

    def has_tgt(self) -> bool:
        tgt, _ = self.get_tgt()
        return tgt is not None

    def has_service_ticket(self, service_principal: str) -> bool:
        ticket, _ = self.get_service_ticket(service_principal)
        return ticket is not None

    def _expired(self, metadata: dict) -> bool:
        try:
            endtime = float(metadata.get("endtime", 0))
        except (TypeError, ValueError):
            return False
        return bool(endtime) and time.time() > endtime

    def _load(self):
        if not os.path.exists(self.path):
            return
        
        try:
            with open(self.path, 'rb') as f:
                data = f.read()
            if len(data) < 4:
                return
            
            format_version, header_len = struct.unpack_from('>HH', data, 0)
            if format_version != 0x0504:
                # Legacy or invalid cache format
                return
                
            offset = 4 + header_len
            
            default_p, offset = _unpack_principal(data, offset)
            
            while offset < len(data):
                cred, offset = _unpack_credential(data, offset)
                from core.crypto import ENCTYPE_TO_NAME
                enctype_name = ENCTYPE_TO_NAME.get(cred["keytype"], "aes256-cts-hmac-sha1-96")
                
                # Check if it is a TGT (server principal starts with krbtgt/)
                if cred["server"].startswith("krbtgt/"):
                    self._tgt = cred["ticket"]
                    self._client_tgs_session_key = cred["key"]
                    self._tgt_metadata = _credential_metadata(cred, enctype_name)
                    self._tgt_metadata.update({
                        "enctype": enctype_name,
                        "ticket_enctype": cred["keytype"],
                        "authtime": cred["times"]["authtime"],
                        "starttime": cred["times"]["starttime"],
                        "endtime": cred["times"]["endtime"],
                        "renew_till": cred["times"]["renew_till"]
                    })
                else:
                    self._service_tickets[cred["server"]] = {
                        "ticket": cred["ticket"],
                        "session_key": cred["key"],
                        "metadata": _credential_metadata(cred, enctype_name) | {
                            "enctype": enctype_name,
                            "ticket_enctype": cred["keytype"],
                            "authtime": cred["times"]["authtime"],
                            "starttime": cred["times"]["starttime"],
                            "endtime": cred["times"]["endtime"],
                            "renew_till": cred["times"]["renew_till"]
                        }
                    }
        except Exception as e:
            # Corrupted cache -> clear and rewrite
            print(f"[Client] Warning: Failed to load binary cache ({e}), clearing...")
            self.clear()

    def _save(self):
        # Ensure directory exists
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        
        # We pack default principal
        # In this demo, we determine the client principal from the global state or metadata
        try:
            from client.client_app import client_principal_global
            default_p = client_principal_global or "alice@DEMO.LOCAL"
        except ImportError:
            default_p = "alice@DEMO.LOCAL"
            
        # File header: format version 0x0504, header length 0
        data = struct.pack('>HH', 0x0504, 0)
        data += _pack_principal(default_p)
        
        # Save TGT if present
        if self._tgt is not None and self._client_tgs_session_key is not None:
            # Server principal is local TGS principal
            from core.messages import REALM
            from core.principal import principal_realm
            client_realm = principal_realm(default_p, REALM)
            tgs_princ = f"krbtgt/{client_realm}@{client_realm}"
            
            enctype_int = _metadata_keytype(self._tgt_metadata)
            
            data += _pack_credential(
                default_p,
                tgs_princ,
                self._client_tgs_session_key,
                enctype_int,
                self._tgt_metadata,
                self._tgt,
                self._tgt_metadata,
            )
            
        # Save service tickets
        for service_principal, entry in self._service_tickets.items():
            enctype_int = _metadata_keytype(entry["metadata"])
            
            data += _pack_credential(
                default_p,
                service_principal,
                entry["session_key"],
                enctype_int,
                entry["metadata"],
                entry["ticket"],
                entry["metadata"],
            )
            
        with open(self.path, 'wb') as f:
            f.write(data)


def _metadata_keytype(metadata: dict) -> int:
    key_info = metadata.get("key")
    if isinstance(key_info, dict) and key_info.get("keytype") is not None:
        return int(key_info["keytype"])

    enctype = metadata.get("enctype")
    if isinstance(enctype, int):
        return enctype
    if isinstance(enctype, str):
        from core.crypto import NAME_TO_ENCTYPE
        return NAME_TO_ENCTYPE.get(enctype, 18)
    return 18


def _pack_demo_metadata(metadata: dict) -> list[tuple[int, bytes]]:
    """Store demo-only metadata in a ccache authdata slot.

    MIT ccache credentials do not expose the ticket kvno as a first-class field.
    The encrypted ticket bytes are still stored in the normal ticket field; this
    small extension keeps enough metadata for this demo client to rebuild outer
    Ticket fields after a cache reload.
    """
    keys = [
        "ticket_enctype",
        "ticket_kvno",
        "tgt_enctype",
        "tgt_kvno",
        "service_ticket_enctype",
        "service_ticket_kvno",
        "client_principal",
        "server_principal",
        "service_principal",
    ]
    payload = {key: metadata[key] for key in keys if metadata.get(key) is not None}
    if not payload:
        return []
    return [
        (
            DEMO_METADATA_AUTHDATA_TYPE,
            json.dumps(payload, sort_keys=True).encode("utf-8"),
        )
    ]


def _credential_metadata(cred: dict, enctype_name: str) -> dict:
    metadata = {}
    for item in cred.get("authdata", []):
        if item.get("ad_type") != DEMO_METADATA_AUTHDATA_TYPE:
            continue
        try:
            decoded = json.loads(item["ad_data"].decode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
            continue
        if isinstance(decoded, dict):
            metadata.update(decoded)
    metadata.setdefault("enctype", enctype_name)
    metadata.setdefault("ticket_enctype", cred["keytype"])
    return metadata
