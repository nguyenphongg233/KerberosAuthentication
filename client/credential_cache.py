"""Persistent credential cache for the Kerberos demo client."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from core.crypto import key_to_str, str_to_key


DEFAULT_CACHE_PATH = os.getenv(
    "KRB5CCNAME",
    os.path.join(os.path.dirname(__file__), "krb5cc_demo.json"),
)


class CredentialCache:
    """
    Minimal file-backed credential cache.

    This is intentionally simpler than a real Kerberos credential cache, but it
    persists TGTs and service tickets across client process runs until ticket
    endtime or manual cache clearing.
    """

    def __init__(self, path: str = DEFAULT_CACHE_PATH):
        self.path = path
        self._tgt = None
        self._client_tgs_session_key = None
        self._tgt_metadata = {}
        self._service_tickets = {}
        self._load()

    def store_tgt(self, tgt: str, client_tgs_session_key: bytes,
                  metadata: dict | None = None):
        self._tgt = tgt
        self._client_tgs_session_key = client_tgs_session_key
        self._tgt_metadata = metadata or {}
        self._save()

    def get_tgt(self) -> tuple:
        if self._tgt is None:
            return None, None
        if self._expired(self._tgt_metadata):
            self._tgt = None
            self._client_tgs_session_key = None
            self._tgt_metadata = {}
            self._save()
            return None, None
        return self._tgt, self._client_tgs_session_key

    def store_service_ticket(self, service_principal: str,
                             service_ticket: str,
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

    def clear(self):
        self._tgt = None
        self._client_tgs_session_key = None
        self._tgt_metadata = {}
        self._service_tickets.clear()
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
            payload = json.loads(Path(self.path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        tgt_payload = payload.get("tgt")
        if tgt_payload:
            self._tgt = tgt_payload.get("ticket")
            key_text = tgt_payload.get("session_key")
            self._client_tgs_session_key = str_to_key(key_text) if key_text else None
            self._tgt_metadata = tgt_payload.get("metadata", {})

        for service_principal, entry in payload.get("service_tickets", {}).items():
            key_text = entry.get("session_key")
            if key_text:
                self._service_tickets[service_principal] = {
                    "ticket": entry.get("ticket"),
                    "session_key": str_to_key(key_text),
                    "metadata": entry.get("metadata", {}),
                }

    def _save(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        service_tickets = {}
        for service_principal, entry in self._service_tickets.items():
            service_tickets[service_principal] = {
                "ticket": entry["ticket"],
                "session_key": key_to_str(entry["session_key"]),
                "metadata": entry.get("metadata", {}),
            }

        payload = {
            "format": "kerberos-demo-ccache-v1",
            "tgt": None,
            "service_tickets": service_tickets,
        }
        if self._tgt and self._client_tgs_session_key:
            payload["tgt"] = {
                "ticket": self._tgt,
                "session_key": key_to_str(self._client_tgs_session_key),
                "metadata": self._tgt_metadata,
            }

        Path(self.path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
