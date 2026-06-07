"""Simple JSON keytab support for service principals."""

from __future__ import annotations

import json
import os
from pathlib import Path


def write_keytab(path: str, principal: str, key: str, kvno: int,
                 enctype: str, realm: str) -> None:
    """Write a single-principal JSON keytab."""
    keytab_path = Path(path)
    keytab_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "format": "kerberos-demo-keytab-v1",
        "entries": [
            {
                "principal": principal,
                "realm": realm,
                "kvno": kvno,
                "enctype": enctype,
                "key": key,
            }
        ],
    }
    keytab_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_keytab(path: str, principal: str) -> dict:
    """Load a principal entry from a JSON keytab."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Keytab not found: {path}")

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    for entry in payload.get("entries", []):
        if entry.get("principal") == principal:
            return entry

    raise KeyError(f"Principal '{principal}' not found in keytab: {path}")
