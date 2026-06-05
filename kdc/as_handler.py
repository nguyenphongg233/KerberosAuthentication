"""
as_handler.py - Authentication Server (AS) logic for KDC.

Handles Phase 1 of the Kerberos protocol (AS Exchange):
    Client sends AS_REQ → AS verifies identity → AS sends AS_REP with TGT.
"""

import time
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.crypto import encrypt, decrypt, generate_session_key, key_to_str, str_to_key
from core.messages import (
    AS_REP, ERROR,
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KRB_ERR_GENERIC,
    TGS_PRINCIPAL, TICKET_LIFETIME
)


def handle_as_request(request: dict, db_cursor) -> dict:
    """
    Process an AS_REQ and return an AS_REP with a TGT.

    AS Exchange Flow:
        1. Client sends AS_REQ with client_principal.
        2. AS looks up the client's master key in the database.
        3. AS generates a client-TGS session key.
        4. AS creates a TGT encrypted with the TGS master key.
        5. AS creates AS_REP encrypted with the client's master key.

    Args:
        request: The AS_REQ message dictionary.
        db_cursor: SQLite database cursor for principal lookups.

    Returns:
        AS_REP or KRB_ERROR message dictionary.
    """
    client_principal = request.get("client_principal")

    print(f"  [AS] Received AS_REQ from '{client_principal}'")

    # ── Step 1: Look up the client's master key ──────────────────
    db_cursor.execute(
        "SELECT secret_key FROM principals WHERE principal_name = ?",
        (client_principal,)
    )
    row = db_cursor.fetchone()

    if row is None:
        print(f"  [AS] ERROR: Client '{client_principal}' not found in database.")
        return {
            "msg_type": ERROR,
            "error_code": KDC_ERR_C_PRINCIPAL_UNKNOWN,
            "error_message": f"Client principal '{client_principal}' not found."
        }

    client_master_key = str_to_key(row[0])

    # ── Step 2: Look up the TGS master key ───────────────────────
    db_cursor.execute(
        "SELECT secret_key FROM principals WHERE principal_name = ?",
        (TGS_PRINCIPAL,)
    )
    tgs_row = db_cursor.fetchone()

    if tgs_row is None:
        print(f"  [AS] ERROR: TGS principal '{TGS_PRINCIPAL}' not found.")
        return {
            "msg_type": ERROR,
            "error_code": KRB_ERR_GENERIC,
            "error_message": "Internal error: TGS principal not found."
        }

    tgs_master_key = str_to_key(tgs_row[0])

    # ── Step 3: Generate a session key for Client ↔ TGS ─────────
    client_tgs_session_key = generate_session_key()

    # ── Step 4: Build the TGT (encrypted with TGS master key) ───
    timestamp = time.time()

    tgt_plaintext = {
        "client_principal": client_principal,
        "tgs_principal": TGS_PRINCIPAL,
        "client_tgs_session_key": key_to_str(client_tgs_session_key),
        "timestamp": timestamp,
        "lifetime": TICKET_LIFETIME
    }

    encrypted_tgt = encrypt(tgt_plaintext, tgs_master_key)

    # ── Step 5: Build AS_REP (encrypted with client's master key)─
    as_rep_plaintext = {
        "client_tgs_session_key": key_to_str(client_tgs_session_key),
        "tgs_principal": TGS_PRINCIPAL,
        "timestamp": timestamp,
        "lifetime": TICKET_LIFETIME
    }

    encrypted_as_rep = encrypt(as_rep_plaintext, client_master_key)

    print(f"  [AS] TGT issued for '{client_principal}'. Lifetime: {TICKET_LIFETIME}s")

    return {
        "msg_type": AS_REP,
        "encrypted_data": encrypted_as_rep,
        "tgt": encrypted_tgt
    }
