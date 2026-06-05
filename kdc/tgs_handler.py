"""
tgs_handler.py - Ticket-Granting Server (TGS) logic for KDC.

Handles Phase 2 of the Kerberos protocol (TGS Exchange):
    Client sends TGS_REQ with TGT + Authenticator →
    TGS validates → TGS sends TGS_REP with Service Ticket.
"""

import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptography.fernet import InvalidToken

from core.crypto import encrypt, decrypt, generate_session_key, key_to_str, str_to_key
from core.messages import (
    TGS_REP, ERROR,
    KDC_ERR_S_PRINCIPAL_UNKNOWN, KRB_AP_ERR_MODIFIED,
    KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_EXPIRED, KRB_ERR_GENERIC,
    TGS_PRINCIPAL, TICKET_LIFETIME, MAX_CLOCK_SKEW
)


def handle_tgs_request(request: dict, db_cursor) -> dict:
    """
    Process a TGS_REQ and return a TGS_REP with a Service Ticket.

    TGS Exchange Flow:
        1. Client sends TGS_REQ with: service_principal, TGT, authenticator.
        2. TGS decrypts TGT with its own master key → gets client_tgs_session_key.
        3. TGS decrypts authenticator with client_tgs_session_key → validates timestamp.
        4. TGS generates a client-service session key.
        5. TGS creates a service ticket encrypted with the service's master key.
        6. TGS creates TGS_REP encrypted with client_tgs_session_key.

    Args:
        request: The TGS_REQ message dictionary.
        db_cursor: SQLite database cursor for principal lookups.

    Returns:
        TGS_REP or KRB_ERROR message dictionary.
    """
    service_principal = request.get("service_principal")
    encrypted_tgt = request.get("tgt")
    encrypted_authenticator = request.get("authenticator")

    print(f"  [TGS] Received TGS_REQ for service '{service_principal}'")

    # ── Step 1: Get TGS master key and decrypt TGT ───────────────
    db_cursor.execute(
        "SELECT secret_key FROM principals WHERE principal_name = ?",
        (TGS_PRINCIPAL,)
    )
    tgs_row = db_cursor.fetchone()

    if tgs_row is None:
        return _error(KRB_ERR_GENERIC, "Internal error: TGS principal not found.")

    tgs_master_key = str_to_key(tgs_row[0])

    try:
        tgt = decrypt(encrypted_tgt, tgs_master_key)
    except InvalidToken:
        print(f"  [TGS] ERROR: Failed to decrypt TGT (tampered or invalid).")
        return _error(KRB_AP_ERR_MODIFIED, "TGT decryption failed - ticket may be tampered.")

    # ── Step 2: Check TGT expiration ─────────────────────────────
    tgt_timestamp = tgt.get("timestamp", 0)
    tgt_lifetime = tgt.get("lifetime", 0)
    current_time = time.time()

    if current_time > tgt_timestamp + tgt_lifetime:
        print(f"  [TGS] ERROR: TGT has expired.")
        return _error(KRB_AP_ERR_TKT_EXPIRED, "TGT has expired.")

    # ── Step 3: Decrypt authenticator with client-TGS session key ─
    client_tgs_session_key = str_to_key(tgt["client_tgs_session_key"])
    client_principal = tgt["client_principal"]

    try:
        authenticator = decrypt(encrypted_authenticator, client_tgs_session_key)
    except InvalidToken:
        print(f"  [TGS] ERROR: Failed to decrypt authenticator.")
        return _error(KRB_AP_ERR_MODIFIED, "Authenticator decryption failed.")

    # ── Step 4: Validate authenticator ───────────────────────────
    # Check that the principal in authenticator matches the TGT
    if authenticator.get("client_principal") != client_principal:
        print(f"  [TGS] ERROR: Authenticator principal mismatch.")
        return _error(KRB_AP_ERR_MODIFIED, "Authenticator principal does not match TGT.")

    # Check timestamp for replay attack prevention
    auth_timestamp = authenticator.get("timestamp", 0)
    if abs(current_time - auth_timestamp) > MAX_CLOCK_SKEW:
        print(f"  [TGS] ERROR: Clock skew too great (replay attack suspected).")
        return _error(KRB_AP_ERR_SKEW, "Clock skew too great.")

    # ── Step 5: Look up the service's master key ─────────────────
    db_cursor.execute(
        "SELECT secret_key FROM principals WHERE principal_name = ?",
        (service_principal,)
    )
    service_row = db_cursor.fetchone()

    if service_row is None:
        print(f"  [TGS] ERROR: Service principal '{service_principal}' not found.")
        return _error(KDC_ERR_S_PRINCIPAL_UNKNOWN,
                      f"Service principal '{service_principal}' not found.")

    service_master_key = str_to_key(service_row[0])

    # ── Step 6: Generate client-service session key ──────────────
    client_service_session_key = generate_session_key()

    # ── Step 7: Build Service Ticket (encrypted with service key)─
    timestamp = time.time()

    service_ticket_plaintext = {
        "client_principal": client_principal,
        "service_principal": service_principal,
        "client_service_session_key": key_to_str(client_service_session_key),
        "timestamp": timestamp,
        "lifetime": TICKET_LIFETIME
    }

    encrypted_service_ticket = encrypt(service_ticket_plaintext, service_master_key)

    # ── Step 8: Build TGS_REP (encrypted with client-TGS session key)
    tgs_rep_plaintext = {
        "client_service_session_key": key_to_str(client_service_session_key),
        "service_principal": service_principal,
        "timestamp": timestamp,
        "lifetime": TICKET_LIFETIME
    }

    encrypted_tgs_rep = encrypt(tgs_rep_plaintext, client_tgs_session_key)

    print(f"  [TGS] Service Ticket issued for '{client_principal}' → '{service_principal}'")

    return {
        "msg_type": TGS_REP,
        "encrypted_data": encrypted_tgs_rep,
        "service_ticket": encrypted_service_ticket
    }


def _error(code: str, message: str) -> dict:
    """Build an error response dictionary."""
    return {
        "msg_type": "KRB_ERROR",
        "error_code": code,
        "error_message": message
    }
