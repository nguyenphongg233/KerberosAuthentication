"""
as_handler.py - Authentication Server (AS) logic for the demo KDC.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.fernet import InvalidToken

from core.crypto import decrypt, encrypt, generate_session_key, key_to_str, str_to_key
from core.messages import (
    AS_REP,
    DEFAULT_TICKET_FLAGS,
    ERROR,
    KDC_ERR_C_PRINCIPAL_UNKNOWN,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_WRONG_REALM,
    KRB_AP_ERR_SKEW,
    KRB_ERR_GENERIC,
    MAX_CLOCK_SKEW,
    REALM,
    RENEWABLE_LIFETIME,
    TGS_PRINCIPAL,
    TICKET_LIFETIME,
)
from kdc.database import audit_event, get_principal


def handle_as_request(request: dict, db_cursor) -> dict:
    """
    Process AS_REQ and return AS_REP with a TGT.

    The demo models RFC 4120 concepts with JSON/Fernet rather than ASN.1/DER:
    cname/realm, pre-authentication, nonce, ticket flags, endtime and renew_till.
    """
    requested_principal = request.get("client_principal")
    requested_realm = str(request.get("realm", REALM)).upper()
    request_nonce = request.get("nonce")
    encrypted_preauth = request.get("preauth")

    print(f"  [AS] Received AS_REQ from '{requested_principal}'")

    if requested_realm != REALM:
        audit_event(db_cursor, "AS", "as_req", requested_principal, "failure",
                    {"error": KDC_ERR_WRONG_REALM, "realm": requested_realm})
        return _error(KDC_ERR_WRONG_REALM,
                      f"KDC does not serve realm '{requested_realm}'.")

    client_record = get_principal(db_cursor, requested_principal)
    if client_record is None:
        print(f"  [AS] ERROR: Client '{requested_principal}' not found.")
        audit_event(db_cursor, "AS", "as_req", requested_principal, "failure",
                    {"error": KDC_ERR_C_PRINCIPAL_UNKNOWN})
        return _error(KDC_ERR_C_PRINCIPAL_UNKNOWN,
                      f"Client principal '{requested_principal}' not found.")

    client_principal = client_record["principal_name"]
    client_master_key = str_to_key(client_record["key"])

    if not encrypted_preauth:
        print("  [AS] ERROR: Missing pre-authentication data.")
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": "missing_preauth"})
        return _error(KDC_ERR_PREAUTH_FAILED, "Missing pre-authentication data.")

    try:
        preauth = decrypt(encrypted_preauth, client_master_key)
    except InvalidToken:
        print(f"  [AS] ERROR: Pre-authentication failed for '{client_principal}'.")
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": "invalid_token"})
        return _error(KDC_ERR_PREAUTH_FAILED, "Pre-authentication failed.")

    if preauth.get("client_principal") != client_principal:
        print("  [AS] ERROR: Pre-authentication principal mismatch.")
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": "principal_mismatch"})
        return _error(KDC_ERR_PREAUTH_FAILED,
                      "Pre-authentication principal mismatch.")

    if str(preauth.get("realm", REALM)).upper() != REALM:
        print("  [AS] ERROR: Pre-authentication realm mismatch.")
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": "realm_mismatch"})
        return _error(KDC_ERR_WRONG_REALM, "Pre-authentication realm mismatch.")

    try:
        preauth_timestamp = float(preauth.get("timestamp", 0))
    except (TypeError, ValueError):
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": "invalid_timestamp"})
        return _error(KRB_AP_ERR_SKEW, "Invalid pre-authentication timestamp.")

    now = time.time()
    if abs(now - preauth_timestamp) > MAX_CLOCK_SKEW:
        print("  [AS] ERROR: Pre-authentication clock skew too great.")
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": KRB_AP_ERR_SKEW})
        return _error(KRB_AP_ERR_SKEW,
                      "Pre-authentication clock skew too great.")

    tgs_record = get_principal(db_cursor, TGS_PRINCIPAL)
    if tgs_record is None:
        print(f"  [AS] ERROR: TGS principal '{TGS_PRINCIPAL}' not found.")
        audit_event(db_cursor, "AS", "as_req", client_principal, "failure",
                    {"error": "missing_tgs_principal"})
        return _error(KRB_ERR_GENERIC, "Internal error: TGS principal not found.")

    tgs_master_key = str_to_key(tgs_record["key"])
    client_tgs_session_key = generate_session_key()

    authtime = now
    starttime = now
    endtime = now + TICKET_LIFETIME
    renew_till = now + RENEWABLE_LIFETIME
    flags = list(DEFAULT_TICKET_FLAGS)

    tgt_plaintext = {
        "ticket_type": "TGT",
        "realm": REALM,
        "client_principal": client_principal,
        "server_principal": TGS_PRINCIPAL,
        "tgs_principal": TGS_PRINCIPAL,
        "client_tgs_session_key": key_to_str(client_tgs_session_key),
        "authtime": authtime,
        "starttime": starttime,
        "endtime": endtime,
        "renew_till": renew_till,
        "timestamp": authtime,
        "lifetime": TICKET_LIFETIME,
        "flags": flags,
        "kvno": tgs_record["kvno"],
        "enctype": tgs_record["enctype"],
    }

    encrypted_tgt = encrypt(tgt_plaintext, tgs_master_key)

    as_rep_plaintext = {
        "realm": REALM,
        "client_principal": client_principal,
        "server_principal": TGS_PRINCIPAL,
        "client_tgs_session_key": key_to_str(client_tgs_session_key),
        "tgs_principal": TGS_PRINCIPAL,
        "authtime": authtime,
        "starttime": starttime,
        "endtime": endtime,
        "renew_till": renew_till,
        "timestamp": authtime,
        "lifetime": TICKET_LIFETIME,
        "flags": flags,
        "nonce": request_nonce,
        "enctype": tgs_record["enctype"],
    }

    encrypted_as_rep = encrypt(as_rep_plaintext, client_master_key)

    audit_event(db_cursor, "AS", "tgt_issued", client_principal, "success",
                {"server": TGS_PRINCIPAL, "endtime": endtime, "flags": flags})
    print(f"  [AS] TGT issued for '{client_principal}'. Lifetime: {TICKET_LIFETIME}s")

    return {
        "msg_type": AS_REP,
        "realm": REALM,
        "client_principal": client_principal,
        "encrypted_data": encrypted_as_rep,
        "tgt": encrypted_tgt,
    }


def _error(code: str, message: str) -> dict:
    return {
        "msg_type": ERROR,
        "error_code": code,
        "error_message": message,
    }
