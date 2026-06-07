"""
tgs_handler.py - Ticket Granting Server (TGS) logic for the demo KDC.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.fernet import InvalidToken

from core.crypto import decrypt, encrypt, generate_session_key, key_to_str, str_to_key
from core.messages import (
    ERROR,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_WRONG_REALM,
    KRB_AP_ERR_MODIFIED,
    KRB_AP_ERR_REPEAT,
    KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED,
    MAX_CLOCK_SKEW,
    REALM,
    SERVICE_TICKET_FLAGS,
    TGS_PRINCIPAL,
    TGS_REP,
    TICKET_LIFETIME,
)
from core.replay_cache import authenticator_cache_key, check_and_store
from kdc.database import audit_event, get_principal


def handle_tgs_request(request: dict, db_cursor) -> dict:
    """Process TGS_REQ and return TGS_REP with a service ticket."""
    requested_service = request.get("service_principal")
    requested_realm = str(request.get("realm", REALM)).upper()
    encrypted_tgt = request.get("tgt")
    encrypted_authenticator = request.get("authenticator")
    request_nonce = request.get("nonce")

    print(f"  [TGS] Received TGS_REQ for service '{requested_service}'")

    if not requested_service or not encrypted_tgt or not encrypted_authenticator:
        return _error(KRB_AP_ERR_MODIFIED,
                      "TGS_REQ missing service principal, TGT, or authenticator.")

    if requested_realm != REALM:
        audit_event(db_cursor, "TGS", "tgs_req", None, "failure",
                    {"error": KDC_ERR_WRONG_REALM, "realm": requested_realm})
        return _error(KDC_ERR_WRONG_REALM,
                      f"KDC does not serve realm '{requested_realm}'.")

    tgs_record = get_principal(db_cursor, TGS_PRINCIPAL)
    if tgs_record is None:
        return _error(KRB_AP_ERR_MODIFIED,
                      "Internal error: TGS principal not found.")

    tgs_master_key = str_to_key(tgs_record["key"])
    try:
        tgt = decrypt(encrypted_tgt, tgs_master_key)
    except InvalidToken:
        print("  [TGS] ERROR: Failed to decrypt TGT.")
        audit_event(db_cursor, "TGS", "tgt_decrypt", None, "failure",
                    {"error": KRB_AP_ERR_MODIFIED})
        return _error(KRB_AP_ERR_MODIFIED,
                      "TGT decryption failed - ticket may be tampered.")

    if tgt.get("server_principal", tgt.get("tgs_principal")) != TGS_PRINCIPAL:
        audit_event(db_cursor, "TGS", "tgt_validate",
                    tgt.get("client_principal"), "failure",
                    {"error": "wrong_tgs_principal"})
        return _error(KRB_AP_ERR_MODIFIED, "TGT is not for this TGS.")

    if str(tgt.get("realm", REALM)).upper() != REALM:
        audit_event(db_cursor, "TGS", "tgt_validate",
                    tgt.get("client_principal"), "failure",
                    {"error": "wrong_realm"})
        return _error(KDC_ERR_WRONG_REALM, "TGT is for another realm.")

    client_principal = tgt.get("client_principal")
    session_key_text = tgt.get("client_tgs_session_key")
    if not client_principal or not session_key_text:
        return _error(KRB_AP_ERR_MODIFIED, "Malformed TGT.")

    now = time.time()
    if _ticket_expired(tgt, now):
        print("  [TGS] ERROR: TGT has expired.")
        audit_event(db_cursor, "TGS", "tgt_validate", client_principal,
                    "failure", {"error": KRB_AP_ERR_TKT_EXPIRED})
        return _error(KRB_AP_ERR_TKT_EXPIRED, "TGT has expired.")

    client_tgs_session_key = str_to_key(session_key_text)
    try:
        authenticator = decrypt(encrypted_authenticator, client_tgs_session_key)
    except InvalidToken:
        print("  [TGS] ERROR: Failed to decrypt authenticator.")
        audit_event(db_cursor, "TGS", "authenticator_decrypt",
                    client_principal, "failure",
                    {"error": KRB_AP_ERR_MODIFIED})
        return _error(KRB_AP_ERR_MODIFIED, "Authenticator decryption failed.")

    auth_client = authenticator.get("client_principal")
    if auth_client != client_principal:
        print("  [TGS] ERROR: Authenticator principal mismatch.")
        return _error(KRB_AP_ERR_MODIFIED,
                      "Authenticator principal does not match TGT.")

    auth_timestamp = _authenticator_timestamp(authenticator)
    if auth_timestamp is None:
        return _error(KRB_AP_ERR_MODIFIED, "Invalid authenticator timestamp.")

    if abs(now - auth_timestamp) > MAX_CLOCK_SKEW:
        print("  [TGS] ERROR: Clock skew too great.")
        audit_event(db_cursor, "TGS", "authenticator_validate",
                    client_principal, "failure",
                    {"error": KRB_AP_ERR_SKEW})
        return _error(KRB_AP_ERR_SKEW, "Clock skew too great.")

    cache_key = authenticator_cache_key(
        client_principal,
        requested_service,
        auth_timestamp,
        authenticator.get("cusec"),
    )
    if check_and_store("TGS", cache_key, client_principal, requested_service,
                       auth_timestamp, now, MAX_CLOCK_SKEW):
        print("  [TGS] ERROR: Replayed authenticator detected.")
        audit_event(db_cursor, "TGS", "authenticator_replay",
                    client_principal, "failure",
                    {"service": requested_service})
        return _error(KRB_AP_ERR_REPEAT, "Replayed authenticator detected.")

    service_record = get_principal(db_cursor, requested_service)
    if service_record is None or service_record["principal_type"] != "service":
        print(f"  [TGS] ERROR: Service principal '{requested_service}' not found.")
        audit_event(db_cursor, "TGS", "service_lookup", client_principal,
                    "failure", {"service": requested_service})
        return _error(KDC_ERR_S_PRINCIPAL_UNKNOWN,
                      f"Service principal '{requested_service}' not found.")

    service_principal = service_record["principal_name"]
    service_master_key = str_to_key(service_record["key"])
    client_service_session_key = generate_session_key()

    starttime = now
    endtime = min(now + TICKET_LIFETIME, float(tgt.get("endtime", now + TICKET_LIFETIME)))
    flags = _service_flags(tgt)

    service_ticket_plaintext = {
        "ticket_type": "SERVICE",
        "realm": REALM,
        "client_principal": client_principal,
        "server_principal": service_principal,
        "service_principal": service_principal,
        "client_service_session_key": key_to_str(client_service_session_key),
        "authtime": tgt.get("authtime", now),
        "starttime": starttime,
        "endtime": endtime,
        "timestamp": starttime,
        "lifetime": max(0, endtime - starttime),
        "flags": flags,
        "kvno": service_record["kvno"],
        "enctype": service_record["enctype"],
    }

    encrypted_service_ticket = encrypt(service_ticket_plaintext, service_master_key)

    tgs_rep_plaintext = {
        "realm": REALM,
        "client_principal": client_principal,
        "server_principal": service_principal,
        "service_principal": service_principal,
        "client_service_session_key": key_to_str(client_service_session_key),
        "starttime": starttime,
        "endtime": endtime,
        "timestamp": starttime,
        "lifetime": max(0, endtime - starttime),
        "flags": flags,
        "nonce": request_nonce,
        "enctype": service_record["enctype"],
    }

    encrypted_tgs_rep = encrypt(tgs_rep_plaintext, client_tgs_session_key)

    audit_event(db_cursor, "TGS", "service_ticket_issued", client_principal,
                "success", {"service": service_principal, "endtime": endtime})
    print(f"  [TGS] Service Ticket issued for '{client_principal}' -> '{service_principal}'")

    return {
        "msg_type": TGS_REP,
        "realm": REALM,
        "client_principal": client_principal,
        "service_principal": service_principal,
        "encrypted_data": encrypted_tgs_rep,
        "service_ticket": encrypted_service_ticket,
    }


def _ticket_expired(ticket: dict, now: float) -> bool:
    try:
        endtime = float(ticket.get("endtime", 0))
    except (TypeError, ValueError):
        return True
    return now > endtime


def _authenticator_timestamp(authenticator: dict) -> float | None:
    try:
        if "ctime" in authenticator:
            return float(authenticator["ctime"]) + (int(authenticator.get("cusec", 0)) / 1_000_000)
        return float(authenticator.get("timestamp", 0))
    except (TypeError, ValueError):
        return None


def _service_flags(tgt: dict) -> list[str]:
    flags = list(SERVICE_TICKET_FLAGS)
    if "forwardable" in tgt.get("flags", []):
        flags.append("forwardable")
    if "renewable" in tgt.get("flags", []):
        flags.append("renewable")
    return list(dict.fromkeys(flags))


def _error(code: str, message: str) -> dict:
    return {
        "msg_type": ERROR,
        "error_code": code,
        "error_message": message,
    }
