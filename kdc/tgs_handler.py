"""
tgs_handler.py - Ticket Granting Server (TGS) logic for KDC (RFC 4120 compliant).
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crypto import (
    decrypt,
    encrypt,
    generate_session_key,
    key_to_str,
    str_to_key,
    InvalidToken,
    KEY_USAGE_TICKET,
    KEY_USAGE_TGS_REQ_AUTH,
    KEY_USAGE_TGS_REP_ENCPART,
    DEFAULT_ENCTYPE,
)
from core.asn1_codec import (
    decode_enc_ticket_part,
    decode_authenticator,
    encode_enc_ticket_part,
    encode_enc_kdc_rep_part,
)
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
    
    tgt_enctype = request.get("tgt_enctype", DEFAULT_ENCTYPE)
    auth_enctype = request.get("authenticator_enctype", DEFAULT_ENCTYPE)

    print(f"  [TGS] Received TGS_REQ for service '{requested_service}'")

    if not requested_service or not encrypted_tgt or not encrypted_authenticator:
        return _error(KRB_AP_ERR_MODIFIED,
                      "TGS_REQ missing service principal, TGT, or authenticator.")

    # Allow KDC to serve both DEMO.LOCAL and PARTNER.LOCAL realms
    ALLOWED_REALMS = [REALM, "PARTNER.LOCAL"]
    if requested_realm not in ALLOWED_REALMS:
        audit_event(db_cursor, "TGS", "tgs_req", None, "failure",
                    {"error": KDC_ERR_WRONG_REALM, "realm": requested_realm})
        return _error(KDC_ERR_WRONG_REALM,
                      f"KDC does not serve realm '{requested_realm}'.")

    # Determine TGS decryption principal based on requested tgt_service_principal
    tgt_service = request.get("tgt_service_principal") or TGS_PRINCIPAL
    
    tgs_record = get_principal(db_cursor, tgt_service)
    if tgs_record is None:
        # Fallback to local TGS principal
        tgs_record = get_principal(db_cursor, TGS_PRINCIPAL)
        
    if tgs_record is None:
        return _error(KRB_AP_ERR_MODIFIED,
                      "Internal error: TGS principal not found.")

    tgs_master_key = str_to_key(tgs_record["key"])
    try:
        # Decrypt TGT using KEY_USAGE_TICKET (2)
        tgt_der = decrypt(encrypted_tgt, tgs_master_key, KEY_USAGE_TICKET)
        tgt = decode_enc_ticket_part(tgt_der)
    except InvalidToken:
        print(f"  [TGS] ERROR: Failed to decrypt TGT using principal '{tgt_service}'.")
        audit_event(db_cursor, "TGS", "tgt_decrypt", None, "failure",
                    {"error": KRB_AP_ERR_MODIFIED})
        return _error(KRB_AP_ERR_MODIFIED,
                      "TGT decryption failed - ticket may be tampered.")

    # Cross-Realm validation:
    tgt_realm = str(tgt.get("realm", REALM)).upper()
    is_cross_realm_ok = False
    
    # Check if tgt_service is an inter-realm principal e.g., krbtgt/PARTNER.LOCAL@DEMO.LOCAL
    if tgt_service.startswith("krbtgt/") and "@" in tgt_service:
        tgs_srv_name, tgs_srv_realm = tgt_service.split("@", 1)
        if tgs_srv_realm == tgt_realm and tgs_srv_name == f"krbtgt/{requested_realm}":
            is_cross_realm_ok = True
            
    if tgt_realm != requested_realm and not is_cross_realm_ok:
        audit_event(db_cursor, "TGS", "tgt_validate",
                    tgt.get("client_principal"), "failure",
                    {"error": "wrong_realm"})
        return _error(KDC_ERR_WRONG_REALM, "TGT is for another realm.")

    client_principal = tgt.get("client_principal")
    session_key_bytes = tgt["key"]["keyvalue"]
    session_enctype = tgt["key"]["keytype"]
    
    if not client_principal or not session_key_bytes:
        return _error(KRB_AP_ERR_MODIFIED, "Malformed TGT.")

    kdc_options = request.get("kdc_options", [])
    is_renew_req = "renew" in kdc_options

    now = time.time()
    if is_renew_req:
        if "renewable" not in tgt.get("flags", []):
            print("  [TGS] ERROR: TGT is not renewable.")
            audit_event(db_cursor, "TGS", "tgt_validate", client_principal,
                        "failure", {"error": "ticket_not_renewable"})
            return _error(KRB_AP_ERR_TKT_EXPIRED, "TGT is not renewable.")
        
        renew_till = float(tgt.get("renew_till", 0))
        if now > renew_till:
            print("  [TGS] ERROR: TGT renew-till has passed.")
            audit_event(db_cursor, "TGS", "tgt_validate", client_principal,
                        "failure", {"error": "renew_till_passed"})
            return _error(KRB_AP_ERR_TKT_EXPIRED, "TGT renewal limit exceeded.")
    else:
        if _ticket_expired(tgt, now):
            print("  [TGS] ERROR: TGT has expired.")
            audit_event(db_cursor, "TGS", "tgt_validate", client_principal,
                        "failure", {"error": KRB_AP_ERR_TKT_EXPIRED})
            return _error(KRB_AP_ERR_TKT_EXPIRED, "TGT has expired.")

    try:
        # Decrypt Authenticator using TGS session key and KEY_USAGE_TGS_REQ_AUTH (7)
        auth_der = decrypt(encrypted_authenticator, session_key_bytes, KEY_USAGE_TGS_REQ_AUTH)
        authenticator = decode_authenticator(auth_der)
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

    auth_timestamp = authenticator.get("ctime")
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

    if is_renew_req:
        # Perform TGT Renewal
        new_session_key = generate_session_key(session_enctype)
        renew_till = float(tgt.get("renew_till", 0))
        endtime = min(now + TICKET_LIFETIME, renew_till)
        
        tgt_plaintext = {
            "flags": tgt.get("flags", []),
            "key": {
                "keytype": session_enctype,
                "keyvalue": new_session_key,
            },
            "realm": REALM,
            "client_principal": client_principal,
            "authtime": tgt.get("authtime", now),
            "starttime": now,
            "endtime": endtime,
            "renew_till": renew_till,
            "authorization_data": tgt.get("authorization_data", []),
        }
        tgt_der = encode_enc_ticket_part(tgt_plaintext)
        encrypted_new_tgt = encrypt(tgt_der, tgs_master_key, KEY_USAGE_TICKET)

        tgs_rep_plaintext = {
            "key": {
                "keytype": session_enctype,
                "keyvalue": new_session_key,
            },
            "nonce": request_nonce,
            "flags": tgt_plaintext["flags"],
            "authtime": tgt.get("authtime", now),
            "starttime": now,
            "endtime": endtime,
            "renew_till": renew_till,
            "realm": REALM,
            "service_principal": TGS_PRINCIPAL,
        }
        tgs_rep_der = encode_enc_kdc_rep_part(tgs_rep_plaintext, TGS_REP)
        encrypted_tgs_rep = encrypt(tgs_rep_der, session_key_bytes, KEY_USAGE_TGS_REP_ENCPART)

        audit_event(db_cursor, "TGS", "tgt_renewed", client_principal,
                    "success", {"endtime": endtime})
        print(f"  [TGS] TGT renewed for '{client_principal}'. New endtime: {endtime}")

        return {
            "msg_type": TGS_REP,
            "realm": REALM,
            "client_principal": client_principal,
            "service_principal": TGS_PRINCIPAL,
            "encrypted_data": encrypted_tgs_rep,
            "service_ticket": encrypted_new_tgt,
            "service_ticket_enctype": session_enctype,
            "enc_part_enctype": session_enctype,
        }

    service_record = get_principal(db_cursor, requested_service)
    if service_record is None or service_record["principal_type"] not in ("service", "tgs"):
        print(f"  [TGS] ERROR: Service principal '{requested_service}' not found.")
        audit_event(db_cursor, "TGS", "service_lookup", client_principal,
                    "failure", {"service": requested_service})
        return _error(KDC_ERR_S_PRINCIPAL_UNKNOWN,
                      f"Service principal '{requested_service}' not found.")

    service_principal_name = service_record["principal_name"]
    service_master_key = str_to_key(service_record["key"])
    
    # Generate session key for Client-Service
    client_service_session_key = generate_session_key(session_enctype)

    starttime = now
    endtime = min(now + TICKET_LIFETIME, float(tgt.get("endtime", now + TICKET_LIFETIME)))
    flags = _service_flags(tgt)

    # 1. Build Service Ticket (EncTicketPart) and encrypt it with Service master key
    service_ticket_plaintext = {
        "flags": flags,
        "key": {
            "keytype": session_enctype,
            "keyvalue": client_service_session_key,
        },
        "realm": tgt.get("realm", REALM),
        "client_principal": client_principal,
        "authtime": tgt.get("authtime", now),
        "starttime": starttime,
        "endtime": endtime,
        "authorization_data": tgt.get("authorization_data", []),
    }
    st_der = encode_enc_ticket_part(service_ticket_plaintext)
    # Encrypt using KEY_USAGE_TICKET (2)
    encrypted_service_ticket = encrypt(st_der, service_master_key, KEY_USAGE_TICKET)

    # 2. Build TGS-REP Inner part (EncTGSRepPart) and encrypt with Client-TGS session key
    tgs_rep_plaintext = {
        "key": {
            "keytype": session_enctype,
            "keyvalue": client_service_session_key,
        },
        "nonce": request_nonce,
        "flags": flags,
        "authtime": tgt.get("authtime", now),
        "starttime": starttime,
        "endtime": endtime,
        "realm": requested_realm,
        "service_principal": service_principal_name,
    }
    tgs_rep_der = encode_enc_kdc_rep_part(tgs_rep_plaintext, TGS_REP)
    # Encrypt using KEY_USAGE_TGS_REP_ENCPART (9)
    encrypted_tgs_rep = encrypt(tgs_rep_der, session_key_bytes, KEY_USAGE_TGS_REP_ENCPART)

    audit_event(db_cursor, "TGS", "service_ticket_issued", client_principal,
                "success", {"service": service_principal_name, "endtime": endtime})
    print(f"  [TGS] Service Ticket issued for '{client_principal}' -> '{service_principal_name}'")

    return {
        "msg_type": TGS_REP,
        "realm": REALM,
        "client_principal": client_principal,
        "service_principal": service_principal_name,
        "encrypted_data": encrypted_tgs_rep,
        "service_ticket": encrypted_service_ticket,
        "service_ticket_enctype": session_enctype,
        "enc_part_enctype": session_enctype,
    }


def _ticket_expired(ticket: dict, now: float) -> bool:
    try:
        endtime = float(ticket.get("endtime", 0))
    except (TypeError, ValueError):
        return True
    return now > endtime


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
