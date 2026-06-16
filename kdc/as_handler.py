"""
as_handler.py - Authentication Server (AS) logic for the KDC (RFC 4120 compliant).
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
    KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
    KEY_USAGE_AS_REP_ENCPART,
    KEY_USAGE_TICKET,
    DEFAULT_ENCTYPE,
)
from core.asn1_codec import (
    decode_pa_enc_timestamp,
    encode_enc_ticket_part,
    encode_enc_kdc_rep_part,
)
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
    
    Uses standard ASN.1/DER structures for inner encrypted parts and
    proper cryptographic key usages.
    """
    requested_principal = request.get("client_principal")
    requested_realm = str(request.get("realm", REALM)).upper()
    request_nonce = request.get("nonce")
    encrypted_preauth = request.get("preauth")
    preauth_enctype = request.get("preauth_enctype", DEFAULT_ENCTYPE)

    print(f"  [AS] Received AS_REQ from '{requested_principal}'")

    ALLOWED_REALMS = [REALM, "PARTNER.LOCAL"]
    if requested_realm not in ALLOWED_REALMS:
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
        preauth_der = decrypt(encrypted_preauth, client_master_key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP)
        print(f"  [AS] Decrypted preauth_der: {preauth_der.hex()}")
        preauth = decode_pa_enc_timestamp(preauth_der)
    except InvalidToken:
        print(f"  [AS] ERROR: Pre-authentication failed for '{client_principal}'.")
        audit_event(db_cursor, "AS", "preauth", client_principal, "failure",
                    {"error": "invalid_token"})
        return _error(KDC_ERR_PREAUTH_FAILED, "Pre-authentication failed.")

    try:
        preauth_timestamp = float(preauth.get("ctime", 0))
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

    tgs_principal_name = f"krbtgt/{requested_realm}@{requested_realm}"
    tgs_record = get_principal(db_cursor, tgs_principal_name)
    if tgs_record is None:
        print(f"  [AS] ERROR: TGS principal '{tgs_principal_name}' not found.")
        audit_event(db_cursor, "AS", "as_req", client_principal, "failure",
                    {"error": "missing_tgs_principal"})
        return _error(KRB_ERR_GENERIC, f"Internal error: TGS principal '{tgs_principal_name}' not found.")

    tgs_master_key = str_to_key(tgs_record["key"])
    
    # Generate session key for Client-TGS
    client_tgs_session_key = generate_session_key(preauth_enctype)

    authtime = now
    starttime = now
    
    kdc_options = request.get("kdc_options", [])
    flags = list(DEFAULT_TICKET_FLAGS)
    if "renewable" in kdc_options:
        if "renewable" not in flags:
            flags.append("renewable")
        renew_till = now + RENEWABLE_LIFETIME
    elif "renewable" in flags:
        renew_till = now + RENEWABLE_LIFETIME
    else:
        renew_till = None

    endtime = now + TICKET_LIFETIME

    import json
    try:
        groups_list = json.loads(client_record.get("groups", "[]"))
    except Exception:
        groups_list = []

    auth_data = [
        {
            "ad_type": 100,
            "ad_data": json.dumps(groups_list).encode("utf-8"),
        }
    ]

    # 1. Build TGT Inner part (EncTicketPart) and encrypt it with TGS master key
    tgt_plaintext = {
        "flags": flags,
        "key": {
            "keytype": preauth_enctype,
            "keyvalue": client_tgs_session_key,
        },
        "realm": requested_realm,
        "client_principal": client_principal,
        "authtime": authtime,
        "starttime": starttime,
        "endtime": endtime,
        "renew_till": renew_till,
        "authorization_data": auth_data,
    }
    tgt_der = encode_enc_ticket_part(tgt_plaintext)
    # Encrypt using KEY_USAGE_TICKET (2)
    encrypted_tgt = encrypt(tgt_der, tgs_master_key, KEY_USAGE_TICKET)

    # 2. Build AS-REP Inner part (EncASRepPart) and encrypt with client master key
    as_rep_plaintext = {
        "key": {
            "keytype": preauth_enctype,
            "keyvalue": client_tgs_session_key,
        },
        "nonce": request_nonce,
        "flags": flags,
        "authtime": authtime,
        "starttime": starttime,
        "endtime": endtime,
        "renew_till": renew_till,
        "realm": requested_realm,
        "service_principal": tgs_principal_name,
    }
    as_rep_der = encode_enc_kdc_rep_part(as_rep_plaintext, AS_REP)
    # Encrypt using KEY_USAGE_AS_REP_ENCPART (3)
    encrypted_as_rep = encrypt(as_rep_der, client_master_key, KEY_USAGE_AS_REP_ENCPART)

    audit_event(db_cursor, "AS", "tgt_issued", client_principal, "success",
                {"server": tgs_principal_name, "endtime": endtime, "flags": flags})
    print(f"  [AS] TGT issued for '{client_principal}'. Lifetime: {TICKET_LIFETIME}s")

    return {
        "msg_type": AS_REP,
        "realm": requested_realm,
        "client_principal": client_principal,
        "server_principal": tgs_principal_name,
        "encrypted_data": encrypted_as_rep,
        "tgt": encrypted_tgt,
        "ticket_enctype": preauth_enctype,
        "enc_part_enctype": preauth_enctype,
    }


def _error(code: str, message: str) -> dict:
    return {
        "msg_type": ERROR,
        "error_code": code,
        "error_message": message,
    }
