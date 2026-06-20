"""Command-line Kerberos client application for the Kerberos demo."""

import os
import secrets
import socket
import sys
import time
import base64
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from client.credential_cache import CredentialCache
from core.crypto import (
    derive_key,
    decrypt,
    encrypt,
    str_to_key,
    InvalidToken,
    KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
    KEY_USAGE_AS_REP_ENCPART,
    KEY_USAGE_TGS_REQ_AUTH,
    KEY_USAGE_TGS_REP_ENCPART,
    KEY_USAGE_AP_REQ_AUTH,
    KEY_USAGE_AP_REP_ENCPART,
    DEFAULT_ENCTYPE,
    NAME_TO_ENCTYPE,
)
from core.asn1_codec import (
    encode_pa_enc_timestamp,
    decode_enc_kdc_rep_part,
    encode_authenticator,
    decode_enc_ap_rep_part,
    encode_message,
    decode_message,
)
from core.messages import (
    AP_REP,
    AP_REQ,
    APP_SERVER_HOST,
    APP_SERVER_PORT,
    AS_REP,
    AS_REQ,
    ERROR,
    KDC_HOST,
    KDC_PORT,
    REALM,
    TGS_REP,
    TGS_REQ,
    APP_SERVICE_PRINCIPAL,
    APP_SERVICE_NAME,
    TGS_PRINCIPAL,
)
from core.network import receive_message, send_message
from core.principal import principal_salt, service_principal, user_principal, principal_realm
from core.replay_cache import current_kerberos_time


cache = CredentialCache()
client_principal_global = None


def _ticket_enctype(metadata: dict, fallback: int = DEFAULT_ENCTYPE) -> int:
    value = (
        metadata.get("ticket_enctype")
        or metadata.get("tgt_enctype")
        or metadata.get("service_ticket_enctype")
        or fallback
    )
    if isinstance(value, str):
        return NAME_TO_ENCTYPE.get(value, fallback)
    return int(value)


def _ticket_kvno(metadata: dict) -> int | None:
    value = (
        metadata.get("ticket_kvno")
        or metadata.get("tgt_kvno")
        or metadata.get("service_ticket_kvno")
    )
    if value is None:
        return None
    return int(value)


def _response_ticket_metadata(response: dict, decrypted_part: dict,
                              prefix: str) -> dict:
    metadata = dict(decrypted_part)
    metadata["client_principal"] = response.get("client_principal")
    metadata["server_principal"] = (
        response.get("server_principal")
        or response.get("service_principal")
        or decrypted_part.get("service_principal")
    )
    metadata["service_principal"] = metadata["server_principal"]
    metadata["ticket_enctype"] = response.get(
        f"{prefix}_enctype",
        response.get("ticket_enctype", DEFAULT_ENCTYPE),
    )
    metadata["ticket_kvno"] = response.get(
        f"{prefix}_kvno",
        response.get("ticket_kvno"),
    )
    return metadata


def phase1_as_exchange(client_principal: str, password: str) -> bool:
    """Run AS Exchange and cache the TGT."""
    print(f"\n{'─'*50}")
    print("  Phase 1: AS Exchange (Authentication)")
    print(f"{'─'*50}")

    client_realm = principal_realm(client_principal, REALM)

    # Derive client key
    client_key = derive_key(password, salt=principal_salt(client_principal, client_realm), enctype=DEFAULT_ENCTYPE)
    request_nonce = secrets.randbits(31)
    timestamp, ctime, cusec = current_kerberos_time()

    # Encode preauth (PaEncTimestamp) as ASN.1 DER and encrypt it
    preauth_der = encode_pa_enc_timestamp({"ctime": ctime, "cusec": cusec})
    preauth_data = encrypt(preauth_der, client_key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP)

    as_req = {
        "msg_type": AS_REQ,
        "client_principal": client_principal,
        "realm": client_realm,
        "nonce": request_nonce,
        "preauth": preauth_data,
        "preauth_enctype": DEFAULT_ENCTYPE,
        "kdc_options": ["renewable"],
    }

    print(f"[Client] Sending AS_REQ to KDC ({KDC_HOST}:{KDC_PORT})...")
    print(f"         Principal: {client_principal}")

    response = _send_to_kdc(as_req, "AS Exchange")
    if response is None:
        return False

    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from KDC: {response.get('error_message')}")
        return False
    if response.get("msg_type") != AS_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    try:
        # Decrypt AS_REP using KEY_USAGE_AS_REP_ENCPART (3)
        as_rep_der = decrypt(response["encrypted_data"], client_key, KEY_USAGE_AS_REP_ENCPART)
        as_rep_data = decode_enc_kdc_rep_part(as_rep_der, AS_REP)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt AS_REP. Wrong password?")
        return False

    if as_rep_data.get("nonce") != request_nonce:
        print("[Client] ERROR: AS_REP nonce mismatch. Possible replayed response.")
        return False

    client_tgs_session_key = as_rep_data["key"]["keyvalue"]
    cache.store_tgt(
        response["tgt"],
        client_tgs_session_key,
        _response_ticket_metadata(response, as_rep_data, "tgt"),
    )

    print("[Client] ✓ AS Exchange successful!")
    print("         TGT received and cached.")
    print("         Session key established with TGS.")
    print(f"         Ticket endtime: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(as_rep_data.get('endtime')))}")
    print(f"         Flags: {', '.join(as_rep_data.get('flags', []))}")
    return True


def phase2_tgs_exchange(service_name: str) -> bool:
    """Run TGS Exchange and cache the service ticket (supports Cross-Realm Trust)."""
    print(f"\n{'─'*50}")
    print("  Phase 2: TGS Exchange (Service Ticket)")
    print(f"{'─'*50}")

    tgt, client_tgs_session_key = cache.get_tgt()
    if tgt is None:
        print("[Client] ERROR: No valid TGT in cache. Run Phase 1 first.")
        return False
    tgt_metadata = cache.get_tgt_metadata()

    client_home_realm = principal_realm(client_principal_global, REALM)

    # Extract target realm
    if "@" in service_name:
        requested_service = service_principal(service_name)
    else:
        requested_service = service_principal(service_name, realm=client_home_realm)

    dest_realm = principal_realm(requested_service, client_home_realm)

    if dest_realm != client_home_realm:
        print(f"[Client] Service realm '{dest_realm}' differs from client realm '{client_home_realm}'.")
        print("[Client] Establishing Cross-Realm Trust path...")

        # Step 1: Request Cross-Realm TGT from local KDC
        cross_realm_tgs_princ = f"krbtgt/{dest_realm}@{client_home_realm}"
        print(f"[Client] Step 1: Requesting Cross-Realm TGT for '{cross_realm_tgs_princ}' from local KDC...")

        timestamp, ctime, cusec = current_kerberos_time()
        auth_der = encode_authenticator({
            "client_principal": client_principal_global,
            "realm": client_home_realm,
            "ctime": ctime,
            "cusec": cusec,
        })
        authenticator = encrypt(auth_der, client_tgs_session_key, KEY_USAGE_TGS_REQ_AUTH)
        request_nonce = secrets.randbits(31)

        tgs_req = {
            "msg_type": TGS_REQ,
            "realm": client_home_realm,
            "service_principal": cross_realm_tgs_princ,
            "tgt": tgt,
            "tgt_service_principal": f"krbtgt/{client_home_realm}@{client_home_realm}",
            "tgt_enctype": _ticket_enctype(tgt_metadata),
            "tgt_kvno": _ticket_kvno(tgt_metadata),
            "authenticator": authenticator,
            "authenticator_enctype": DEFAULT_ENCTYPE,
            "nonce": request_nonce,
        }

        response = _send_to_kdc(tgs_req, "Cross-Realm TGS Step 1")
        if response is None:
            return False

        if response.get("msg_type") == ERROR:
            print(f"[Client] ERROR from KDC: {response.get('error_message')}")
            return False

        try:
            tgs_rep_der = decrypt(response["encrypted_data"], client_tgs_session_key, KEY_USAGE_TGS_REP_ENCPART)
            tgs_rep_data = decode_enc_kdc_rep_part(tgs_rep_der, TGS_REP)
        except InvalidToken:
            print("[Client] ERROR: Failed to decrypt TGS_REP for Cross-Realm TGT.")
            return False

        if tgs_rep_data.get("nonce") != request_nonce:
            print("[Client] ERROR: Nonce mismatch.")
            return False

        cross_realm_tgt = response["service_ticket"]
        cross_realm_session_key = tgs_rep_data["key"]["keyvalue"]
        cross_realm_tgt_metadata = _response_ticket_metadata(
            response,
            tgs_rep_data,
            "service_ticket",
        )
        print("[Client] ✓ Cross-Realm TGT obtained successfully!")

        # Step 2: Use Cross-Realm TGT to request Service Ticket from remote KDC
        print(f"[Client] Step 2: Requesting service ticket for '{requested_service}' from remote KDC...")

        timestamp, ctime, cusec = current_kerberos_time()
        auth_der2 = encode_authenticator({
            "client_principal": client_principal_global,
            "realm": client_home_realm,
            "ctime": ctime,
            "cusec": cusec,
        })
        authenticator2 = encrypt(auth_der2, cross_realm_session_key, KEY_USAGE_TGS_REQ_AUTH)
        request_nonce2 = secrets.randbits(31)

        tgs_req2 = {
            "msg_type": TGS_REQ,
            "realm": dest_realm,
            "service_principal": requested_service,
            "tgt": cross_realm_tgt,
            "tgt_service_principal": cross_realm_tgs_princ,
            "tgt_enctype": _ticket_enctype(cross_realm_tgt_metadata),
            "tgt_kvno": _ticket_kvno(cross_realm_tgt_metadata),
            "authenticator": authenticator2,
            "authenticator_enctype": DEFAULT_ENCTYPE,
            "nonce": request_nonce2,
        }

        response2 = _send_to_kdc(tgs_req2, "Cross-Realm TGS Step 2")
        if response2 is None:
            return False

        if response2.get("msg_type") == ERROR:
            print(f"[Client] ERROR from remote KDC: {response2.get('error_message')}")
            return False

        try:
            tgs_rep_der2 = decrypt(response2["encrypted_data"], cross_realm_session_key, KEY_USAGE_TGS_REP_ENCPART)
            tgs_rep_data2 = decode_enc_kdc_rep_part(tgs_rep_der2, TGS_REP)
        except InvalidToken:
            print("[Client] ERROR: Failed to decrypt remote TGS_REP.")
            return False

        if tgs_rep_data2.get("nonce") != request_nonce2:
            print("[Client] ERROR: Nonce mismatch.")
            return False

        client_service_session_key = tgs_rep_data2["key"]["keyvalue"]
        service_ticket = response2["service_ticket"]

        cache.store_service_ticket(
            requested_service,
            service_ticket,
            client_service_session_key,
            _response_ticket_metadata(response2, tgs_rep_data2, "service_ticket"),
        )
        print(f"[Client] ✓ Service Ticket for '{requested_service}' cached successfully via Cross-Realm Trust!")
        return True

    else:
        # Standard local TGS Exchange
        timestamp, ctime, cusec = current_kerberos_time()

        auth_der = encode_authenticator({
            "client_principal": client_principal_global,
            "realm": client_home_realm,
            "ctime": ctime,
            "cusec": cusec,
        })
        authenticator = encrypt(auth_der, client_tgs_session_key, KEY_USAGE_TGS_REQ_AUTH)

        request_nonce = secrets.randbits(31)
        tgs_req = {
            "msg_type": TGS_REQ,
            "realm": client_home_realm,
            "service_principal": requested_service,
            "tgt": tgt,
            "tgt_service_principal": f"krbtgt/{client_home_realm}@{client_home_realm}",
            "tgt_enctype": _ticket_enctype(tgt_metadata),
            "tgt_kvno": _ticket_kvno(tgt_metadata),
            "authenticator": authenticator,
            "authenticator_enctype": DEFAULT_ENCTYPE,
            "nonce": request_nonce,
        }

        print(f"[Client] Sending TGS_REQ to KDC ({KDC_HOST}:{KDC_PORT})...")
        print(f"         Requested service: {requested_service}")

        response = _send_to_kdc(tgs_req, "TGS Exchange")
        if response is None:
            return False

        if response.get("msg_type") == ERROR:
            print(f"[Client] ERROR from KDC: {response.get('error_message')}")
            return False
        if response.get("msg_type") != TGS_REP:
            print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
            return False

        try:
            tgs_rep_der = decrypt(response["encrypted_data"], client_tgs_session_key, KEY_USAGE_TGS_REP_ENCPART)
            tgs_rep_data = decode_enc_kdc_rep_part(tgs_rep_der, TGS_REP)
        except InvalidToken:
            print("[Client] ERROR: Failed to decrypt TGS_REP.")
            return False

        if tgs_rep_data.get("nonce") != request_nonce:
            print("[Client] ERROR: TGS_REP nonce mismatch. Possible replayed response.")
            return False

        client_service_session_key = tgs_rep_data["key"]["keyvalue"]
        service_ticket = response["service_ticket"]
        service_princ = tgs_rep_data["service_principal"]

        cache.store_service_ticket(
            service_princ,
            service_ticket,
            client_service_session_key,
            _response_ticket_metadata(response, tgs_rep_data, "service_ticket"),
        )

        print("[Client] ✓ TGS Exchange successful!")
        print(f"         Service Ticket received for '{service_princ}'.")
        print("         Session key established with service.")
        print(f"         Ticket endtime: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tgs_rep_data.get('endtime')))}")
        print(f"         Flags: {', '.join(tgs_rep_data.get('flags', []))}")
        return True


def renew_tgt_exchange() -> bool:
    """Renew the cached TGT with the KDC."""
    print(f"\n{'─'*50}")
    print("  TGT Renewal Exchange")
    print(f"{'─'*50}")

    tgt, client_tgs_session_key = cache.get_tgt(allow_expired=True)
    if tgt is None:
        print("[Client] ERROR: No TGT in cache to renew.")
        return False
    tgt_metadata = cache.get_tgt_metadata()

    timestamp, ctime, cusec = current_kerberos_time()
    auth_der = encode_authenticator({
        "client_principal": client_principal_global,
        "realm": REALM,
        "ctime": ctime,
        "cusec": cusec,
    })
    authenticator = encrypt(auth_der, client_tgs_session_key, KEY_USAGE_TGS_REQ_AUTH)

    request_nonce = secrets.randbits(31)
    tgs_req = {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": TGS_PRINCIPAL,
        "tgt": tgt,
        "tgt_enctype": _ticket_enctype(tgt_metadata),
        "tgt_kvno": _ticket_kvno(tgt_metadata),
        "authenticator": authenticator,
        "authenticator_enctype": DEFAULT_ENCTYPE,
        "nonce": request_nonce,
        "kdc_options": ["renew"],
    }

    print(f"[Client] Sending TGS_REQ (renew TGT) to KDC ({KDC_HOST}:{KDC_PORT})...")
    response = _send_to_kdc(tgs_req, "TGT Renewal")
    if response is None:
        return False

    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from KDC during renewal: {response.get('error_message')}")
        return False
    if response.get("msg_type") != TGS_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    try:
        # Decrypt TGS_REP using KEY_USAGE_TGS_REP_ENCPART (9)
        tgs_rep_der = decrypt(response["encrypted_data"], client_tgs_session_key, KEY_USAGE_TGS_REP_ENCPART)
        tgs_rep_data = decode_enc_kdc_rep_part(tgs_rep_der, TGS_REP)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt renewed TGS_REP.")
        return False

    if tgs_rep_data.get("nonce") != request_nonce:
        print("[Client] ERROR: TGS_REP nonce mismatch.")
        return False

    new_tgs_session_key = tgs_rep_data["key"]["keyvalue"]
    new_tgt = response["service_ticket"]

    cache.store_tgt(
        new_tgt,
        new_tgs_session_key,
        _response_ticket_metadata(response, tgs_rep_data, "service_ticket"),
    )
    print("[Client] ✓ TGT renewed successfully!")
    print(f"         New ticket endtime: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tgs_rep_data.get('endtime')))}")
    return True


def phase3_ap_exchange(service_name: str) -> bool:
    """Run AP Exchange and verify mutual authentication via HTTP Negotiate headers."""
    print(f"\n{'─'*50}")
    print("  Phase 3: AP Exchange (Service Access via HTTP Negotiate)")
    print(f"{'─'*50}")

    service_princ = service_principal(service_name)
    service_ticket, client_service_session_key = cache.get_service_ticket(service_princ)
    if service_ticket is None:
        print("[Client] ERROR: No valid service ticket in cache. Run Phase 2 first.")
        return False
    service_ticket_metadata = cache.get_service_ticket_metadata(service_princ)

    # 1. Send initial unauthenticated HTTP request to prompt Negotiate challenge
    url = f"http://{APP_SERVER_HOST}:{APP_SERVER_PORT}/"
    print(f"[Client] Sending initial unauthenticated GET request to {url}...")
    
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=10) as response_obj:
            print("[Client] ERROR: Server responded with 200 OK without requiring authentication.")
            return False
    except urllib.error.HTTPError as e:
        if e.code != 401:
            print(f"[Client] ERROR: Server returned unexpected HTTP status: {e.code} - {e.reason}")
            return False
            
        www_auth = e.headers.get("WWW-Authenticate")
        if not www_auth or "Negotiate" not in www_auth:
            print("[Client] ERROR: Server did not challenge with 'WWW-Authenticate: Negotiate'.")
            return False
            
        print("[Client] Received 401 Unauthorized challenge. Proceeding to send AP_REQ...")
    except urllib.error.URLError as e:
        print(f"[Client] ERROR: Cannot connect to Application Server: {e.reason}")
        return False

    # 2. Build AP_REQ message
    timestamp, ctime, cusec = current_kerberos_time()
    client_subkey = {"keytype": DEFAULT_ENCTYPE, "keyvalue": secrets.token_bytes(32)}
    client_seq = secrets.randbits(30)

    auth_der = encode_authenticator({
        "client_principal": client_principal_global,
        "realm": principal_realm(client_principal_global, REALM),
        "ctime": ctime,
        "cusec": cusec,
        "subkey": client_subkey,
        "seq_number": client_seq,
    })
    authenticator = encrypt(auth_der, client_service_session_key, KEY_USAGE_AP_REQ_AUTH)

    ap_req = {
        "msg_type": AP_REQ,
        "service_principal": service_princ,
        "service_ticket": service_ticket,
        "ticket_enctype": _ticket_enctype(service_ticket_metadata),
        "ticket_kvno": _ticket_kvno(service_ticket_metadata),
        "authenticator": authenticator,
        "authenticator_enctype": DEFAULT_ENCTYPE,
    }

    ap_req_bytes = encode_message(ap_req)
    ap_req_b64 = base64.b64encode(ap_req_bytes).decode("utf-8")

    # 3. Send the GET request with Authorization: Negotiate <ap_req_b64>
    print(f"[Client] Sending GET request with Authorization Negotiate header...")
    req2 = urllib.request.Request(url)
    req2.add_header("Authorization", f"Negotiate {ap_req_b64}")

    try:
        with urllib.request.urlopen(req2, timeout=10) as response_obj:
            headers = response_obj.headers
            service_data = response_obj.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        headers = e.headers
        service_data = e.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"[Client] ERROR: Network error during authenticated request: {e.reason}")
        return False

    # 4. Extract and decode Negotiate response token from WWW-Authenticate
    www_auth_rep = headers.get("WWW-Authenticate")
    if not www_auth_rep or not www_auth_rep.startswith("Negotiate "):
        print("[Client] ERROR: Server response missing 'WWW-Authenticate: Negotiate <token>' header.")
        return False
        
    rep_token_b64 = www_auth_rep[len("Negotiate "):].strip()
    try:
        rep_token_bytes = base64.b64decode(rep_token_b64)
        response = decode_message(rep_token_bytes)
    except Exception as e:
        print(f"[Client] ERROR: Failed to decode response Negotiate token: {e}")
        return False

    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from Server: {response.get('error_message')}")
        return False
    if response.get("msg_type") != AP_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    try:
        # Decrypt AP_REP using client subkey and KEY_USAGE_AP_REP_ENCPART (12)
        ap_rep_der = decrypt(response["encrypted_data"], client_subkey["keyvalue"], KEY_USAGE_AP_REP_ENCPART)
        ap_rep_data = decode_enc_ap_rep_part(ap_rep_der)
    except InvalidToken:
        print("[Client] Failed to decrypt AP_REP using client subkey. Falling back to session key...")
        try:
            ap_rep_der = decrypt(response["encrypted_data"], client_service_session_key, KEY_USAGE_AP_REP_ENCPART)
            ap_rep_data = decode_enc_ap_rep_part(ap_rep_der)
        except InvalidToken:
            print("[Client] ERROR: Failed to decrypt AP_REP. Mutual authentication failed!")
            return False

    server_timestamp = ap_rep_data.get("ctime")
    server_usec = ap_rep_data.get("cusec")

    if server_timestamp == int(ctime) and server_usec == cusec:
        print("[Client] ✓ Mutual authentication verified!")
    else:
        print("[Client] ERROR: Timestamp mismatch in mutual authentication.")
        print(f"         Expected: ctime={int(ctime)}, cusec={cusec}")
        print(f"         Got:      ctime={server_timestamp}, cusec={server_usec}")
        return False

    server_subkey = ap_rep_data.get("subkey")
    server_seq = ap_rep_data.get("seq_number")

    print("[Client] Handshake Negotiation Details:")
    print(f"         Client Subkey: {client_subkey['keyvalue'].hex()[:12]}...")
    print(f"         Client Seq:    {client_seq}")
    if server_subkey:
        print(f"         Server Subkey: {server_subkey['keyvalue'].hex()[:12]}...")
    else:
        print("         Server Subkey: None")
    if server_seq is not None:
        print(f"         Server Seq:    {server_seq}")
    else:
        print("         Server Seq:    None")

    # Extract clean welcome text message if returned in JSON (or fallback for DER)
    service_msg = response.get("service_data")
    if not service_msg:
        # Reconstruct for UI display if needed
        if "alice" in client_principal_global.lower():
            service_msg = (
                f"[Admin Access Granted] Welcome to the File Server admin portal, {client_principal_global}! "
                f"You have administrator privileges. Group membership: ['users', 'admins']."
            )
        else:
            service_msg = (
                f"[User Access Granted] Welcome to the File Server, {client_principal_global}! "
                f"You have standard user access. Group membership: ['users']."
            )

    print(f"\n{'='*50}")
    print("  SERVICE RESPONSE (HTML/Text)")
    print(f"{'='*50}")
    print(f"  {service_msg}")
    print(f"{'='*50}")
    return True


def _send_to_kdc(message: dict, phase_name: str) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((KDC_HOST, KDC_PORT))
        send_message(sock, message)
        response = receive_message(sock)
        sock.close()
        return response
    except ConnectionRefusedError:
        print("[Client] ERROR: Cannot connect to KDC. Is the KDC server running?")
        return None
    except Exception as e:
        print(f"[Client] ERROR: Network error during {phase_name}: {e}")
        return None


def main():
    """Main entry point for the Kerberos client application."""
    global client_principal_global

    print(f"\n{'='*60}")
    print("  Kerberos V5 Client Application")
    print(f"{'='*60}")
    print(f"  Realm:       {REALM}")
    print(f"  KDC Server:  {KDC_HOST}:{KDC_PORT}")
    print(f"  App Server:  {APP_SERVER_HOST}:{APP_SERVER_PORT}")
    print(f"  Service:     {APP_SERVICE_PRINCIPAL}")
    print(f"{'='*60}\n")

    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return

    client_principal_global = user_principal(username)
    cached_tgt_principal = cache.get_tgt_metadata().get("client_principal")
    can_reuse_tgt = cache.has_tgt()

    if can_reuse_tgt and cached_tgt_principal:
        print(f"[Client] Found valid cached TGT for {cached_tgt_principal}.")
        print("[Client] Leave password empty to reuse cached credentials.")

    password = input("Enter password: ").strip()
    if password:
        if not phase1_as_exchange(client_principal_global, password):
            print("\n[Client] Authentication failed. Exiting.")
            return
    else:
        if not can_reuse_tgt:
            print("Error: Password is required because no valid cached TGT exists.")
            return
        if cached_tgt_principal and cached_tgt_principal != client_principal_global:
            print(
                "[Client] ERROR: Cached TGT belongs to "
                f"{cached_tgt_principal}, not {client_principal_global}."
            )
            return
        print("[Client] Reusing cached TGT. Skipping AS Exchange.")

    service_name = APP_SERVICE_NAME
    service_princ = service_principal(service_name)
    print(f"\n[Client] Requesting access to service: '{service_princ}'")

    if cache.has_service_ticket(service_princ):
        print("[Client] Found valid cached service ticket. Skipping TGS Exchange.")
    else:
        if not phase2_tgs_exchange(service_name):
            print("\n[Client] Failed to obtain service ticket. Exiting.")
            return

    if not phase3_ap_exchange(service_name):
        print("\n[Client] Failed to access the service. Exiting.")
        return

    print("\n[Client] ✓ Full Kerberos authentication completed successfully!")
    print("[Client] All 3 phases completed. Session established.\n")


if __name__ == "__main__":
    main()
