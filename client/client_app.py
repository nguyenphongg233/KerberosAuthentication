"""Command-line Kerberos demo client."""

import os
import secrets
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from cryptography.fernet import InvalidToken

from client.credential_cache import CredentialCache
from core.crypto import derive_key, decrypt, encrypt, str_to_key
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
)
from core.network import receive_message, send_message
from core.principal import principal_salt, service_principal, user_principal
from core.replay_cache import current_kerberos_time


cache = CredentialCache()
client_principal_global = None


def phase1_as_exchange(client_principal: str, password: str) -> bool:
    """Run AS Exchange and cache the TGT."""
    print(f"\n{'─'*50}")
    print("  Phase 1: AS Exchange (Authentication)")
    print(f"{'─'*50}")

    client_key = derive_key(password, salt=principal_salt(client_principal, REALM))
    request_nonce = secrets.randbits(31)
    timestamp, ctime, cusec = current_kerberos_time()
    preauth_data = encrypt({
        "client_principal": client_principal,
        "realm": REALM,
        "timestamp": timestamp,
        "ctime": ctime,
        "cusec": cusec,
    }, client_key)

    as_req = {
        "msg_type": AS_REQ,
        "client_principal": client_principal,
        "realm": REALM,
        "timestamp": timestamp,
        "ctime": ctime,
        "cusec": cusec,
        "nonce": request_nonce,
        "preauth": preauth_data,
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
        as_rep_data = decrypt(response["encrypted_data"], client_key)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt AS_REP. Wrong password?")
        return False

    if as_rep_data.get("nonce") != request_nonce:
        print("[Client] ERROR: AS_REP nonce mismatch. Possible replayed response.")
        return False

    client_tgs_session_key = str_to_key(as_rep_data["client_tgs_session_key"])
    cache.store_tgt(response["tgt"], client_tgs_session_key, as_rep_data)

    print("[Client] ✓ AS Exchange successful!")
    print("         TGT received and cached.")
    print("         Session key established with TGS.")
    print(f"         Ticket endtime: {as_rep_data.get('endtime')}")
    print(f"         Flags: {', '.join(as_rep_data.get('flags', []))}")
    return True


def phase2_tgs_exchange(service_name: str) -> bool:
    """Run TGS Exchange and cache the service ticket."""
    print(f"\n{'─'*50}")
    print("  Phase 2: TGS Exchange (Service Ticket)")
    print(f"{'─'*50}")

    tgt, client_tgs_session_key = cache.get_tgt()
    if tgt is None:
        print("[Client] ERROR: No valid TGT in cache. Run Phase 1 first.")
        return False

    requested_service = service_principal(service_name)
    timestamp, ctime, cusec = current_kerberos_time()
    authenticator = encrypt({
        "client_principal": client_principal_global,
        "realm": REALM,
        "timestamp": timestamp,
        "ctime": ctime,
        "cusec": cusec,
    }, client_tgs_session_key)

    request_nonce = secrets.randbits(31)
    tgs_req = {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": requested_service,
        "tgt": tgt,
        "authenticator": authenticator,
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
        tgs_rep_data = decrypt(response["encrypted_data"], client_tgs_session_key)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt TGS_REP.")
        return False

    if tgs_rep_data.get("nonce") != request_nonce:
        print("[Client] ERROR: TGS_REP nonce mismatch. Possible replayed response.")
        return False

    client_service_session_key = str_to_key(tgs_rep_data["client_service_session_key"])
    service_ticket = response["service_ticket"]
    service_princ = tgs_rep_data["service_principal"]
    cache.store_service_ticket(
        service_princ,
        service_ticket,
        client_service_session_key,
        tgs_rep_data,
    )

    print("[Client] ✓ TGS Exchange successful!")
    print(f"         Service Ticket received for '{service_princ}'.")
    print("         Session key established with service.")
    print(f"         Ticket endtime: {tgs_rep_data.get('endtime')}")
    print(f"         Flags: {', '.join(tgs_rep_data.get('flags', []))}")
    return True


def phase3_ap_exchange(service_name: str) -> bool:
    """Run AP Exchange and verify mutual authentication."""
    print(f"\n{'─'*50}")
    print("  Phase 3: AP Exchange (Service Access)")
    print(f"{'─'*50}")

    service_princ = service_principal(service_name)
    service_ticket, client_service_session_key = cache.get_service_ticket(service_princ)
    if service_ticket is None:
        print("[Client] ERROR: No valid service ticket in cache. Run Phase 2 first.")
        return False

    timestamp, ctime, cusec = current_kerberos_time()
    authenticator = encrypt({
        "client_principal": client_principal_global,
        "realm": REALM,
        "timestamp": timestamp,
        "ctime": ctime,
        "cusec": cusec,
    }, client_service_session_key)

    ap_req = {
        "msg_type": AP_REQ,
        "service_principal": service_princ,
        "service_ticket": service_ticket,
        "authenticator": authenticator,
    }

    print(f"[Client] Sending AP_REQ to Application Server ({APP_SERVER_HOST}:{APP_SERVER_PORT})...")
    response = _send_to_app_server(ap_req)
    if response is None:
        return False

    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from Server: {response.get('error_message')}")
        return False
    if response.get("msg_type") != AP_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    try:
        ap_rep_data = decrypt(response["encrypted_data"], client_service_session_key)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt AP_REP. Mutual authentication failed!")
        return False

    try:
        server_timestamp = float(ap_rep_data.get("timestamp"))
    except (TypeError, ValueError):
        print("[Client] ERROR: Missing or invalid timestamp in AP_REP.")
        return False

    expected_timestamp = timestamp + 1
    if abs(server_timestamp - expected_timestamp) < 0.01:
        print("[Client] ✓ Mutual authentication verified!")
    else:
        print("[Client] ERROR: Timestamp mismatch in mutual authentication.")
        print(f"         Expected: {expected_timestamp}, Got: {server_timestamp}")
        return False

    print(f"\n{'='*50}")
    print("  SERVICE RESPONSE")
    print(f"{'='*50}")
    print(f"  {ap_rep_data.get('service_data', 'No data received.')}")
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


def _send_to_app_server(message: dict) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((APP_SERVER_HOST, APP_SERVER_PORT))
        send_message(sock, message)
        response = receive_message(sock)
        sock.close()
        return response
    except ConnectionRefusedError:
        print("[Client] ERROR: Cannot connect to Application Server. Is it running?")
        return None
    except Exception as e:
        print(f"[Client] ERROR: Network error during AP Exchange: {e}")
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

    password = input("Enter password: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return

    client_principal_global = user_principal(username)

    if not phase1_as_exchange(client_principal_global, password):
        print("\n[Client] Authentication failed. Exiting.")
        return

    service_name = APP_SERVICE_NAME
    print(f"\n[Client] Requesting access to service: '{service_principal(service_name)}'")

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
