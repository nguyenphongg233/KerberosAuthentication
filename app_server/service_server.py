"""
service_server.py - Application Server (File Server mock).

Handles the Kerberos AP Exchange:
    AP_REQ(Service Ticket + Authenticator) -> AP_REP(timestamp + 1)
"""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from cryptography.fernet import InvalidToken

from core.keytab import load_keytab
from core.messages import (
    AP_REP,
    AP_REQ,
    APP_SERVER_HOST,
    APP_SERVER_PORT,
    APP_SERVICE_PRINCIPAL,
    ERROR,
    KRB_AP_ERR_MODIFIED,
    KRB_AP_ERR_REPEAT,
    KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED,
    MAX_CLOCK_SKEW,
    REALM,
)
from core.crypto import decrypt, encrypt, str_to_key
from core.network import receive_message, send_message
from core.replay_cache import authenticator_cache_key, check_and_store
from kdc.database import DEFAULT_KEYTAB_PATH


SERVICE_PRINCIPAL = APP_SERVICE_PRINCIPAL
KEYTAB_PATH = os.getenv("APP_SERVER_KEYTAB", DEFAULT_KEYTAB_PATH)


def handle_client(client_socket: socket.socket, client_address: tuple,
                  service_key: bytes):
    """Handle a single AP Exchange from a client."""
    try:
        print(f"\n[FileServer] Connection from {client_address}")
        request = receive_message(client_socket)

        if request.get("msg_type") != AP_REQ:
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                f"Expected AP_REQ, got: {request.get('msg_type')}",
            ))
            return

        encrypted_service_ticket = request.get("service_ticket")
        encrypted_authenticator = request.get("authenticator")
        if not encrypted_service_ticket or not encrypted_authenticator:
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "AP_REQ missing ticket or authenticator.",
            ))
            return

        try:
            service_ticket = decrypt(encrypted_service_ticket, service_key)
        except InvalidToken:
            print("[FileServer] ERROR: Failed to decrypt service ticket.")
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Service ticket decryption failed.",
            ))
            return

        client_principal = service_ticket.get("client_principal")
        server_principal = service_ticket.get(
            "server_principal",
            service_ticket.get("service_principal"),
        )
        session_key_text = service_ticket.get("client_service_session_key")

        if not client_principal or not server_principal or not session_key_text:
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Malformed service ticket.",
            ))
            return

        if server_principal != SERVICE_PRINCIPAL:
            print(f"[FileServer] ERROR: Ticket is for '{server_principal}', not '{SERVICE_PRINCIPAL}'.")
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Service ticket is not for this service.",
            ))
            return

        if str(service_ticket.get("realm", REALM)).upper() != REALM:
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Service ticket is for another realm.",
            ))
            return

        now = time.time()
        if _ticket_expired(service_ticket, now):
            print("[FileServer] ERROR: Service ticket has expired.")
            send_message(client_socket, _error(
                KRB_AP_ERR_TKT_EXPIRED,
                "Service ticket has expired.",
            ))
            return

        client_service_session_key = str_to_key(session_key_text)
        try:
            authenticator = decrypt(encrypted_authenticator, client_service_session_key)
        except InvalidToken:
            print("[FileServer] ERROR: Failed to decrypt authenticator.")
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Authenticator decryption failed.",
            ))
            return

        if authenticator.get("client_principal") != client_principal:
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Authenticator principal mismatch.",
            ))
            return

        auth_timestamp = _authenticator_timestamp(authenticator)
        if auth_timestamp is None:
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED,
                "Invalid authenticator timestamp.",
            ))
            return

        if abs(now - auth_timestamp) > MAX_CLOCK_SKEW:
            print("[FileServer] ERROR: Clock skew too great.")
            send_message(client_socket, _error(
                KRB_AP_ERR_SKEW,
                "Clock skew too great.",
            ))
            return

        cache_key = authenticator_cache_key(
            client_principal,
            server_principal,
            auth_timestamp,
            authenticator.get("cusec"),
        )
        if check_and_store("AP", cache_key, client_principal, server_principal,
                           auth_timestamp, now, MAX_CLOCK_SKEW):
            print("[FileServer] ERROR: Replayed authenticator detected.")
            send_message(client_socket, _error(
                KRB_AP_ERR_REPEAT,
                "Replayed authenticator detected.",
            ))
            return

        print(f"[FileServer] ✓ Client '{client_principal}' authenticated successfully!")

        ap_rep_plaintext = {
            "timestamp": auth_timestamp + 1,
            "ctime": int(auth_timestamp + 1),
            "service_principal": SERVICE_PRINCIPAL,
            "service_data": (
                f"Welcome to the File Server, {client_principal}! "
                f"You have been authenticated via Kerberos V5. "
                f"Access granted at {time.strftime('%Y-%m-%d %H:%M:%S')}."
            ),
        }

        send_message(client_socket, {
            "msg_type": AP_REP,
            "service_principal": SERVICE_PRINCIPAL,
            "encrypted_data": encrypt(ap_rep_plaintext, client_service_session_key),
        })
        print("[FileServer] AP_REP sent. Mutual authentication complete.")

    except ConnectionError as e:
        print(f"[FileServer] Connection error from {client_address}: {e}")
    except Exception as e:
        print(f"[FileServer] Error handling client {client_address}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_socket.close()


def _ticket_expired(ticket: dict, now: float) -> bool:
    try:
        return now > float(ticket.get("endtime", 0))
    except (TypeError, ValueError):
        return True


def _authenticator_timestamp(authenticator: dict) -> float | None:
    try:
        if "ctime" in authenticator:
            return float(authenticator["ctime"]) + (int(authenticator.get("cusec", 0)) / 1_000_000)
        return float(authenticator.get("timestamp", 0))
    except (TypeError, ValueError):
        return None


def _error(code: str, message: str) -> dict:
    return {
        "msg_type": ERROR,
        "error_code": code,
        "error_message": message,
    }


def start_service_server():
    """Start the Application Server."""
    keytab_entry = load_keytab(KEYTAB_PATH, SERVICE_PRINCIPAL)
    service_key = str_to_key(keytab_entry["key"])

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((APP_SERVER_HOST, APP_SERVER_PORT))
    server_socket.listen(5)

    print(f"\n{'='*60}")
    print("  Kerberos Application Server (File Server)")
    print(f"  Principal: {SERVICE_PRINCIPAL}")
    print(f"  Keytab:    {KEYTAB_PATH}")
    print(f"  Listening on {APP_SERVER_HOST}:{APP_SERVER_PORT}")
    print(f"{'='*60}")
    print("[FileServer] Waiting for connections...\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, service_key),
                daemon=True,
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[FileServer] Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_service_server()
