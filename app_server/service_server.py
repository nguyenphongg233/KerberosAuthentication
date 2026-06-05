"""
service_server.py - Application Server (File Server mock).

Handles Phase 3 of the Kerberos protocol (AP Exchange):
    Client sends AP_REQ with Service Ticket + Authenticator →
    Server validates → Server sends AP_REP for mutual authentication →
    Server provides the requested service.

Listens on port 8000.

Usage:
    python -m app_server.service_server
"""

import socket
import threading
import time
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptography.fernet import InvalidToken

from core.crypto import derive_key, encrypt, decrypt, str_to_key
from core.network import send_message, receive_message
from core.messages import (
    AP_REQ, AP_REP, ERROR,
    KRB_AP_ERR_MODIFIED, KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_EXPIRED,
    APP_SERVER_HOST, APP_SERVER_PORT, MAX_CLOCK_SKEW
)


# ============================================================
# Service Configuration
# ============================================================
SERVICE_PRINCIPAL = "fileserver"
SERVICE_PASSWORD = "fileserver_secret"


def handle_client(client_socket: socket.socket, client_address: tuple,
                   service_master_key: bytes):
    """
    Handle a single AP Exchange from a client.

    AP Exchange Flow:
        1. Receive AP_REQ with service ticket + authenticator.
        2. Decrypt service ticket with service's master key.
        3. Extract client-service session key from ticket.
        4. Decrypt authenticator with session key.
        5. Validate timestamp (replay prevention).
        6. Send AP_REP with timestamp+1 for mutual authentication.
        7. Provide service data.

    Args:
        client_socket: The connected client socket.
        client_address: The (host, port) tuple of the client.
        service_master_key: The service's Fernet master key.
    """
    try:
        print(f"\n[FileServer] Connection from {client_address}")

        # Receive AP_REQ
        request = receive_message(client_socket)
        msg_type = request.get("msg_type")

        if msg_type != AP_REQ:
            error_resp = _error(KRB_AP_ERR_MODIFIED,
                                f"Expected AP_REQ, got: {msg_type}")
            send_message(client_socket, error_resp)
            return

        encrypted_service_ticket = request.get("service_ticket")
        encrypted_authenticator = request.get("authenticator")

        # ── Step 1: Decrypt the Service Ticket ──────────────────
        try:
            service_ticket = decrypt(encrypted_service_ticket, service_master_key)
        except InvalidToken:
            print(f"[FileServer] ERROR: Failed to decrypt service ticket.")
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED, "Service ticket decryption failed."))
            return

        client_principal = service_ticket.get("client_principal")
        print(f"[FileServer] Service ticket from client: '{client_principal}'")

        # ── Step 2: Check ticket expiration ─────────────────────
        ticket_timestamp = service_ticket.get("timestamp", 0)
        ticket_lifetime = service_ticket.get("lifetime", 0)
        current_time = time.time()

        if current_time > ticket_timestamp + ticket_lifetime:
            print(f"[FileServer] ERROR: Service ticket has expired.")
            send_message(client_socket, _error(
                KRB_AP_ERR_TKT_EXPIRED, "Service ticket has expired."))
            return

        # ── Step 3: Decrypt the Authenticator ───────────────────
        client_service_session_key = str_to_key(
            service_ticket["client_service_session_key"]
        )

        try:
            authenticator = decrypt(encrypted_authenticator, client_service_session_key)
        except InvalidToken:
            print(f"[FileServer] ERROR: Failed to decrypt authenticator.")
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED, "Authenticator decryption failed."))
            return

        # ── Step 4: Validate the Authenticator ──────────────────
        # Check principal match
        if authenticator.get("client_principal") != client_principal:
            print(f"[FileServer] ERROR: Principal mismatch in authenticator.")
            send_message(client_socket, _error(
                KRB_AP_ERR_MODIFIED, "Authenticator principal mismatch."))
            return

        # Check timestamp for replay prevention
        auth_timestamp = authenticator.get("timestamp", 0)
        if abs(current_time - auth_timestamp) > MAX_CLOCK_SKEW:
            print(f"[FileServer] ERROR: Clock skew too great.")
            send_message(client_socket, _error(
                KRB_AP_ERR_SKEW, "Clock skew too great."))
            return

        print(f"[FileServer] ✓ Client '{client_principal}' authenticated successfully!")

        # ── Step 5: Build AP_REP for mutual authentication ──────
        # Return timestamp + 1 to prove we could decrypt the authenticator
        ap_rep_plaintext = {
            "timestamp": auth_timestamp + 1,
            "service_data": (
                f"Welcome to the File Server, {client_principal}! "
                f"You have been authenticated via Kerberos V5. "
                f"Access granted at {time.strftime('%Y-%m-%d %H:%M:%S')}."
            )
        }

        encrypted_ap_rep = encrypt(ap_rep_plaintext, client_service_session_key)

        ap_rep = {
            "msg_type": AP_REP,
            "encrypted_data": encrypted_ap_rep
        }

        send_message(client_socket, ap_rep)
        print(f"[FileServer] AP_REP sent. Mutual authentication complete.")
        print(f"[FileServer] Service provided to '{client_principal}'.")

    except ConnectionError as e:
        print(f"[FileServer] Connection error from {client_address}: {e}")
    except Exception as e:
        print(f"[FileServer] Error handling client {client_address}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_socket.close()


def _error(code: str, message: str) -> dict:
    """Build an error response dictionary."""
    return {
        "msg_type": ERROR,
        "error_code": code,
        "error_message": message
    }


def start_service_server():
    """
    Start the Application Server (File Server).

    Listens on APP_SERVER_HOST:APP_SERVER_PORT and spawns a new thread
    for each incoming AP Exchange request.
    """
    # Derive the service's master key (must match the key in KDC database)
    service_master_key = derive_key(SERVICE_PASSWORD)

    # Create and configure the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((APP_SERVER_HOST, APP_SERVER_PORT))
    server_socket.listen(5)

    print(f"\n{'='*60}")
    print(f"  Kerberos Application Server (File Server)")
    print(f"  Principal: {SERVICE_PRINCIPAL}")
    print(f"  Listening on {APP_SERVER_HOST}:{APP_SERVER_PORT}")
    print(f"{'='*60}")
    print(f"[FileServer] Waiting for connections...\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, service_master_key),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[FileServer] Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_service_server()
