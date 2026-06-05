"""
client_app.py - User CLI to initiate Kerberos authentication.

Orchestrates the full 3-phase Kerberos authentication flow:
    Phase 1: AS Exchange  → Obtain TGT
    Phase 2: TGS Exchange → Obtain Service Ticket
    Phase 3: AP Exchange  → Access the Application Server

Usage:
    python -m client.client_app
"""

import socket
import time
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptography.fernet import InvalidToken

from core.crypto import derive_key, encrypt, decrypt, key_to_str, str_to_key
from core.network import send_message, receive_message
from core.messages import (
    AS_REQ, AS_REP, TGS_REQ, TGS_REP, AP_REQ, AP_REP, ERROR,
    KDC_HOST, KDC_PORT, APP_SERVER_HOST, APP_SERVER_PORT, TGS_PRINCIPAL
)
from client.credential_cache import CredentialCache


# Global credential cache
cache = CredentialCache()


def phase1_as_exchange(client_principal: str, password: str) -> bool:
    """
    Phase 1: Authentication Service (AS) Exchange.

    Sends AS_REQ to the KDC and processes AS_REP to obtain a TGT.

    Args:
        client_principal: The client's username/principal.
        password: The client's plaintext password.

    Returns:
        True if the AS exchange succeeded, False otherwise.
    """
    print(f"\n{'─'*50}")
    print(f"  Phase 1: AS Exchange (Authentication)")
    print(f"{'─'*50}")

    # Derive the client's master key from the password
    client_master_key = derive_key(password)

    # Build AS_REQ
    as_req = {
        "msg_type": AS_REQ,
        "client_principal": client_principal,
        "timestamp": time.time()
    }

    print(f"[Client] Sending AS_REQ to KDC ({KDC_HOST}:{KDC_PORT})...")
    print(f"         Principal: {client_principal}")

    try:
        # Connect to KDC and send AS_REQ
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((KDC_HOST, KDC_PORT))
        send_message(sock, as_req)

        # Receive AS_REP
        response = receive_message(sock)
        sock.close()

    except ConnectionRefusedError:
        print("[Client] ERROR: Cannot connect to KDC. Is the KDC server running?")
        return False
    except Exception as e:
        print(f"[Client] ERROR: Network error during AS Exchange: {e}")
        return False

    # Check for error response
    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from KDC: {response.get('error_message')}")
        return False

    if response.get("msg_type") != AS_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    # Decrypt AS_REP with client's master key
    try:
        as_rep_data = decrypt(response["encrypted_data"], client_master_key)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt AS_REP. Wrong password?")
        return False

    # Extract session key and TGT
    client_tgs_session_key = str_to_key(as_rep_data["client_tgs_session_key"])
    tgt = response["tgt"]

    # Store in credential cache
    cache.store_tgt(tgt, client_tgs_session_key)

    print(f"[Client] ✓ AS Exchange successful!")
    print(f"         TGT received and cached.")
    print(f"         Session key established with TGS.")
    print(f"         Ticket lifetime: {as_rep_data['lifetime']}s")

    return True


def phase2_tgs_exchange(service_principal: str) -> bool:
    """
    Phase 2: Ticket-Granting Service (TGS) Exchange.

    Sends TGS_REQ with TGT + Authenticator to obtain a Service Ticket.

    Args:
        service_principal: The target service to access.

    Returns:
        True if the TGS exchange succeeded, False otherwise.
    """
    print(f"\n{'─'*50}")
    print(f"  Phase 2: TGS Exchange (Service Ticket)")
    print(f"{'─'*50}")

    # Retrieve cached TGT and session key
    tgt, client_tgs_session_key = cache.get_tgt()

    if tgt is None:
        print("[Client] ERROR: No TGT in cache. Run Phase 1 first.")
        return False

    # Build Authenticator (encrypted with client-TGS session key)
    authenticator_plaintext = {
        "client_principal": client_principal_global,
        "timestamp": time.time()
    }
    encrypted_authenticator = encrypt(authenticator_plaintext, client_tgs_session_key)

    # Build TGS_REQ
    tgs_req = {
        "msg_type": TGS_REQ,
        "service_principal": service_principal,
        "tgt": tgt,
        "authenticator": encrypted_authenticator
    }

    print(f"[Client] Sending TGS_REQ to KDC ({KDC_HOST}:{KDC_PORT})...")
    print(f"         Requested service: {service_principal}")

    try:
        # Connect to KDC and send TGS_REQ
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((KDC_HOST, KDC_PORT))
        send_message(sock, tgs_req)

        # Receive TGS_REP
        response = receive_message(sock)
        sock.close()

    except ConnectionRefusedError:
        print("[Client] ERROR: Cannot connect to KDC. Is the KDC server running?")
        return False
    except Exception as e:
        print(f"[Client] ERROR: Network error during TGS Exchange: {e}")
        return False

    # Check for error response
    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from KDC: {response.get('error_message')}")
        return False

    if response.get("msg_type") != TGS_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    # Decrypt TGS_REP with client-TGS session key
    try:
        tgs_rep_data = decrypt(response["encrypted_data"], client_tgs_session_key)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt TGS_REP.")
        return False

    # Extract service session key and service ticket
    client_service_session_key = str_to_key(tgs_rep_data["client_service_session_key"])
    service_ticket = response["service_ticket"]

    # Store in credential cache
    cache.store_service_ticket(service_principal, service_ticket, client_service_session_key)

    print(f"[Client] ✓ TGS Exchange successful!")
    print(f"         Service Ticket received for '{service_principal}'.")
    print(f"         Session key established with service.")
    print(f"         Ticket lifetime: {tgs_rep_data['lifetime']}s")

    return True


def phase3_ap_exchange(service_principal: str) -> bool:
    """
    Phase 3: Application Service (AP) Exchange.

    Sends AP_REQ with Service Ticket + Authenticator to the Application Server.
    Verifies mutual authentication via AP_REP.

    Args:
        service_principal: The target service to access.

    Returns:
        True if the AP exchange succeeded, False otherwise.
    """
    print(f"\n{'─'*50}")
    print(f"  Phase 3: AP Exchange (Service Access)")
    print(f"{'─'*50}")

    # Retrieve cached service ticket and session key
    service_ticket, client_service_session_key = cache.get_service_ticket(service_principal)

    if service_ticket is None:
        print("[Client] ERROR: No service ticket in cache. Run Phase 2 first.")
        return False

    # Build Authenticator (encrypted with client-service session key)
    current_time = time.time()
    authenticator_plaintext = {
        "client_principal": client_principal_global,
        "timestamp": current_time
    }
    encrypted_authenticator = encrypt(authenticator_plaintext, client_service_session_key)

    # Build AP_REQ
    ap_req = {
        "msg_type": AP_REQ,
        "service_ticket": service_ticket,
        "authenticator": encrypted_authenticator
    }

    print(f"[Client] Sending AP_REQ to Application Server ({APP_SERVER_HOST}:{APP_SERVER_PORT})...")

    try:
        # Connect to Application Server and send AP_REQ
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((APP_SERVER_HOST, APP_SERVER_PORT))
        send_message(sock, ap_req)

        # Receive AP_REP
        response = receive_message(sock)
        sock.close()

    except ConnectionRefusedError:
        print("[Client] ERROR: Cannot connect to Application Server. Is it running?")
        return False
    except Exception as e:
        print(f"[Client] ERROR: Network error during AP Exchange: {e}")
        return False

    # Check for error response
    if response.get("msg_type") == ERROR:
        print(f"[Client] ERROR from Server: {response.get('error_message')}")
        return False

    if response.get("msg_type") != AP_REP:
        print(f"[Client] ERROR: Unexpected response type: {response.get('msg_type')}")
        return False

    # Decrypt AP_REP for mutual authentication
    try:
        ap_rep_data = decrypt(response["encrypted_data"], client_service_session_key)
    except InvalidToken:
        print("[Client] ERROR: Failed to decrypt AP_REP. Mutual authentication failed!")
        return False

    # Verify mutual authentication: server should return timestamp + 1
    server_timestamp = ap_rep_data.get("timestamp")
    expected_timestamp = current_time + 1

    if abs(server_timestamp - expected_timestamp) < 0.01:
        print(f"[Client] ✓ Mutual authentication verified!")
    else:
        print(f"[Client] WARNING: Timestamp mismatch in mutual authentication.")
        print(f"         Expected: {expected_timestamp}, Got: {server_timestamp}")

    # Display the service response
    service_data = ap_rep_data.get("service_data", "No data received.")
    print(f"\n{'='*50}")
    print(f"  SERVICE RESPONSE")
    print(f"{'='*50}")
    print(f"  {service_data}")
    print(f"{'='*50}")

    return True


# ============================================================
# Main Application
# ============================================================

# Global variable to store the client principal name
client_principal_global = None


def main():
    """Main entry point for the Kerberos client application."""
    global client_principal_global

    print(f"\n{'='*60}")
    print(f"  Kerberos V5 Client Application")
    print(f"{'='*60}")
    print(f"  KDC Server:  {KDC_HOST}:{KDC_PORT}")
    print(f"  App Server:  {APP_SERVER_HOST}:{APP_SERVER_PORT}")
    print(f"{'='*60}\n")

    # ── Get user credentials ────────────────────────────────────
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return

    password = input("Enter password: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return

    client_principal_global = username

    # ── Phase 1: AS Exchange ────────────────────────────────────
    if not phase1_as_exchange(username, password):
        print("\n[Client] Authentication failed. Exiting.")
        return

    # ── Phase 2: TGS Exchange ───────────────────────────────────
    service_name = "fileserver"
    print(f"\n[Client] Requesting access to service: '{service_name}'")

    if not phase2_tgs_exchange(service_name):
        print("\n[Client] Failed to obtain service ticket. Exiting.")
        return

    # ── Phase 3: AP Exchange ────────────────────────────────────
    if not phase3_ap_exchange(service_name):
        print("\n[Client] Failed to access the service. Exiting.")
        return

    print(f"\n[Client] ✓ Full Kerberos authentication completed successfully!")
    print(f"[Client] All 3 phases completed. Session established.\n")


if __name__ == "__main__":
    main()
