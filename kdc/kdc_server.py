"""
kdc_server.py - Main KDC process.

The KDC hosts both logical Kerberos services used by this demo:
Authentication Server (AS) and Ticket Granting Server (TGS).
"""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from core.messages import AS_REQ, TGS_REQ, KDC_BIND_HOST, KDC_HOST, KDC_PORT
from core.network import receive_message, send_message
from kdc.as_handler import handle_as_request
from kdc.database import DB_PATH, connect, init_database
from kdc.tgs_handler import handle_tgs_request


def handle_client(client_socket: socket.socket, client_address: tuple):
    """Handle a single KDC request in a dedicated thread."""
    conn = None
    try:
        print(f"\n[KDC] Connection from {client_address}")
        conn = connect()
        cursor = conn.cursor()

        request = receive_message(client_socket)
        msg_type = request.get("msg_type")
        print(f"[KDC] Received message type: {msg_type}")

        if msg_type == AS_REQ:
            response = handle_as_request(request, cursor)
        elif msg_type == TGS_REQ:
            response = handle_tgs_request(request, cursor)
        else:
            response = {
                "msg_type": "KRB_ERROR",
                "error_code": "KRB_ERR_GENERIC",
                "error_message": f"Unknown message type: {msg_type}",
            }

        send_message(client_socket, response)
        conn.commit()
        print(f"[KDC] Response sent: {response.get('msg_type', 'UNKNOWN')}")

    except ConnectionError as e:
        print(f"[KDC] Connection error from {client_address}: {e}")
    except Exception as e:
        print(f"[KDC] Error handling client {client_address}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if conn is not None:
            conn.close()
        client_socket.close()


def start_kdc_server():
    """Start the KDC server."""
    registered = init_database()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((KDC_BIND_HOST, KDC_PORT))
    server_socket.listen(5)

    print(f"[KDC] Database initialized at '{DB_PATH}'")
    print(f"[KDC] Registered principals: {registered}")
    print(f"\n{'='*60}")
    print("  Kerberos KDC Server")
    print(f"  Listening on {KDC_BIND_HOST}:{KDC_PORT}")
    if KDC_BIND_HOST != KDC_HOST:
        print(f"  Client target: {KDC_HOST}:{KDC_PORT}")
    print(f"{'='*60}")
    print("[KDC] Waiting for connections...\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[KDC] Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_kdc_server()
