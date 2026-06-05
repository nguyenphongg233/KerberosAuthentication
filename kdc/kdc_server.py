"""
kdc_server.py - Main KDC (Key Distribution Center) process.

Runs a threaded TCP server on port 88 that dispatches incoming
requests to either the AS handler or the TGS handler based on
the message type.

Also initializes the SQLite database with principal entries.

Usage:
    python -m kdc.kdc_server
"""

import socket
import sqlite3
import threading
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.crypto import derive_key, key_to_str
from core.network import send_message, receive_message
from core.messages import AS_REQ, TGS_REQ, KDC_HOST, KDC_PORT, TGS_PRINCIPAL
from kdc.as_handler import handle_as_request
from kdc.tgs_handler import handle_tgs_request


# ============================================================
# Database path (stored alongside the KDC module)
# ============================================================
DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')


def init_database():
    """
    Initialize the SQLite database with the principals table.

    Pre-populates the database with:
        - 'alice' (password: 'alice_password') — a sample client
        - 'bob' (password: 'bob_password') — another sample client
        - 'krbtgt' (password: 'tgs_secret') — the TGS principal
        - 'fileserver' (password: 'fileserver_secret') — a service principal
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS principals (
            principal_name TEXT PRIMARY KEY,
            secret_key TEXT NOT NULL
        )
    ''')

    # Default principals with their derived keys
    default_principals = {
        "alice": "alice_password",
        "bob": "bob_password",
        TGS_PRINCIPAL: "tgs_secret",
        "fileserver": "fileserver_secret"
    }

    for name, password in default_principals.items():
        key = key_to_str(derive_key(password))
        cursor.execute(
            "INSERT OR IGNORE INTO principals (principal_name, secret_key) VALUES (?, ?)",
            (name, key)
        )

    conn.commit()
    conn.close()

    print(f"[KDC] Database initialized at '{DB_PATH}'")
    print(f"[KDC] Registered principals: {list(default_principals.keys())}")


def handle_client(client_socket: socket.socket, client_address: tuple):
    """
    Handle a single client connection in a separate thread.

    Reads the incoming message, dispatches to the appropriate handler
    (AS or TGS), and sends the response back to the client.

    Args:
        client_socket: The connected client socket.
        client_address: The (host, port) tuple of the client.
    """
    try:
        print(f"\n[KDC] Connection from {client_address}")

        # Each thread gets its own database connection (SQLite thread safety)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Receive the request
        request = receive_message(client_socket)
        msg_type = request.get("msg_type")

        print(f"[KDC] Received message type: {msg_type}")

        # Dispatch to the appropriate handler
        if msg_type == AS_REQ:
            response = handle_as_request(request, cursor)
        elif msg_type == TGS_REQ:
            response = handle_tgs_request(request, cursor)
        else:
            response = {
                "msg_type": "KRB_ERROR",
                "error_code": "KRB_ERR_GENERIC",
                "error_message": f"Unknown message type: {msg_type}"
            }

        # Send response
        send_message(client_socket, response)
        print(f"[KDC] Response sent: {response.get('msg_type', 'UNKNOWN')}")

        conn.close()

    except ConnectionError as e:
        print(f"[KDC] Connection error from {client_address}: {e}")
    except Exception as e:
        print(f"[KDC] Error handling client {client_address}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client_socket.close()


def start_kdc_server():
    """
    Start the KDC server.

    Listens on KDC_HOST:KDC_PORT and spawns a new thread
    for each incoming connection.
    """
    # Initialize the database
    init_database()

    # Create and configure the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((KDC_HOST, KDC_PORT))
    server_socket.listen(5)

    print(f"\n{'='*60}")
    print(f"  Kerberos KDC Server")
    print(f"  Listening on {KDC_HOST}:{KDC_PORT}")
    print(f"{'='*60}")
    print(f"[KDC] Waiting for connections...\n")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[KDC] Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_kdc_server()
