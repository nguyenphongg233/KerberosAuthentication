"""
network.py - TCP Socket utilities for JSON data exchange.

Implements length-prefixed framing over TCP sockets to reliably
send and receive JSON-serialized messages between Kerberos components.

Frame format:
    [4 bytes: message length (big-endian)] + [N bytes: JSON payload]
"""

import json
import struct
import socket


def send_message(sock: socket.socket, data: dict) -> None:
    """
    Send a JSON message over a TCP socket with length-prefixed framing.

    Args:
        sock: The connected TCP socket.
        data: Dictionary to serialize and send.
    """
    payload = json.dumps(data).encode('utf-8')
    length_prefix = struct.pack('>I', len(payload))
    sock.sendall(length_prefix + payload)


def receive_message(sock: socket.socket) -> dict:
    """
    Receive a length-prefixed JSON message from a TCP socket.

    Args:
        sock: The connected TCP socket.

    Returns:
        The deserialized dictionary from the received JSON message.

    Raises:
        ConnectionError: If the connection is closed unexpectedly.
    """
    # Read the 4-byte length header
    raw_length = _recv_exact(sock, 4)
    if not raw_length:
        raise ConnectionError("Connection closed while reading message length.")

    message_length = struct.unpack('>I', raw_length)[0]

    # Read the full message payload
    raw_payload = _recv_exact(sock, message_length)
    if not raw_payload:
        raise ConnectionError("Connection closed while reading message payload.")

    return json.loads(raw_payload.decode('utf-8'))


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Receive exactly `num_bytes` bytes from the socket.

    Args:
        sock: The TCP socket to read from.
        num_bytes: The exact number of bytes to receive.

    Returns:
        The received bytes, or empty bytes if the connection is closed.
    """
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return b''
        data += chunk
    return data
