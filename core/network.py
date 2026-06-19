"""TCP framing utilities for Kerberos demo messages.

Frame format:
    [4 bytes: message length (big-endian)] + [N bytes: DER or JSON payload]
"""

import base64
import json
import struct
import socket

from core.asn1_codec import decode_message, encode_message
from core.messages import WIRE_FORMAT


def send_message(sock: socket.socket, data: dict) -> None:
    """
    Send a Kerberos message over a TCP socket with length-prefixed framing.

    Args:
        sock: The connected TCP socket.
        data: Dictionary to serialize and send.
    """
    payload = _serialize(data)
    length_prefix = struct.pack('>I', len(payload))
    sock.sendall(length_prefix + payload)


def receive_message(sock: socket.socket) -> dict:
    """
    Receive a length-prefixed Kerberos message from a TCP socket.

    Args:
        sock: The connected TCP socket.

    Returns:
        The deserialized dictionary from the received message.

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

    return _deserialize(raw_payload)


def _serialize(data: dict) -> bytes:
    if WIRE_FORMAT == "der":
        return encode_message(data)
    if WIRE_FORMAT == "json":
        return json.dumps(_to_jsonable(data)).encode("utf-8")
    raise ValueError(f"Unsupported KRB_WIRE_FORMAT: {WIRE_FORMAT}")


def _deserialize(payload: bytes) -> dict:
    if WIRE_FORMAT == "der":
        return decode_message(payload)
    if WIRE_FORMAT == "json":
        return _from_jsonable(json.loads(payload.decode("utf-8")))
    raise ValueError(f"Unsupported KRB_WIRE_FORMAT: {WIRE_FORMAT}")


def _to_jsonable(value):
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    return value


def _from_jsonable(value):
    if isinstance(value, dict):
        if set(value) == {"__bytes__"}:
            return base64.b64decode(value["__bytes__"].encode("ascii"))
        return {key: _from_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_from_jsonable(item) for item in value]
    return value


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
