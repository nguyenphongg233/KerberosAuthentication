"""
JSON/TCP wire helpers for running the Kerberos demo across machines.
"""

import argparse
import json
import socket
import socketserver
from dataclasses import asdict
from typing import Any, Callable, Dict

from models import (
    APReply,
    APRequest,
    ASReply,
    ASRequest,
    Authenticator,
    TGSReply,
    TGSRequest,
    Ticket,
)


def ticket_from_dict(data: Dict[str, Any]) -> Ticket:
    return Ticket(**data)


def authenticator_from_dict(data: Dict[str, Any]) -> Authenticator:
    return Authenticator(**data)


def as_request_to_dict(message: ASRequest) -> Dict[str, Any]:
    return asdict(message)


def as_request_from_dict(data: Dict[str, Any]) -> ASRequest:
    return ASRequest(**data)


def as_reply_to_dict(message: ASReply) -> Dict[str, Any]:
    data = asdict(message)
    data["tgt"] = asdict(message.tgt) if message.tgt else None
    return data


def as_reply_from_dict(data: Dict[str, Any]) -> ASReply:
    data = dict(data)
    if data.get("tgt") is not None:
        data["tgt"] = ticket_from_dict(data["tgt"])
    return ASReply(**data)


def tgs_request_to_dict(message: TGSRequest) -> Dict[str, Any]:
    data = asdict(message)
    data["tgt"] = asdict(message.tgt) if message.tgt else None
    data["authenticator"] = asdict(message.authenticator) if message.authenticator else None
    return data


def tgs_request_from_dict(data: Dict[str, Any]) -> TGSRequest:
    data = dict(data)
    data["tgt"] = ticket_from_dict(data["tgt"])
    data["authenticator"] = authenticator_from_dict(data["authenticator"])
    return TGSRequest(**data)


def tgs_reply_to_dict(message: TGSReply) -> Dict[str, Any]:
    data = asdict(message)
    data["service_ticket"] = asdict(message.service_ticket) if message.service_ticket else None
    return data


def tgs_reply_from_dict(data: Dict[str, Any]) -> TGSReply:
    data = dict(data)
    if data.get("service_ticket") is not None:
        data["service_ticket"] = ticket_from_dict(data["service_ticket"])
    return TGSReply(**data)


def ap_request_to_dict(message: APRequest) -> Dict[str, Any]:
    data = asdict(message)
    data["service_ticket"] = asdict(message.service_ticket) if message.service_ticket else None
    data["authenticator"] = asdict(message.authenticator) if message.authenticator else None
    return data


def ap_request_from_dict(data: Dict[str, Any]) -> APRequest:
    data = dict(data)
    data["service_ticket"] = ticket_from_dict(data["service_ticket"])
    data["authenticator"] = authenticator_from_dict(data["authenticator"])
    return APRequest(**data)


def ap_reply_to_dict(message: APReply) -> Dict[str, Any]:
    return asdict(message)


def ap_reply_from_dict(data: Dict[str, Any]) -> APReply:
    return APReply(**data)


def recv_json_file(file_obj) -> Dict[str, Any]:
    line = file_obj.readline()
    if not line:
        return {}
    return json.loads(line.decode("utf-8"))


def send_json_file(file_obj, payload: Dict[str, Any]) -> None:
    file_obj.write((json.dumps(payload) + "\n").encode("utf-8"))
    file_obj.flush()


def request_json(host: str, port: int, payload: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        file_obj = sock.makefile("rwb")
        send_json_file(file_obj, payload)
        return recv_json_file(file_obj)


def serve_json(host: str, port: int, handler: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
    class JsonHandler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                request = recv_json_file(self.rfile)
                response = handler(request)
            except Exception as exc:
                response = {"ok": False, "error": str(exc)}
            send_json_file(self.wfile, response)

    with socketserver.ThreadingTCPServer((host, port), JsonHandler) as server:
        server.allow_reuse_address = True
        print(f"Listening on {host}:{port}")
        server.serve_forever()


def add_host_port_args(parser: argparse.ArgumentParser, default_port: int) -> None:
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=default_port)
