"""
Run the Kerberos demo across machines.

Typical lab setup:
  Machine 1 (KDC):     python distributed.py kdc --host 0.0.0.0 --port 8800
  Machine 2 (Service): python distributed.py service --host 0.0.0.0 --port 8801
  Machine 3 (Client):  python distributed.py client --kdc-host <kdc-ip> --service-host <service-ip>
"""

import argparse

from KDC_database.database_crypto import DatabaseCryptoEngine
from KDC_database.database_engine import DatabaseEngine
from KDC_database.database_entity import KDCDatabaseEntity
from as_server.as_engine import ASEngine
from as_server.as_entity import AuthenticationServerEntity
from client.client_engine import ClientEngine
from client.client_entity import KerberosClientEntity
from service_server.service_engine import ServiceEngine
from service_server.service_entity import ServiceServerEntity
from tgs_server.tgs_engine import TGSEngine
from tgs_server.tgs_entity import TicketGrantingServerEntity
from utils import log_error, log_info, log_success, section_header
from wire import (
    add_host_port_args,
    ap_reply_from_dict,
    ap_reply_to_dict,
    ap_request_from_dict,
    ap_request_to_dict,
    as_reply_from_dict,
    as_reply_to_dict,
    as_request_from_dict,
    as_request_to_dict,
    request_json,
    serve_json,
    tgs_reply_from_dict,
    tgs_reply_to_dict,
    tgs_request_from_dict,
    tgs_request_to_dict,
)


REALM = "HUST.EDU.VN"
TGS_SECRET = "TGS_SECRET_KEY"
MAIL_SERVICE_SECRET = "MAIL_SERVICE_SECRET"


def build_kdc():
    db_entity = KDCDatabaseEntity(realm=REALM)
    db_engine = DatabaseEngine(db_entity)
    db_engine.initialize_database()

    as_entity = AuthenticationServerEntity(
        server_name="AS",
        realm=REALM,
        master_key=DatabaseCryptoEngine.hash_password(TGS_SECRET),
        server_address="192.168.1.10",
    )
    tgs_entity = TicketGrantingServerEntity(
        server_name="krbtgt",
        realm=REALM,
        master_key=DatabaseCryptoEngine.hash_password(TGS_SECRET),
        server_address="192.168.1.10",
    )
    return ASEngine(as_entity, db_engine), TGSEngine(tgs_entity, db_engine)


def run_kdc(args):
    as_engine, tgs_engine = build_kdc()

    def handle(message):
        message_type = message.get("type")
        payload = message.get("payload", {})
        if message_type == "AS_REQ":
            reply = as_engine.process_as_request(as_request_from_dict(payload))
            return {"ok": True, "type": "AS_REP", "payload": as_reply_to_dict(reply)}
        if message_type == "TGS_REQ":
            request = tgs_request_from_dict(payload)
            # TGS extracts K_c,tgs from the encrypted TGT. Do not trust a client-supplied key.
            reply = tgs_engine.process_tgs_request(request, "")
            return {"ok": True, "type": "TGS_REP", "payload": tgs_reply_to_dict(reply)}
        return {"ok": False, "error": f"unknown message type: {message_type}"}

    section_header("KDC Server (AS + TGS)", "=", 80)
    serve_json(args.host, args.port, handle)


def build_service():
    service_entity = ServiceServerEntity(
        service_name="mail-service",
        realm=REALM,
        master_key=DatabaseCryptoEngine.hash_password(MAIL_SERVICE_SECRET),
        server_address="192.168.1.20",
        instance="mailserver.hust.edu.vn",
    )
    return ServiceEngine(service_entity)


def run_service(args):
    service_engine = build_service()

    def handle(message):
        message_type = message.get("type")
        payload = message.get("payload", {})
        if message_type == "AP_REQ":
            reply = service_engine.process_ap_request(ap_request_from_dict(payload))
            return {"ok": True, "type": "AP_REP", "payload": ap_reply_to_dict(reply)}
        return {"ok": False, "error": f"unknown message type: {message_type}"}

    section_header("Service Server", "=", 80)
    serve_json(args.host, args.port, handle)


def run_client(args):
    section_header("Distributed Kerberos Client", "=", 80)
    client_entity = KerberosClientEntity(
        client_id=args.client_id,
        realm=REALM,
        password=args.password,
        client_address=args.client_address,
    )
    client_engine = ClientEngine(client_entity)

    as_request = client_engine.create_as_request("krbtgt")
    log_info("Network", f"Sending AS-REQ to KDC {args.kdc_host}:{args.kdc_port}")
    as_response = request_json(
        args.kdc_host,
        args.kdc_port,
        {"type": "AS_REQ", "payload": as_request_to_dict(as_request)},
    )
    if not as_response.get("ok"):
        log_error("Network", as_response.get("error", "AS request failed"))
        return
    as_reply = as_reply_from_dict(as_response["payload"])
    if not client_engine.process_as_reply(as_reply, as_request, args.password):
        log_error("Client", "Phase 1 failed")
        return
    log_success("Client", "Phase 1 completed")

    tgs_request = client_engine.create_tgs_request(args.service_name)
    log_info("Network", f"Sending TGS-REQ to KDC {args.kdc_host}:{args.kdc_port}")
    tgs_response = request_json(
        args.kdc_host,
        args.kdc_port,
        {"type": "TGS_REQ", "payload": tgs_request_to_dict(tgs_request)},
    )
    if not tgs_response.get("ok"):
        log_error("Network", tgs_response.get("error", "TGS request failed"))
        return
    tgs_reply = tgs_reply_from_dict(tgs_response["payload"])
    if not client_engine.process_tgs_reply(tgs_reply, tgs_request):
        log_error("Client", "Phase 2 failed")
        return
    log_success("Client", "Phase 2 completed")

    ap_request = client_engine.create_ap_request()
    log_info("Network", f"Sending AP-REQ to Service {args.service_host}:{args.service_port}")
    ap_response = request_json(
        args.service_host,
        args.service_port,
        {"type": "AP_REQ", "payload": ap_request_to_dict(ap_request)},
    )
    if not ap_response.get("ok"):
        log_error("Network", ap_response.get("error", "AP request failed"))
        return
    ap_reply = ap_reply_from_dict(ap_response["payload"])
    if not client_engine.process_ap_reply(ap_reply, ap_request):
        log_error("Client", "Phase 3 failed")
        return
    log_success("Client", "Distributed authentication completed")


def build_parser():
    parser = argparse.ArgumentParser(description="Distributed Kerberos demo")
    subparsers = parser.add_subparsers(dest="role", required=True)

    kdc_parser = subparsers.add_parser("kdc", help="run AS+TGS server")
    add_host_port_args(kdc_parser, 8800)

    service_parser = subparsers.add_parser("service", help="run service server")
    add_host_port_args(service_parser, 8801)

    client_parser = subparsers.add_parser("client", help="run client")
    client_parser.add_argument("--kdc-host", required=True)
    client_parser.add_argument("--kdc-port", type=int, default=8800)
    client_parser.add_argument("--service-host", required=True)
    client_parser.add_argument("--service-port", type=int, default=8801)
    client_parser.add_argument("--client-id", default="alice")
    client_parser.add_argument("--password", default="alice_password_123")
    client_parser.add_argument("--client-address", default="192.168.1.100")
    client_parser.add_argument("--service-name", default="mail-service")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.role == "kdc":
        run_kdc(args)
    elif args.role == "service":
        run_service(args)
    elif args.role == "client":
        run_client(args)


if __name__ == "__main__":
    main()
