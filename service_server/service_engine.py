"""
Service Server Engine: Logic xu ly cua Service Server
"""

import time
from models import APRequest, APReply
from service_server.service_entity import ServiceServerEntity
from service_server.service_crypto import ServiceCryptoEngine
from utils import log_info, log_success, log_error, log_debug


class ServiceEngine:
    """Engine xu ly logic cua Service Server"""

    def __init__(self, service_entity: ServiceServerEntity):
        self.service_entity = service_entity
        self.crypto = ServiceCryptoEngine()
        self.replay_cache = set()

    def process_ap_request(self, ap_request: APRequest) -> APReply:
        """Xu ly AP-REQ tu Client va tra ve AP-REP."""
        log_info("ServiceServer", "Received AP-REQ")

        def error_reply(message: str) -> APReply:
            log_error("ServiceServer", message)
            return APReply(
                client_timestamp_proof=0,
                server_timestamp=time.time(),
                ok=False,
                error_message=message
            )

        if not ap_request.service_ticket:
            return error_reply("Missing Service Ticket in AP-REQ")

        # Step 1: Service decrypts ST with its long-term key Kv.
        ticket_data = self.crypto.decrypt_dict(
            ap_request.service_ticket.encrypted_data,
            self.service_entity.master_key
        )
        if not ticket_data:
            return error_reply("Cannot decrypt Service Ticket with service key")

        required_ticket_fields = [
            "client_id", "server_id", "session_key", "timestamp",
            "lifetime", "client_address", "realm", "ticket_type"
        ]
        if any(field not in ticket_data for field in required_ticket_fields):
            return error_reply("Invalid Service Ticket payload: missing required fields")

        if ticket_data["ticket_type"] != "ST":
            return error_reply(f"Invalid ticket type: {ticket_data['ticket_type']}")

        valid_service_ids = {self.service_entity.service_name, self.service_entity.full_name}
        if ticket_data["server_id"] not in valid_service_ids:
            return error_reply(f"Service Ticket was not issued for this service: {ticket_data['server_id']}")

        ticket_timestamp = float(ticket_data["timestamp"])
        ticket_lifetime = int(ticket_data["lifetime"])
        if time.time() - ticket_timestamp > ticket_lifetime:
            return error_reply("Service Ticket has expired")

        session_key_c_s = ticket_data["session_key"]
        log_debug("ServiceServer", "Service Ticket decrypted and validated successfully")

        # Step 2: Service decrypts Authenticator with K_c,s from ST.
        authenticator_data = self.crypto.decrypt_dict(
            ap_request.authenticator.encrypted_data,
            session_key_c_s
        )
        if not authenticator_data:
            return error_reply("Cannot decrypt Authenticator with K_c,s")

        client_id = authenticator_data.get("client_id", "")
        client_address = authenticator_data.get("client_address", "")
        client_timestamp = float(authenticator_data.get("timestamp", 0))

        if client_id != ticket_data["client_id"]:
            return error_reply("Authenticator client does not match Service Ticket client")

        if client_address != ticket_data["client_address"]:
            return error_reply("Authenticator client address does not match Service Ticket address")

        if abs(time.time() - client_timestamp) > 300:
            return error_reply("Authenticator timestamp is outside allowed clock skew")

        replay_key = (
            client_id,
            client_address,
            client_timestamp,
            ticket_data["server_id"]
        )
        if replay_key in self.replay_cache:
            return error_reply("Replay detected: AP Authenticator has already been used")
        self.replay_cache.add(replay_key)

        # Step 3: AP-REP proves the server owns Kv and recovered K_c,s.
        client_timestamp_proof = client_timestamp + 1
        server_timestamp = time.time()
        server_proof_encrypted = self.crypto.encrypt_dict(
            {
                "client_timestamp_proof": client_timestamp_proof,
                "server_timestamp": server_timestamp
            },
            session_key_c_s
        )

        log_success("ServiceServer", f"Client {client_id} authenticated successfully")
        log_success("ServiceServer", "Sending AP-REP for mutual authentication")
        return APReply(
            client_timestamp_proof=client_timestamp_proof,
            server_timestamp=server_timestamp,
            server_proof_encrypted=server_proof_encrypted,
            ok=True,
            error_message=""
        )
