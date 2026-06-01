"""
TGS Engine: Logic xử lý của Ticket Granting Server
"""

import time
from models import TGSRequest, TGSReply, Ticket, Authenticator
from tgs_server.tgs_entity import TicketGrantingServerEntity
from tgs_server.tgs_crypto import TGSCryptoEngine
from KDC_database.database_engine import DatabaseEngine
from utils import log_info, log_success, log_error, log_debug, generate_session_key


class TGSEngine:
    """Engine xử lý logic của TGS"""
    
    def __init__(self, tgs_entity: TicketGrantingServerEntity, db_engine: DatabaseEngine):
        self.tgs_entity = tgs_entity
        self.db_engine = db_engine
        self.crypto = TGSCryptoEngine()
        self.replay_cache = set()
    
    def process_tgs_request(self, tgs_request: TGSRequest, session_key_c_tgs: str) -> TGSReply:
        """Xử lý TGS-REQ từ Client
        
        Args:
            tgs_request: TGS-REQ message (chứa TGT và Authenticator)
            session_key_c_tgs: Khóa phiên K_c,tgs từ AS (dùng để giải mã Authenticator)
        
        Returns:
            TGS-REP message
        """
        log_info("TGS", f"Received TGS-REQ from {tgs_request.client_id} for {tgs_request.server_id}")

        def error_reply(message: str) -> TGSReply:
            log_error("TGS", message)
            return TGSReply(
                client_id=tgs_request.client_id,
                service_ticket=None,
                session_key_c_s="",
                server_timestamp=time.time(),
                ok=False,
                error_message=message
            )

        if not tgs_request.tgt:
            return error_reply("Missing TGT in TGS-REQ")

        # Step 1: decrypt and validate TGT with the TGS master key.
        tgt_data = self.crypto.decrypt_dict(
            tgs_request.tgt.encrypted_data,
            self.tgs_entity.master_key
        )
        if not tgt_data:
            return error_reply("Cannot decrypt TGT with TGS master key")

        required_tgt_fields = [
            "client_id", "server_id", "session_key", "timestamp",
            "lifetime", "client_address", "realm", "ticket_type"
        ]
        if any(field not in tgt_data for field in required_tgt_fields):
            return error_reply("Invalid TGT payload: missing required fields")

        if tgt_data["ticket_type"] != "TGT":
            return error_reply(f"Invalid ticket type: {tgt_data['ticket_type']}")

        if tgt_data["client_id"] != tgs_request.client_id:
            return error_reply("TGS-REQ client does not match TGT client")

        if tgt_data["server_id"] != self.tgs_entity.server_name:
            return error_reply(f"TGT was not issued for this TGS: {tgt_data['server_id']}")

        tgt = Ticket(
            client_id=tgt_data["client_id"],
            server_id=tgt_data["server_id"],
            session_key=tgt_data["session_key"],
            timestamp=float(tgt_data["timestamp"]),
            lifetime=int(tgt_data["lifetime"]),
            client_address=tgt_data["client_address"],
            realm=tgt_data["realm"],
            ticket_type=tgt_data["ticket_type"],
            nonce=tgt_data.get("nonce", "")
        )
        if not tgt.is_valid():
            return error_reply("TGT has expired")

        session_key_from_tgt = tgt.session_key
        if session_key_c_tgs and session_key_c_tgs != session_key_from_tgt:
            return error_reply("Provided K_c,tgs does not match the key inside TGT")

        log_debug("TGS", "TGT decrypted and validated successfully")

        # Step 2: decrypt and validate the authenticator with K_c,tgs.
        authenticator_data = {}
        if tgs_request.authenticator.encrypted_data:
            authenticator_data = self.crypto.decrypt_dict(
                tgs_request.authenticator.encrypted_data,
                session_key_from_tgt
            )
            if not authenticator_data:
                return error_reply("Cannot decrypt Authenticator with K_c,tgs")
        else:
            authenticator_data = {
                "client_id": tgs_request.authenticator.client_id,
                "timestamp": tgs_request.authenticator.timestamp,
                "client_address": tgs_request.authenticator.client_address,
                "realm": tgs_request.authenticator.realm
            }

        authenticator = Authenticator(
            client_id=authenticator_data.get("client_id", ""),
            timestamp=float(authenticator_data.get("timestamp", 0)),
            client_address=authenticator_data.get("client_address", ""),
            realm=authenticator_data.get("realm", "")
        )

        if authenticator.client_id != tgt.client_id:
            return error_reply("Authenticator client does not match TGT client")

        if authenticator.client_address != tgt.client_address:
            return error_reply("Authenticator client address does not match TGT address")

        if not authenticator.is_valid():
            return error_reply("Authenticator timestamp is outside allowed clock skew")

        replay_key = (
            authenticator.client_id,
            authenticator.client_address,
            authenticator.timestamp,
            tgs_request.server_id
        )
        if replay_key in self.replay_cache:
            return error_reply("Replay detected: TGS Authenticator has already been used")
        self.replay_cache.add(replay_key)

        log_debug("TGS", "Authenticator decrypted and validated successfully")

        # Step 3: find the requested service key.
        service_principal = (
            tgs_request.server_id
            if "@" in tgs_request.server_id
            else f"{tgs_request.server_id}@{self.tgs_entity.realm}"
        )
        if not self.db_engine.verify_principal_exists(service_principal):
            return error_reply(f"Service not found: {service_principal}")

        service_key = self.db_engine.get_principal_master_key(service_principal)
        if not service_key:
            return error_reply(f"Cannot retrieve key for service: {service_principal}")

        # Step 4: create and encrypt Service Ticket for the service server.
        session_key_c_s = generate_session_key()
        server_timestamp = time.time()
        service_ticket = Ticket(
            client_id=tgt.client_id,
            server_id=tgs_request.server_id,
            session_key=session_key_c_s,
            timestamp=server_timestamp,
            lifetime=tgs_request.lifetime,
            client_address=tgt.client_address,
            realm=self.tgs_entity.realm,
            ticket_type="ST"
        )

        service_ticket_data = {
            "client_id": service_ticket.client_id,
            "server_id": service_ticket.server_id,
            "session_key": service_ticket.session_key,
            "timestamp": service_ticket.timestamp,
            "lifetime": service_ticket.lifetime,
            "client_address": service_ticket.client_address,
            "realm": service_ticket.realm,
            "ticket_type": service_ticket.ticket_type
        }
        service_ticket.encrypted_data = self.crypto.encrypt_dict(service_ticket_data, service_key)
        log_success("TGS", f"Created Service Ticket for {tgt.client_id} -> {tgs_request.server_id}")

        # Step 5: encrypt the client-readable part with K_c,tgs.
        client_portion_data = {
            "session_key": session_key_c_s,
            "server_id": tgs_request.server_id,
            "timestamp": server_timestamp,
            "lifetime": tgs_request.lifetime,
            "nonce": tgs_request.nonce
        }
        client_portion_encrypted = self.crypto.encrypt_dict(
            client_portion_data,
            session_key_from_tgt
        )
        
        log_success("TGS", f"Sending TGS-REP to {tgt.client_id}")
        return TGSReply(
            client_id=tgt.client_id,
            service_ticket=service_ticket,
            session_key_c_s=session_key_c_s,
            server_timestamp=server_timestamp,
            nonce=tgs_request.nonce,
            client_portion_encrypted=client_portion_encrypted,
            ok=True,
            error_message=""
        )
