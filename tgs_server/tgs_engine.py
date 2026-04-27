"""
TGS Engine: Logic xử lý của Ticket Granting Server
"""

import time
from models import TGSRequest, TGSReply, Ticket, Authenticator
from tgs_server.tgs_entity import TicketGrantingServerEntity
from tgs_server.tgs_crypto import TGSCryptoEngine
from database.database_engine import DatabaseEngine
from shared.utils import log_info, log_success, log_error, log_debug, generate_session_key


class TGSEngine:
    """Engine xử lý logic của TGS"""
    
    def __init__(self, tgs_entity: TicketGrantingServerEntity, db_engine: DatabaseEngine):
        self.tgs_entity = tgs_entity
        self.db_engine = db_engine
        self.crypto = TGSCryptoEngine()
    
    def process_tgs_request(self, tgs_request: TGSRequest, session_key_c_tgs: str) -> TGSReply:
        """Xử lý TGS-REQ từ Client
        
        Args:
            tgs_request: TGS-REQ message (chứa TGT và Authenticator)
            session_key_c_tgs: Khóa phiên K_c,tgs từ AS (dùng để giải mã Authenticator)
        
        Returns:
            TGS-REP message
        """
        log_info("TGS", f"Received TGS-REQ from {tgs_request.client_id}")
        
        # Bước 1: Kiểm tra Service có tồn tại không
        service_full_name = f"{tgs_request.server_id}@{self.tgs_entity.realm}"
        if not self.db_engine.verify_principal_exists(service_full_name):
            error_msg = f"Service not found: {service_full_name}"
            log_error("TGS", error_msg)
            return TGSReply(
                client_id=tgs_request.client_id,
                service_ticket=None,
                session_key_c_s="",
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        # Bước 2: Kiểm tra TGT có hợp lệ không
        if not tgs_request.tgt.is_valid():
            error_msg = f"TGT is expired"
            log_error("TGS", error_msg)
            return TGSReply(
                client_id=tgs_request.client_id,
                service_ticket=None,
                session_key_c_s="",
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        # Bước 3: Kiểm tra Authenticator có hợp lệ không
        if not tgs_request.authenticator.is_valid():
            error_msg = f"Authenticator is invalid or expired"
            log_error("TGS", error_msg)
            return TGSReply(
                client_id=tgs_request.client_id,
                service_ticket=None,
                session_key_c_s="",
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        log_success("TGS", f"TGT and Authenticator are valid")
        
        # Bước 4: Lấy Master Key của Service từ Database
        service_master_key = self.db_engine.get_principal_master_key(service_full_name)
        if not service_master_key:
            error_msg = f"Cannot retrieve key for {service_full_name}"
            log_error("TGS", error_msg)
            return TGSReply(
                client_id=tgs_request.client_id,
                service_ticket=None,
                session_key_c_s="",
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        # Bước 4b: Đăng ký service key vào TGS (nếu chưa có)
        if tgs_request.server_id not in self.tgs_entity.service_keys:
            self.tgs_entity.register_service(tgs_request.server_id, service_master_key)
            log_debug("TGS", f"Registered service {tgs_request.server_id} with its key")
        
        # Bước 5: Tạo Session Key cho Client-Service
        session_key_c_s = generate_session_key()
        log_debug("TGS", f"Generated session key K_c,s")
        
        # Bước 6: Tạo Service Ticket
        server_timestamp = time.time()
        service_ticket = Ticket(
            client_id=tgs_request.client_id,
            server_id=tgs_request.server_id,
            session_key=session_key_c_s,
            timestamp=server_timestamp,
            lifetime=tgs_request.lifetime,
            client_address=self.tgs_entity.server_address,
            realm=self.tgs_entity.realm,
            ticket_type="ST",
            nonce=tgs_request.tgt.nonce
        )
        
        # Bước 7: Mã hóa Service Ticket bằng khóa của Service
        st_data = {
            "client_id": service_ticket.client_id,
            "server_id": service_ticket.server_id,
            "session_key": service_ticket.session_key,
            "timestamp": service_ticket.timestamp,
            "lifetime": service_ticket.lifetime,
            "client_address": service_ticket.client_address,
            "realm": service_ticket.realm,
            "ticket_type": service_ticket.ticket_type,
            "nonce": service_ticket.nonce
        }
        service_ticket.encrypted_data = self.crypto.encrypt_dict(st_data, service_master_key)
        
        log_success("TGS", f"Created and encrypted Service Ticket for {tgs_request.server_id}")
        
        # Bước 8: Trả về TGS-REP
        tgs_reply = TGSReply(
            client_id=tgs_request.client_id,
            service_ticket=service_ticket,
            session_key_c_s=session_key_c_s,
            server_timestamp=server_timestamp,
            ok=True,
            error_message=""
        )
        
        log_success("TGS", f"Sending TGS-REP to {tgs_request.client_id}")
        return tgs_reply
