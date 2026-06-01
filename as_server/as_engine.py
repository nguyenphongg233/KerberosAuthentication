"""
AS Engine: Logic xử lý của Authentication Server
"""

import time
from models import ASRequest, ASReply, Ticket
from as_server.as_entity import AuthenticationServerEntity
from as_server.as_crypto import ASCryptoEngine
from KDC_database.database_engine import DatabaseEngine
from utils import log_info, log_success, log_error, log_debug, generate_session_key


class ASEngine:
    """Engine xử lý logic của AS"""
    
    def __init__(self, as_entity: AuthenticationServerEntity, db_engine: DatabaseEngine):
        self.as_entity = as_entity
        self.db_engine = db_engine
        self.crypto = ASCryptoEngine()
    
    def process_as_request(self, as_request: ASRequest) -> ASReply:
        """Xử lý AS-REQ từ Client
        
        Args:
            as_request: AS-REQ message
        Returns:
            AS-REP message
        """
        log_info("AS", f"Received AS-REQ from {as_request.client_id}")
        
        # Bước 1: Kiểm tra Client có tồn tại không
        client_full_name = f"{as_request.client_id}@{self.as_entity.realm}"
        if not self.db_engine.verify_principal_exists(client_full_name):
            error_msg = f"Client not found: {client_full_name}"
            log_error("AS", error_msg)
            return ASReply(
                client_id=as_request.client_id,
                tgt=None,
                server_id=as_request.server_id,
                session_key_c_tgs="",
                server_timestamp=time.time(),
                lifetime=as_request.lifetime,
                nonce=as_request.nonce,
                ok=False,
                error_message=error_msg
            )
        
        # Bước 2: Lấy Master Key của Client từ Database
        client_master_key = self.db_engine.get_principal_master_key(client_full_name)
        if not client_master_key:
            error_msg = f"Cannot retrieve key for {client_full_name}"
            log_error("AS", error_msg)
            return ASReply(
                client_id=as_request.client_id,
                tgt = None,
                server_id=as_request.server_id,
                session_key_c_tgs="",
                server_timestamp=time.time(),
                lifetime=as_request.lifetime,
                nonce=as_request.nonce,
                ok=False,
                error_message=error_msg
            )
        
        # Step 3: AS does not receive the user's password over the network.
        # It encrypts the client portion with Kc from the database. If the
        # user types a wrong password, the client cannot decrypt AS-REP.
        log_success("AS", f"Client principal {as_request.client_id} found; issuing AS-REP")
        
        # Bước 4: Tạo Session Key cho Client-TGS
        session_key_c_tgs = generate_session_key()
        log_debug("AS", f"Generated session key K_c,tgs")
        
        # Bước 5: Tạo TGT (Ticket Granting Ticket)
        server_timestamp = time.time()
        tgt = Ticket(
            client_id=as_request.client_id,
            server_id=as_request.server_id,
            session_key=session_key_c_tgs,
            timestamp=server_timestamp,
            lifetime=as_request.lifetime,
            client_address=getattr(as_request, "client_address", "127.0.0.1"),
            realm=self.as_entity.realm,
            ticket_type="TGT",
            nonce=as_request.nonce
        )
        
        # Bước 6: Mã hóa TGT bằng khóa của TGS (AS có khóa này)
        tgt_data = {
            "client_id": tgt.client_id,
            "server_id": tgt.server_id,
            "session_key": tgt.session_key,
            "timestamp": tgt.timestamp,
            "lifetime": tgt.lifetime,
            "client_address": tgt.client_address,
            "realm": tgt.realm,
            "ticket_type": tgt.ticket_type,
            "nonce": tgt.nonce
        }
        tgt.encrypted_data = self.crypto.encrypt_dict(tgt_data, self.as_entity.master_key)
        
        log_success("AS", f"Created and encrypted TGT for {as_request.client_id}")
        
        # Bước 7: Tạo Client_Portion và mã hóa bằng khóa của Client
        # Client_Portion = E_{K_c}[Kc,tgs || IDtgs || TS2 || Lifetime2 || Nonce1]
        client_portion_data = {
            "session_key": session_key_c_tgs,
            "server_id": as_request.server_id,
            "timestamp": server_timestamp,
            "lifetime": as_request.lifetime,
            "nonce": as_request.nonce
        }
        client_portion_encrypted = self.crypto.encrypt_dict(client_portion_data, client_master_key)
        log_debug("AS", f"Encrypted Client_Portion for {as_request.client_id}")
        
        # Bước 8: Trả về AS-REP
        as_reply = ASReply(
            client_id=as_request.client_id,
            tgt=tgt,
            server_id=as_request.server_id,
            session_key_c_tgs=session_key_c_tgs,
            server_timestamp=server_timestamp,
            lifetime=as_request.lifetime,
            nonce=as_request.nonce,
            client_portion_encrypted=client_portion_encrypted,
            ok=True,
            error_message=""
        )
        
        log_success("AS", f"Sending AS-REP to {as_request.client_id}")
        return as_reply
