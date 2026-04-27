"""
Client Engine: Logic xử lý của Client (Alice)
"""

import time
from models import (
    ASRequest, Authenticator, TGSRequest, APRequest,
    Ticket
)
from client.client_entity import KerberosClientEntity
from client.client_crypto import ClientCryptoEngine
from shared.utils import (
    log_info, log_success, log_error, log_debug, 
    generate_nonce, get_current_timestamp
)


class ClientEngine:
    """Engine xử lý logic của Client"""
    
    def __init__(self, client_entity: KerberosClientEntity):
        self.client_entity = client_entity
        self.crypto = ClientCryptoEngine()
    
    def create_as_request(self, tgs_name: str) -> ASRequest:
        """Tạo AS-REQ để xin TGT
        
        Args:
            tgs_name: Tên của TGS (e.g., "krbtgt")
        
        Returns:
            AS-REQ message
        """
        log_info("Client", "Creating AS-REQ...")
        
        as_request = ASRequest(
            client_id=self.client_entity.client_id,
            server_id=tgs_name,
            timestamp=get_current_timestamp(),
            nonce=generate_nonce(),
            lifetime=28800  # 8 tiếng
        )
        
        log_success("Client", f"AS-REQ created with nonce: {as_request.nonce[:8]}...")
        return as_request
    
    def process_as_reply(self, as_reply, client_master_key: str) -> bool:
        """Xử lý AS-REP từ AS
        
        Args:
            as_reply: AS-REP message
            client_master_key: Master Key của Client (để giải mã)
        
        Returns:
            True nếu thành công, False nếu thất bại
        """
        log_info("Client", "Processing AS-REP...")
        
        if not as_reply.ok:
            log_error("Client", f"AS-REP error: {as_reply.error_message}")
            return False
        
        # Lưu TGT và Session Key
        self.client_entity.tgt = as_reply.tgt
        self.client_entity.session_key_c_tgs = as_reply.session_key_c_tgs
        
        log_success("Client", f"AS-REP received successfully")
        log_debug("Client", f"Saved TGT and K_c,tgs")
        return True
    
    def create_tgs_request(self, service_name: str) -> TGSRequest:
        """Tạo TGS-REQ để xin Service Ticket
        
        Args:
            service_name: Tên của dịch vụ (e.g., "mail-service")
        
        Returns:
            TGS-REQ message
        """
        log_info("Client", f"Creating TGS-REQ for service: {service_name}...")
        
        if not self.client_entity.tgt:
            log_error("Client", "No TGT available. Run AS-REQ first.")
            return None
        
        # Tạo Authenticator mới cho TGS
        authenticator = Authenticator(
            client_id=self.client_entity.client_id,
            timestamp=get_current_timestamp(),
            client_address=self.client_entity.client_address,
            realm=self.client_entity.realm
        )
        
        # Mã hóa Authenticator bằng K_c,tgs
        auth_data = {
            "client_id": authenticator.client_id,
            "timestamp": authenticator.timestamp,
            "client_address": authenticator.client_address,
            "realm": authenticator.realm
        }
        authenticator.encrypted_data = self.crypto.encrypt_dict(
            auth_data, self.client_entity.session_key_c_tgs
        )
        
        tgs_request = TGSRequest(
            client_id=self.client_entity.client_id,
            server_id=service_name,
            tgt=self.client_entity.tgt,
            authenticator=authenticator,
            lifetime=3600  # 1 tiếng
        )
        
        log_success("Client", f"TGS-REQ created for {service_name}")
        return tgs_request
    
    def process_tgs_reply(self, tgs_reply) -> bool:
        """Xử lý TGS-REP từ TGS
        
        Args:
            tgs_reply: TGS-REP message
        
        Returns:
            True nếu thành công, False nếu thất bại
        """
        log_info("Client", "Processing TGS-REP...")
        
        if not tgs_reply.ok:
            log_error("Client", f"TGS-REP error: {tgs_reply.error_message}")
            return False
        
        # Lưu Service Ticket và Session Key
        self.client_entity.service_ticket = tgs_reply.service_ticket
        self.client_entity.session_key_c_s = tgs_reply.session_key_c_s
        
        log_success("Client", f"TGS-REP received successfully")
        log_debug("Client", f"Saved Service Ticket and K_c,s")
        return True
    
    def create_ap_request(self) -> APRequest:
        """Tạo AP-REQ để truy cập dịch vụ
        
        Returns:
            AP-REQ message
        """
        log_info("Client", "Creating AP-REQ...")
        
        if not self.client_entity.service_ticket:
            log_error("Client", "No Service Ticket available. Run TGS-REQ first.")
            return None
        
        # Tạo Authenticator mới cho Service
        authenticator = Authenticator(
            client_id=self.client_entity.client_id,
            timestamp=get_current_timestamp(),
            client_address=self.client_entity.client_address,
            realm=self.client_entity.realm
        )
        
        # Mã hóa Authenticator bằng K_c,s
        auth_data = {
            "client_id": authenticator.client_id,
            "timestamp": authenticator.timestamp,
            "client_address": authenticator.client_address,
            "realm": authenticator.realm
        }
        authenticator.encrypted_data = self.crypto.encrypt_dict(
            auth_data, self.client_entity.session_key_c_s
        )
        
        ap_request = APRequest(
            service_ticket=self.client_entity.service_ticket,
            authenticator=authenticator
        )
        
        log_success("Client", "AP-REQ created")
        return ap_request
    
    def process_ap_reply(self, ap_reply, original_timestamp: float) -> bool:
        """Xử lý AP-REP từ Service Server (Mutual Authentication)
        
        Args:
            ap_reply: AP-REP message
            original_timestamp: Timestamp gốc từ AP-REQ
        
        Returns:
            True nếu xác thực thành công
        """
        log_info("Client", "Processing AP-REP (Mutual Authentication)...")
        
        if not ap_reply.ok:
            log_error("Client", f"AP-REP error: {ap_reply.error_message}")
            return False
        
        # Kiểm tra Mutual Authentication (Timestamp + 1)
        expected_proof = original_timestamp + 1
        if abs(ap_reply.client_timestamp_proof - expected_proof) > 0.1:
            log_error("Client", "Mutual authentication failed: Invalid timestamp proof")
            return False
        
        log_success("Client", "Mutual authentication successful!")
        log_success("Client", "Access to service granted!")
        return True
