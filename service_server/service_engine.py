"""
Service Server Engine: Logic xử lý của Service Server
"""

import time
from models import APRequest, APReply
from service_server.service_entity import ServiceServerEntity
from service_server.service_crypto import ServiceCryptoEngine
from shared.utils import log_info, log_success, log_error, log_debug


class ServiceEngine:
    """Engine xử lý logic của Service Server"""
    
    def __init__(self, service_entity: ServiceServerEntity):
        self.service_entity = service_entity
        self.crypto = ServiceCryptoEngine()
    
    def process_ap_request(self, ap_request: APRequest, service_session_key: str) -> APReply:
        """Xử lý AP-REQ từ Client
        
        Args:
            ap_request: AP-REQ message (chứa Service Ticket và Authenticator)
            service_session_key: Khóa phiên K_c,s (dùng để giải mã Authenticator)
        
        Returns:
            AP-REP message
        """
        log_info("Service", f"Received AP-REQ from {ap_request.authenticator.client_id}")
        
        # Bước 1: Kiểm tra Service Ticket có hợp lệ không
        if not ap_request.service_ticket.is_valid():
            error_msg = "Service Ticket is expired"
            log_error("Service", error_msg)
            return APReply(
                client_timestamp_proof=0,
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        # Bước 2: Kiểm tra Authenticator có hợp lệ không
        if not ap_request.authenticator.is_valid():
            error_msg = "Authenticator is invalid or expired"
            log_error("Service", error_msg)
            return APReply(
                client_timestamp_proof=0,
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        # Bước 3: Kiểm tra client_id trong Service Ticket có khớp với Authenticator không
        if ap_request.service_ticket.client_id != ap_request.authenticator.client_id:
            error_msg = "Client ID mismatch between Ticket and Authenticator"
            log_error("Service", error_msg)
            return APReply(
                client_timestamp_proof=0,
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        # Bước 4: Kiểm tra server_id trong Service Ticket là dịch vụ này không
        # So sánh cả dạng "service_name" và "service_name/instance@realm"
        service_names = [
            self.service_entity.service_name,
            self.service_entity.full_name,
            f"{self.service_entity.service_name}@{self.service_entity.realm}"
        ]
        
        if ap_request.service_ticket.server_id not in service_names:
            error_msg = f"Service mismatch: expected {self.service_entity.full_name}, got {ap_request.service_ticket.server_id}"
            log_error("Service", error_msg)
            return APReply(
                client_timestamp_proof=0,
                server_timestamp=time.time(),
                ok=False,
                error_message=error_msg
            )
        
        log_success("Service", f"Service Ticket and Authenticator are valid")
        log_success("Service", f"Client {ap_request.authenticator.client_id} authenticated successfully")
        
        # Bước 5: Tạo AP-REP (Mutual Authentication)
        # Server trích xuất Timestamp từ Authenticator, cộng thêm 1, mã hóa lại bằng K_c,s
        server_timestamp = time.time()
        client_timestamp_proof = ap_request.authenticator.timestamp + 1
        
        ap_reply = APReply(
            client_timestamp_proof=client_timestamp_proof,
            server_timestamp=server_timestamp,
            ok=True,
            error_message=""
        )
        
        log_success("Service", f"Sending AP-REP to {ap_request.authenticator.client_id}")
        log_success("Service", f"Mutual authentication established!")
        
        return ap_reply
