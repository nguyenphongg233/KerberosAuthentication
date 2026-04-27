"""
Service Server Engine: Logic xử lý của Service Server
"""

import time
from models import APRequest, APReply
from service_server.service_entity import ServiceServerEntity
from service_server.service_crypto import ServiceCryptoEngine
from utils import log_info, log_success, log_error, log_debug


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
        
        return None
