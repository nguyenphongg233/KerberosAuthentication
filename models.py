"""
Models: Các mô hình dữ liệu chung cho giao thức Kerberos
"""

from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class Ticket:
    """Vé xác thực (Ticket) - Được mã hóa bằng khóa bí mật của Server/TGS"""
    client_id: str
    server_id: str
    session_key: str
    timestamp: float
    lifetime: int  # Số giây khóa còn hiệu lực
    client_address: str = "127.0.0.1"
    encrypted_data: str = ""  # Dữ liệu đã mã hóa
    
    def is_valid(self) -> bool:
        """Kiểm tra xem vé có còn hiệu lực không"""
        current_time = time.time()
        return current_time - self.timestamp <= self.lifetime
    
    def __repr__(self) -> str:
        return f"Ticket(client={self.client_id}, server={self.server_id}, valid={self.is_valid()})"


@dataclass
class Authenticator:
    """Bộ xác thực (Authenticator) - Được mã hóa bằng Session Key"""
    client_id: str
    timestamp: float
    client_address: str = "127.0.0.1"
    encrypted_data: str = ""
    
    def is_valid(self, max_clock_skew: int = 300) -> bool:
        """Kiểm tra Authenticator có còn hợp lệ không (mặc định 5 phút)"""
        current_time = time.time()
        return abs(current_time - self.timestamp) <= max_clock_skew
    
    def __repr__(self) -> str:
        return f"Authenticator(client={self.client_id}, timestamp={self.timestamp}, valid={self.is_valid()})"


@dataclass
class Principal:
    """Thực thể (Principal) - Người dùng hoặc dịch vụ"""
    name: str
    realm: str = "HUST.EDU.VN"
    
    @property
    def full_name(self) -> str:
        return f"{self.name}@{self.realm}"
    
    def __repr__(self) -> str:
        return self.full_name


# ========== AS-REQ / AS-REP ==========

@dataclass
class ASRequest:
    """AS-REQ: Yêu cầu xác thực từ Client đến AS"""
    client_id: str
    server_id: str  # TGS
    timestamp: float
    nonce: str
    lifetime: int = 28800  # 8 tiếng


@dataclass
class ASReply:
    """AS-REP: Phản hồi từ AS về cho Client"""
    client_id: str
    tgt: Ticket
    session_key_c_tgs: str
    server_timestamp: float
    nonce: str
    ok: bool = True
    error_message: str = ""


# ========== TGS-REQ / TGS-REP ==========

@dataclass
class TGSRequest:
    """TGS-REQ: Yêu cầu cấp Service Ticket từ Client đến TGS"""
    client_id: str
    server_id: str  # Service Server
    tgt: Ticket
    authenticator: Authenticator
    lifetime: int = 3600  # 1 tiếng


@dataclass
class TGSReply:
    """TGS-REP: Phản hồi từ TGS về cho Client"""
    client_id: str
    service_ticket: Ticket
    session_key_c_s: str
    server_timestamp: float
    ok: bool = True
    error_message: str = ""


# ========== AP-REQ / AP-REP ==========

@dataclass
class APRequest:
    """AP-REQ: Yêu cầu ứng dụng từ Client đến Service Server"""
    service_ticket: Ticket
    authenticator: Authenticator


@dataclass
class APReply:
    """AP-REP: Phản hồi từ Service Server về cho Client (Mutual Auth)"""
    client_timestamp_proof: float  # Timestamp + 1
    server_timestamp: float
    ok: bool = True
    error_message: str = ""
