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
    realm: str = "HUST.EDU.VN"
    ticket_type: str = "ST"  # TGT hoặc ST (Service Ticket)
    nonce: str = ""  # Nonce để ghép nối request và reply
    
    def is_valid(self) -> bool:
        """Kiểm tra xem vé có còn hiệu lực không"""
        current_time = time.time()
        return current_time - self.timestamp <= self.lifetime
    
    def __repr__(self) -> str:
        return f"Ticket(client={self.client_id}, server={self.server_id}, type={self.ticket_type}, valid={self.is_valid()})"


@dataclass
class Authenticator:
    """Bộ xác thực (Authenticator) - Được mã hóa bằng Session Key"""
    client_id: str
    timestamp: float
    client_address: str = "127.0.0.1"
    encrypted_data: str = ""
    realm: str = "HUST.EDU.VN"
    
    def is_valid(self, max_clock_skew: int = 300) -> bool:
        """Kiểm tra Authenticator có còn hợp lệ không (mặc định 5 phút)"""
        current_time = time.time()
        return abs(current_time - self.timestamp) <= max_clock_skew
    
    def __repr__(self) -> str:
        return f"Authenticator(client={self.client_id}, timestamp={self.timestamp}, valid={self.is_valid()})"


@dataclass
class Principal:
    """Thực thể (Principal) - Người dùng hoặc dịch vụ
    
    Định dạng: primary/instance@realm
    - primary: Tên người dùng (vd: alice) hoặc tên dịch vụ (vd: HTTP, host)
    - instance: (Tùy chọn) Vai trò hoặc FQDN của máy chủ (vd: admin hoặc webserver.hust.edu.vn)
    - realm: Vùng quản trị Kerberos (vd: HUST.EDU.VN)
    """
    name: str  # primary
    realm: str = "HUST.EDU.VN"
    instance: str = ""  # instance (tùy chọn)
    
    @property
    def full_name(self) -> str:
        """Trả về đủ định dạng principal (primary/instance@realm)"""
        if self.instance:
            return f"{self.name}/{self.instance}@{self.realm}"
        return f"{self.name}@{self.realm}"
    
    def __repr__(self) -> str:
        return self.full_name


# ========== AS-REQ / AS-REP ==========

@dataclass
class ASRequest:
    """AS-REQ: Yêu cầu xác thực từ Client đến AS
    
    Bao gồm:
    - IDc: Định danh Client
    - IDtgs: Định danh máy chủ TGS mà Client muốn xin vé TGT
    - TS1: Dấu thời gian của Client
    - Lifetime1: Thời gian sống dự kiến của vé TGT
    - Nonce1: Số ngẫu nhiên để ghép nối request và reply
    """
    client_id: str  # IDc
    server_id: str  # IDtgs (TGS)
    timestamp: float  # TS1
    nonce: str  # Nonce1
    lifetime: int = 28800  # Lifetime1 (8 tiếng)


@dataclass
class ASReply:
    """AS-REP: Phản hồi từ AS về cho Client
    
    Gồm 2 phần:
    - Phần 1: Vé TGT (mã hóa bằng khóa của TGS)
      TGT = E_{K_tgs}[IDc || C_Address || IDtgs || TS2 || Lifetime2 || Kc,tgs]
    - Phần 2: Client_Portion (mã hóa bằng khóa bí mật của Client)
      Client_Portion = E_{K_c}[Kc,tgs || IDtgs || TS2 || Lifetime2 || Nonce1]
    """
    client_id: str
    tgt: Ticket  # Vé TGT (mã hóa)
    server_id: str  # IDtgs (TGS) - cho Client_Portion
    session_key_c_tgs: str  # Khóa phiên Kc,tgs
    server_timestamp: float  # TS2
    lifetime: int  # Lifetime2 - cho Client_Portion
    nonce: str  # Nonce1 (phản hồi)
    client_portion_encrypted: str = ""  # Client_Portion đã mã hóa
    ok: bool = True
    error_message: str = ""


# ========== TGS-REQ / TGS-REP ==========

@dataclass
class TGSRequest:
    """TGS-REQ: Yêu cầu cấp Service Ticket từ Client đến TGS
    
    Bao gồm:
    - IDv: Định danh của Service Server
    - TGT: Vé TGT từ bước 2
    - Authenticator_c: Authenticator mới (mã hóa bằng Kc,tgs)
    """
    client_id: str
    server_id: str  # IDv (Service Server)
    tgt: Ticket
    authenticator: Authenticator
    lifetime: int = 3600  # 1 tiếng


@dataclass
class TGSReply:
    """TGS-REP: Phản hồi từ TGS về cho Client
    
    Gồm 2 phần:
    - Phần 1: Service Ticket (mã hóa bằng khóa của Service Server)
    - Phần 2: Khóa phiên Kc,v (mã hóa bằng Kc,tgs)
    """
    client_id: str
    service_ticket: Ticket
    session_key_c_s: str  # Khóa phiên Kc,v
    server_timestamp: float  # TS4
    ok: bool = True
    error_message: str = ""


# ========== AP-REQ / AP-REP ==========

@dataclass
class APRequest:
    """AP-REQ: Yêu cầu ứng dụng từ Client đến Service Server
    
    Bao gồm:
    - ST: Vé dịch vụ (mã hóa bằng Kv)
    - Authenticator_c_v: Authenticator mới (mã hóa bằng Kc,v)
    """
    service_ticket: Ticket
    authenticator: Authenticator


@dataclass
class APReply:
    """AP-REP: Phản hồi từ Service Server về cho Client (Xác thực hai chiều - Mutual Authentication)
    
    Chứa Timestamp + 1 (mã hóa bằng Kc,v) để chứng minh Server là hợp pháp
    """
    client_timestamp_proof: float  # Timestamp + 1
    server_timestamp: float
    ok: bool = True
    error_message: str = ""
