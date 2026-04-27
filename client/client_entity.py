"""
Client Entity: Biểu diễn Client (Alice)
"""

from dataclasses import dataclass, field
from typing import Optional
from models import Ticket, Authenticator


@dataclass
class KerberosClientEntity:
    """Entity đại diện cho Kerberos Client (Alice)
    
    Lưu trữ:
    - Định danh Client
    - Vé TGT và khóa phiên Kc,tgs (từ pha AS Exchange)
    - Service Ticket và khóa phiên Kc,v (từ pha TGS Exchange)
    """
    client_id: str
    realm: str = "HUST.EDU.VN"
    password: str = ""
    client_address: str = "127.0.0.1"
    
    # Vé và khóa được lưu trong RAM của Client
    tgt: Optional[Ticket] = None
    session_key_c_tgs: Optional[str] = None
    service_ticket: Optional[Ticket] = None
    session_key_c_s: Optional[str] = None
    
    # Thông tin caches
    tgs_id: Optional[str] = "krbtgt"  # Định danh TGS (mặc định)
    last_as_nonce: Optional[str] = None  # Nonce từ AS-REQ (để xác minh AS-REP)
    
    def __repr__(self) -> str:
        tgt_status = "has_TGT" if self.tgt else "no_TGT"
        st_status = "has_ST" if self.service_ticket else "no_ST"
        return f"KerberosClient(id={self.client_id}@{self.realm}, {tgt_status}, {st_status})"
