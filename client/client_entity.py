"""
Client Entity: Biểu diễn Client (Alice)
"""

from dataclasses import dataclass, field
from typing import Optional
from models import Ticket, Authenticator


@dataclass
class KerberosClientEntity:
    """Entity đại diện cho Kerberos Client (Alice)"""
    client_id: str
    realm: str
    password: str
    
    # Vé và khóa được lưu trong RAM của Client
    tgt: Optional[Ticket] = None
    session_key_c_tgs: str = ""
    service_ticket: Optional[Ticket] = None
    session_key_c_s: str = ""
    
    def __repr__(self) -> str:
        return f"KerberosClient(id={self.client_id}, realm={self.realm})"
