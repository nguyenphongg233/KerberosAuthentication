"""
TGS Entity: Biểu diễn Ticket Granting Server
"""

from dataclasses import dataclass


@dataclass
class TicketGrantingServerEntity:
    """Entity đại diện cho Ticket Granting Server (TGS)"""
    server_name: str
    realm: str
    master_key: str = ""  # Khóa bí mật của TGS
    
    def __repr__(self) -> str:
        return f"TicketGrantingServer(name={self.server_name}, realm={self.realm})"
