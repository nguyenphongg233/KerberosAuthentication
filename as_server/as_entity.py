"""
AS Entity: Biểu diễn Authentication Server
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class AuthenticationServerEntity:
    """Entity đại diện cho Authentication Server (AS)"""
    server_name: str
    realm: str
    master_key: str = ""  # Khóa bí mật của AS (TGS key)
    
    def __repr__(self) -> str:
        return f"AuthenticationServer(name={self.server_name}, realm={self.realm})"
