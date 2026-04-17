"""
Service Server Entity: Biểu diễn Service Server (Mail Service)
"""

from dataclasses import dataclass


@dataclass
class ServiceServerEntity:
    """Entity đại diện cho Service Server"""
    service_name: str
    realm: str
    master_key: str = ""  # Khóa bí mật của Service
    
    def __repr__(self) -> str:
        return f"ServiceServer(name={self.service_name}, realm={self.realm})"
