"""
Database Entity: Biểu diễn cơ sở dữ liệu KDC
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Principal:
    """Biểu diễn một Principal (User hoặc Service)"""
    name: str
    realm: str
    password_hash: str = ""  # Cho User
    master_key: str = ""     # Cho Service
    
    @property
    def full_name(self) -> str:
        return f"{self.name}@{self.realm}"
    
    def __repr__(self) -> str:
        return self.full_name


@dataclass
class KDCDatabaseEntity:
    """Entity đại diện cho KDC Database"""
    realm: str
    principals: Dict[str, Principal] = field(default_factory=dict)
    
    def add_principal(self, principal: Principal):
        """Thêm một Principal vào database"""
        self.principals[principal.full_name] = principal
    
    def get_principal(self, principal_name: str) -> Optional[Principal]:
        """Lấy thông tin Principal"""
        return self.principals.get(principal_name)
    
    def principal_exists(self, principal_name: str) -> bool:
        """Kiểm tra Principal có tồn tại không"""
        return principal_name in self.principals
    
    def get_all_principals(self) -> Dict[str, Principal]:
        """Lấy tất cả Principal"""
        return self.principals.copy()
    
    def __repr__(self) -> str:
        return f"KDCDatabase(realm={self.realm}, principals={len(self.principals)})"
