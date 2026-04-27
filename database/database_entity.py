"""
Database Entity: Biểu diễn cơ sở dữ liệu KDC
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Principal:
    """Biểu diễn một Principal (User hoặc Service) trong KDC Database
    
    Định dạng: primary/instance@realm
    - primary: Tên người dùng (vd: alice) hoặc tên dịch vụ (vd: HTTP, krbtgt)
    - instance: (Tùy chọn) Vai trò hoặc FQDN (vd: admin, webserver.hust.edu.vn)
    - realm: Vùng quản trị Kerberos
    
    Thuộc tính:
    - name: primary
    - realm: vùng Kerberos
    - instance: instance (tùy chọn)
    - password_hash: Hash mật khẩu (cho User)
    - master_key: Khóa bí mật dài hạn (cho Service)
    """
    name: str  # primary
    realm: str
    instance: str = ""  # instance (tùy chọn)
    password_hash: str = ""  # Cho User
    master_key: str = ""     # Cho Service
    principal_type: str = "user"  # "user" hoặc "service"
    
    @property
    def full_name(self) -> str:
        """Trả về đủ định dạng principal (primary/instance@realm)"""
        if self.instance:
            return f"{self.name}/{self.instance}@{self.realm}"
        return f"{self.name}@{self.realm}"
    
    def __repr__(self) -> str:
        return self.full_name


@dataclass
class KDCDatabaseEntity:
    """Entity đại diện cho KDC Database
    
    Lưu trữ:
    - Danh sách tất cả Principal (Users và Services)
    - Khóa bí mật dài hạn của từng Principal
    - Thông tin Realm
    """
    realm: str = "HUST.EDU.VN"
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
    
    def get_principals_by_type(self, principal_type: str) -> Dict[str, Principal]:
        """Lấy tất cả Principal của một loại (user hoặc service)"""
        return {k: v for k, v in self.principals.items() if v.principal_type == principal_type}
    
    def __repr__(self) -> str:
        users = sum(1 for p in self.principals.values() if p.principal_type == "user")
        services = sum(1 for p in self.principals.values() if p.principal_type == "service")
        return f"KDCDatabase(realm={self.realm}, users={users}, services={services})"
