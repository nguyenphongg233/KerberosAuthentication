"""
TGS Entity: Biểu diễn Ticket Granting Server
"""

from dataclasses import dataclass


@dataclass
class TicketGrantingServerEntity:
    """Entity đại diện cho Ticket Granting Server (TGS)
    
    Chức năng:
    - Xác minh TGT từ Client
    - Cấp Service Ticket và khóa phiên Kc,v
    - Là một phần logic của KDC
    
    Thuộc tính:
    - server_name: Tên TGS (thường là "krbtgt")
    - realm: Vùng Kerberos
    - master_key: Khóa bí mật của TGS (giống với khóa của AS vì cùng là KDC)
    - service_keys: Danh sách khóa bí mật của các dịch vụ được quản lý
    """
    server_name: str
    realm: str = "HUST.EDU.VN"
    master_key: str = ""  # Khóa bí mật của TGS
    server_address: str = "127.0.0.1"
    service_keys: dict = None  # {service_name: secret_key}
    
    def __post_init__(self):
        if self.service_keys is None:
            self.service_keys = {}
    
    def register_service(self, service_name: str, service_key: str):
        """Đăng ký một dịch vụ với khóa bí mật của nó"""
        self.service_keys[service_name] = service_key
    
    def get_service_key(self, service_name: str) -> str:
        """Lấy khóa bí mật của một dịch vụ"""
        return self.service_keys.get(service_name, "")
    
    def __repr__(self) -> str:
        return f"TicketGrantingServer(name={self.server_name}@{self.realm}, services={len(self.service_keys)})"
