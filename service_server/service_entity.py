"""
Service Server Entity: Biểu diễn Service Server (Mail Service, HTTP Server, ...)
"""

from dataclasses import dataclass


@dataclass
class ServiceServerEntity:
    """Entity đại diện cho Service Server
    
    Chức năng:
    - Nhận Service Ticket từ Client
    - Xác minh Authenticator
    - Cấp quyền truy cập và phản hồi Mutual Authentication
    
    Thuộc tính:
    - service_name: Tên dịch vụ (vd: "mail-service", "HTTP", "host")
    - realm: Vùng Kerberos
    - master_key: Khóa bí mật được chia sẻ với KDC
    - server_address: Địa chỉ IP của máy chủ
    - instance: (Tùy chọn) FQDN hoặc tên máy chủ (vd: webserver.hust.edu.vn)
    """
    service_name: str
    realm: str = "HUST.EDU.VN"
    master_key: str = ""  # Khóa bí mật của Service (Kv)
    server_address: str = "127.0.0.1"
    instance: str = ""  # FQDN hoặc tên máy chủ (tùy chọn)
    
    @property
    def full_name(self) -> str:
        """Trả về đủ định dạng service (service_name/instance@realm)"""
        if self.instance:
            return f"{self.service_name}/{self.instance}@{self.realm}"
        return f"{self.service_name}@{self.realm}"
    
    def __repr__(self) -> str:
        return f"ServiceServer(name={self.full_name})"
