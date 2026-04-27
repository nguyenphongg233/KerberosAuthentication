"""
AS Entity: Biểu diễn Authentication Server
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class AuthenticationServerEntity:
    """Entity đại diện cho Authentication Server (AS)
    
    Chức năng:
    - Xác thực người dùng dựa trên mật khẩu
    - Cấp vé TGT và khóa phiên Kc,tgs
    - Là một phần logic của KDC
    
    Thuộc tính:
    - server_name: Tên AS (thường là "krbtgt")
    - realm: Vùng Kerberos
    - master_key: Khóa bí mật của AS (được lưu trữ trong KDC)
    """
    server_name: str
    realm: str = "HUST.EDU.VN"
    master_key: str = ""  # Khóa bí mật của AS (Ktgs)
    server_address: str = "127.0.0.1"
    
    def __repr__(self) -> str:
        return f"AuthenticationServer(name={self.server_name}@{self.realm})"
