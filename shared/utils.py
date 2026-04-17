"""
Shared Utils: Các hàm tiện ích chung
"""

import time
import random
import string


def get_current_timestamp() -> float:
    """Lấy dấu thời gian hiện tại (Unix timestamp)"""
    return time.time()


def generate_nonce(length: int = 16) -> str:
    """Sinh ra một số ngẫu nhiên dùng một lần"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_session_key(length: int = 32) -> str:
    """Sinh ra một khóa phiên ngẫu nhiên"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def format_log(entity: str, level: str, message: str) -> str:
    """Format thông báo log
    
    Args:
        entity: Tên thực thể (Client, AS, TGS, ServiceServer, Database)
        level: Mức log (INFO, SUCCESS, ERROR, DEBUG)
        message: Nội dung thông báo
    """
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    
    # Màu sắc
    colors = {
        "INFO": "\033[94m",    # Blue
        "SUCCESS": "\033[92m",  # Green
        "ERROR": "\033[91m",    # Red
        "DEBUG": "\033[93m",    # Yellow
        "RESET": "\033[0m"      # Reset
    }
    
    color = colors.get(level, colors["INFO"])
    reset = colors["RESET"]
    
    return f"{color}[{timestamp}] [{entity:15}] {level:7}: {message}{reset}"


def log_info(entity: str, message: str):
    """In log INFO"""
    print(format_log(entity, "INFO", message))


def log_success(entity: str, message: str):
    """In log SUCCESS"""
    print(format_log(entity, "SUCCESS", message))


def log_error(entity: str, message: str):
    """In log ERROR"""
    print(format_log(entity, "ERROR", message))


def log_debug(entity: str, message: str):
    """In log DEBUG"""
    print(format_log(entity, "DEBUG", message))


def separator(char: str = "=", length: int = 80):
    """In một dòng phân cách"""
    print(char * length)


def section_header(title: str, char: str = "=", length: int = 80):
    """In tiêu đề phần"""
    separator(char, length)
    padding = (length - len(title) - 4) // 2
    print(f"{char * padding}  {title}  {char * padding}")
    separator(char, length)
