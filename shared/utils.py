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


# ========== Chi tiết Request/Reply Log ==========

def log_as_request_details(as_request):
    """Log chi tiết AS-REQ"""
    log_debug("→ AS-REQ", f"client_id={as_request.client_id}")
    log_debug("→ AS-REQ", f"server_id={as_request.server_id}")
    log_debug("→ AS-REQ", f"timestamp={as_request.timestamp:.2f}")
    log_debug("→ AS-REQ", f"nonce={as_request.nonce[:12]}...")
    log_debug("→ AS-REQ", f"lifetime={as_request.lifetime}s")


def log_as_reply_details(as_reply):
    """Log chi tiết AS-REP"""
    if as_reply.ok:
        log_debug("← AS-REP", f"client_id={as_reply.client_id}")
        log_debug("← AS-REP", f"TGT=Ticket(type=TGT, client={as_reply.tgt.client_id}, lifetime={as_reply.tgt.lifetime}s)")
        log_debug("← AS-REP", f"session_key_c_tgs={as_reply.session_key_c_tgs[:16]}...")
        log_debug("← AS-REP", f"server_timestamp={as_reply.server_timestamp:.2f}")
    else:
        log_error("← AS-REP", f"ERROR: {as_reply.error_message}")


def log_tgs_request_details(tgs_request):
    """Log chi tiết TGS-REQ"""
    log_debug("→ TGS-REQ", f"client_id={tgs_request.client_id}")
    log_debug("→ TGS-REQ", f"server_id={tgs_request.server_id}")
    log_debug("→ TGS-REQ", f"TGT=Ticket(type={tgs_request.tgt.ticket_type}, lifetime={tgs_request.tgt.lifetime}s)")
    log_debug("→ TGS-REQ", f"Authenticator(client_id={tgs_request.authenticator.client_id}, timestamp={tgs_request.authenticator.timestamp:.2f})")
    log_debug("→ TGS-REQ", f"lifetime={tgs_request.lifetime}s")


def log_tgs_reply_details(tgs_reply):
    """Log chi tiết TGS-REP"""
    if tgs_reply.ok:
        log_debug("← TGS-REP", f"client_id={tgs_reply.client_id}")
        log_debug("← TGS-REP", f"Service Ticket=Ticket(type=ST, server={tgs_reply.service_ticket.server_id}, lifetime={tgs_reply.service_ticket.lifetime}s)")
        log_debug("← TGS-REP", f"session_key_c_s={tgs_reply.session_key_c_s[:16]}...")
        log_debug("← TGS-REP", f"server_timestamp={tgs_reply.server_timestamp:.2f}")
    else:
        log_error("← TGS-REP", f"ERROR: {tgs_reply.error_message}")


def log_ap_request_details(ap_request):
    """Log chi tiết AP-REQ"""
    log_debug("→ AP-REQ", f"Service Ticket=Ticket(type={ap_request.service_ticket.ticket_type}, client={ap_request.service_ticket.client_id})")
    log_debug("→ AP-REQ", f"Authenticator(client_id={ap_request.authenticator.client_id}, timestamp={ap_request.authenticator.timestamp:.2f})")


def log_ap_reply_details(ap_reply):
    """Log chi tiết AP-REP"""
    if ap_reply.ok:
        log_debug("← AP-REP", f"client_timestamp_proof={ap_reply.client_timestamp_proof:.2f} (Timestamp + 1 = Mutual Auth)")
        log_debug("← AP-REP", f"server_timestamp={ap_reply.server_timestamp:.2f}")
    else:
        log_error("← AP-REP", f"ERROR: {ap_reply.error_message}")
