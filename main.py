"""
Main: Mô phỏng quá trình xác thực Kerberos
Orchestrates the three-phase authentication process
"""

from KDC_database.database_entity import KDCDatabaseEntity
from KDC_database.database_engine import DatabaseEngine
from KDC_database.database_crypto import DatabaseCryptoEngine

from as_server.as_entity import AuthenticationServerEntity
from as_server.as_engine import ASEngine

from tgs_server.tgs_entity import TicketGrantingServerEntity
from tgs_server.tgs_engine import TGSEngine

from client.client_entity import KerberosClientEntity
from client.client_engine import ClientEngine

from service_server.service_entity import ServiceServerEntity
from service_server.service_engine import ServiceEngine

from utils import (
    log_info, log_success, log_error, log_debug,
    separator, section_header, get_current_timestamp,
    log_as_request_details, log_as_reply_details,
    log_tgs_request_details, log_tgs_reply_details,
    log_ap_request_details, log_ap_reply_details
)


def main():
    """Main function - Orchestrates Kerberos authentication"""
    
    section_header("KERBEROS AUTHENTICATION PROTOCOL SIMULATION", "=", 80)
    
    # ============= INITIALIZATION =============
    section_header("Phase 0: System Initialization", "-", 80)
    
    # Initialize Database
    db_entity = KDCDatabaseEntity(realm="HUST.EDU.VN")
    db_engine = DatabaseEngine(db_entity)
    db_engine.initialize_database()
    
    print("="*80)
    
    # Initialize AS Server
    as_entity = AuthenticationServerEntity(
        server_name="AS",
        realm="HUST.EDU.VN",
        master_key=DatabaseCryptoEngine.hash_password("TGS_SECRET_KEY"),
        server_address="192.168.1.10"
    )
    as_engine = ASEngine(as_entity, db_engine)
    log_success("System", f"Initialized: {as_entity}")
    
    print("="*80)
    
    # Initialize TGS Server
    tgs_entity = TicketGrantingServerEntity(
        server_name="krbtgt",
        realm="HUST.EDU.VN",
        master_key=DatabaseCryptoEngine.hash_password("TGS_SECRET_KEY"),
        server_address="192.168.1.10"
    )
    tgs_engine = TGSEngine(tgs_entity, db_engine)
    log_success("System", f"Initialized: {tgs_entity}")
    
    print("="*80)
    
    # Initialize Service Server
    service_entity = ServiceServerEntity(
        service_name="mail-service",
        realm="HUST.EDU.VN",
        master_key=DatabaseCryptoEngine.hash_password("MAIL_SERVICE_SECRET"),
        server_address="192.168.1.20",
        instance="mailserver.hust.edu.vn"
    )
    service_engine = ServiceEngine(service_entity)
    log_success("System", f"Initialized: {service_entity}")
    
    print("="*80)
    
    # Initialize Client (Alice)
    client_entity = KerberosClientEntity(
        client_id="alice",
        realm="HUST.EDU.VN",
        password="alice_password_123",
        client_address="192.168.1.100"
    )
    client_engine = ClientEngine(client_entity)
    log_success("System", f"Initialized: {client_entity}")
    
    print("="*80)
    
    # ============= PHASE 1: AS EXCHANGE =============
    section_header("Phase 1: AS Exchange (AS-REQ / AS-REP)", "-", 80)
    
    # Step 1: Client creates AS-REQ
    as_request = client_engine.create_as_request("krbtgt")
    log_info("Flow", f"[Client] → [AS] Sending AS-REQ")
    log_as_request_details(as_request)
    
    print("="*80)
    
    # Step 2: AS processes AS-REQ and creates AS-REP
    log_info("Flow", f"[AS] Processing AS-REQ from {as_request.client_id}")

    as_reply = as_engine.process_as_request(as_request, client_entity.password)
    
    print("="*80)
    
    # Step 3: Client processes AS-REP
    if not as_reply.ok:
        log_error("Client", f"AS authentication failed: {as_reply.error_message}")
        return
    
    log_info("Flow", f"[AS] → [Client] Sending AS-REP")
    log_as_reply_details(as_reply)
    
    print("="*80)
    
    if client_engine.process_as_reply(as_reply, as_request, client_entity.password):
        log_success("Flow", "✓ Phase 1 (AS Exchange) completed successfully!")
    else:
        log_error("Flow", "✗ Phase 1 failed!")
        return
    
    print("="*80)
    

    
    # ============= TEST: WRONG PASSWORD =============
    section_header("Test: Client nhập sai mật khẩu (Wrong Password)", "-", 80)
    
    # Tạo AS-REQ như bình thường
    wrong_as_request = client_engine.create_as_request("krbtgt")
    log_info("Flow", f"[Client] → [AS] Sending AS-REQ with WRONG password")
    log_as_request_details(wrong_as_request)
    
    print("="*80)
    
    # AS xử lý AS-REQ với mật khẩu SAI
    wrong_password = "WRONG_PASSWORD_XYZ"
    log_info("Flow", f"[AS] Processing AS-REQ with wrong password: {wrong_password}")
    
    wrong_as_reply = as_engine.process_as_request(wrong_as_request, wrong_password)
    
    print("="*80)
    
    # Client xử lý AS-REP
    if not wrong_as_reply.ok:
        log_error("Client", f"❌ Authentication FAILED: {wrong_as_reply.error_message}")
        log_info("Flow", "Client cannot proceed without valid authentication")
    else:
        log_success("Client", "This should not happen!")
    
    print("="*80)
    
if __name__ == "__main__":
    main()
