"""
Main: Mô phỏng quá trình xác thực Kerberos
Orchestrates the three-phase authentication process
"""

from database.database_entity import KDCDatabaseEntity
from database.database_engine import DatabaseEngine
from database.database_crypto import DatabaseCryptoEngine

from as_server.as_entity import AuthenticationServerEntity
from as_server.as_engine import ASEngine

from tgs_server.tgs_entity import TicketGrantingServerEntity
from tgs_server.tgs_engine import TGSEngine

from client.client_entity import KerberosClientEntity
from client.client_engine import ClientEngine

from service_server.service_entity import ServiceServerEntity
from service_server.service_engine import ServiceEngine

from shared.utils import (
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
    client_master_key = DatabaseCryptoEngine.hash_password(client_entity.password)
    as_reply = as_engine.process_as_request(as_request, client_entity.password)
    
    print("="*80)
    
    # Step 3: Client processes AS-REP
    if not as_reply.ok:
        log_error("Client", f"AS authentication failed: {as_reply.error_message}")
        return
    
    log_info("Flow", f"[AS] → [Client] Sending AS-REP")
    log_as_reply_details(as_reply)
    
    print("="*80)
    
    if client_engine.process_as_reply(as_reply, client_master_key):
        log_success("Flow", "✓ Phase 1 (AS Exchange) completed successfully!")
    else:
        log_error("Flow", "✗ Phase 1 failed!")
        return
    
    print("="*80)
    
    # ============= PHASE 2: TGS EXCHANGE =============
    section_header("Phase 2: TGS Exchange (TGS-REQ / TGS-REP)", "-", 80)
    
    # Step 3: Client creates TGS-REQ
    tgs_request = client_engine.create_tgs_request("mail-service")
    log_info("Flow", f"[Client] → [TGS] Sending TGS-REQ")
    log_tgs_request_details(tgs_request)
    
    print("="*80)
    
    # Step 4: TGS processes TGS-REQ and creates TGS-REP
    log_info("Flow", f"[TGS] Processing TGS-REQ from {tgs_request.client_id}")
    tgs_reply = tgs_engine.process_tgs_request(tgs_request, as_reply.session_key_c_tgs)
    
    print("="*80)
    
    # Step 4: Client processes TGS-REP
    if not tgs_reply.ok:
        log_error("Client", f"TGS request failed: {tgs_reply.error_message}")
        return
    
    log_info("Flow", f"[TGS] → [Client] Sending TGS-REP")
    log_tgs_reply_details(tgs_reply)
    
    print("="*80)
    
    if client_engine.process_tgs_reply(tgs_reply):
        log_success("Flow", "✓ Phase 2 (TGS Exchange) completed successfully!")
    else:
        log_error("Flow", "✗ Phase 2 failed!")
        return
    
    print("="*80)
    
    # ============= PHASE 3: APPLICATION EXCHANGE =============
    section_header("Phase 3: Application Exchange (AP-REQ / AP-REP)", "-", 80)
    
    # Step 5: Client creates AP-REQ
    ap_request = client_engine.create_ap_request()
    log_info("Flow", f"[Client] → [Service] Sending AP-REQ")
    log_ap_request_details(ap_request)
    
    print("="*80)
    
    # Step 6: Service Server processes AP-REQ and creates AP-REP
    log_info("Flow", f"[Service] Processing AP-REQ from {ap_request.authenticator.client_id}")
    original_timestamp = ap_request.authenticator.timestamp
    ap_reply = service_engine.process_ap_request(ap_request, tgs_reply.session_key_c_s)
    
    print("="*80)
    
    # Step 6: Client processes AP-REP (Mutual Authentication)
    if not ap_reply.ok:
        log_error("Client", f"AP authentication failed: {ap_reply.error_message}")
        return
    
    log_info("Flow", f"[Service] → [Client] Sending AP-REP (Mutual Authentication)")
    log_ap_reply_details(ap_reply)
    
    print("="*80)
    
    if client_engine.process_ap_reply(ap_reply, original_timestamp):
        log_success("Flow", "✓ Phase 3 (Application Exchange) completed successfully!")
    else:
        log_error("Flow", "✗ Phase 3 failed!")
        return
    
    print("="*80)
    
    # ============= SUMMARY =============
    section_header("AUTHENTICATION PROCESS COMPLETED", "=", 80)
    log_success("System", "✓ Kerberos authentication workflow successful!")
    log_success("System", f"✓ Client {client_entity.client_id} can now access {service_entity.service_name}")
    print("="*80)


if __name__ == "__main__":
    main()
