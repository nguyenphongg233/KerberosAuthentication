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
    separator, section_header, get_current_timestamp
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
    
    separator()
    
    # Initialize AS Server
    as_entity = AuthenticationServerEntity(
        server_name="AS",
        realm="HUST.EDU.VN",
        master_key=DatabaseCryptoEngine.hash_password("TGS_SECRET_KEY")
    )
    as_engine = ASEngine(as_entity, db_engine)
    log_success("System", f"Initialized: {as_entity}")
    
    separator()
    
    # Initialize TGS Server
    tgs_entity = TicketGrantingServerEntity(
        server_name="krbtgt",
        realm="HUST.EDU.VN",
        master_key=DatabaseCryptoEngine.hash_password("TGS_SECRET_KEY")
    )
    tgs_engine = TGSEngine(tgs_entity, db_engine)
    log_success("System", f"Initialized: {tgs_entity}")
    
    separator()
    
    # Initialize Service Server
    service_entity = ServiceServerEntity(
        service_name="mail-service",
        realm="HUST.EDU.VN",
        master_key=DatabaseCryptoEngine.hash_password("MAIL_SERVICE_SECRET")
    )
    service_engine = ServiceEngine(service_entity)
    log_success("System", f"Initialized: {service_entity}")
    
    separator()
    
    # Initialize Client (Alice)
    client_entity = KerberosClientEntity(
        client_id="alice",
        realm="HUST.EDU.VN",
        password="alice_password_123"
    )
    client_engine = ClientEngine(client_entity)
    log_success("System", f"Initialized: {client_entity}")
    
    separator("\n")
    
    # ============= PHASE 1: AS EXCHANGE =============
    section_header("Phase 1: AS Exchange (AS-REQ / AS-REP)", "-", 80)
    
    # Step 1: Client creates AS-REQ
    as_request = client_engine.create_as_request("krbtgt")
    log_info("Flow", f"Client sends AS-REQ to AS")
    log_debug("AS", f"Received: client={as_request.client_id}, nonce={as_request.nonce[:8]}...")
    
    separator()
    
    # Step 2: AS processes AS-REQ and creates AS-REP
    client_master_key = DatabaseCryptoEngine.hash_password(client_entity.password)
    as_reply = as_engine.process_as_request(as_request, client_entity.password)
    
    separator()
    
    # Step 3: Client processes AS-REP
    if not as_reply.ok:
        log_error("Client", f"AS authentication failed: {as_reply.error_message}")
        return
    
    log_info("Flow", f"AS sends AS-REP to Client")
    if client_engine.process_as_reply(as_reply, client_master_key):
        log_success("Flow", "Phase 1 completed successfully!")
    else:
        log_error("Flow", "Phase 1 failed!")
        return
    
    separator("\n")
    
    # ============= PHASE 2: TGS EXCHANGE =============
    section_header("Phase 2: TGS Exchange (TGS-REQ / TGS-REP)", "-", 80)
    
    # Step 3: Client creates TGS-REQ
    tgs_request = client_engine.create_tgs_request("mail-service")
    log_info("Flow", f"Client sends TGS-REQ to TGS")
    log_debug("TGS", f"Received: client={tgs_request.client_id}, service={tgs_request.server_id}")
    
    separator()
    
    # Step 4: TGS processes TGS-REQ and creates TGS-REP
    tgs_reply = tgs_engine.process_tgs_request(tgs_request, as_reply.session_key_c_tgs)
    
    separator()
    
    # Step 4: Client processes TGS-REP
    if not tgs_reply.ok:
        log_error("Client", f"TGS request failed: {tgs_reply.error_message}")
        return
    
    log_info("Flow", f"TGS sends TGS-REP to Client")
    if client_engine.process_tgs_reply(tgs_reply):
        log_success("Flow", "Phase 2 completed successfully!")
    else:
        log_error("Flow", "Phase 2 failed!")
        return
    
    separator("\n")
    
    # ============= PHASE 3: APPLICATION EXCHANGE =============
    section_header("Phase 3: Application Exchange (AP-REQ / AP-REP)", "-", 80)
    
    # Step 5: Client creates AP-REQ
    ap_request = client_engine.create_ap_request()
    log_info("Flow", f"Client sends AP-REQ to Service Server")
    log_debug("Service", f"Received: from {ap_request.authenticator.client_id}")
    
    separator()
    
    # Step 6: Service Server processes AP-REQ and creates AP-REP
    original_timestamp = ap_request.authenticator.timestamp
    ap_reply = service_engine.process_ap_request(ap_request, tgs_reply.session_key_c_s)
    
    separator()
    
    # Step 6: Client processes AP-REP (Mutual Authentication)
    if not ap_reply.ok:
        log_error("Client", f"Service authentication failed: {ap_reply.error_message}")
        return
    
    log_info("Flow", f"Service sends AP-REP to Client")
    if client_engine.process_ap_reply(ap_reply, original_timestamp):
        log_success("Flow", "Phase 3 completed successfully!")
    else:
        log_error("Flow", "Phase 3 failed!")
        return
    
    separator("\n")
    
    # ============= SUMMARY =============
    section_header("AUTHENTICATION PROCESS COMPLETED", "=", 80)
    log_success("System", "Kerberos authentication workflow successful!")
    log_success("System", f"Client {client_entity.client_id} can now access {service_entity.service_name}")
    separator()


if __name__ == "__main__":
    main()
