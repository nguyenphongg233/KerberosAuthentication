"""
Client Engine: Logic xử lý của Client (Alice)
"""

import time
from models import (
    ASRequest, Authenticator, TGSRequest, TGSReply, APRequest, APReply,
    Ticket
)
from client.client_entity import KerberosClientEntity
from client.client_crypto import ClientCryptoEngine
from utils import (
    log_info, log_success, log_error, log_debug, 
    generate_nonce, get_current_timestamp
)


class ClientEngine:
    """Engine xử lý logic của Client"""
    
    def __init__(self, client_entity: KerberosClientEntity):
        self.client_entity = client_entity
        self.crypto = ClientCryptoEngine()
    
    def create_as_request(self, tgs_name: str) -> ASRequest:
        """Tạo AS-REQ để xin TGT
        
        Args:
            tgs_name: Tên của TGS (e.g., "krbtgt")
        
        Returns:
            AS-REQ message
        """
        log_info("Client", "Creating AS-REQ...")
        
        as_request = ASRequest(
            client_id=self.client_entity.client_id,
            server_id=tgs_name,
            timestamp=get_current_timestamp(),
            nonce=generate_nonce(),
            lifetime=28800,  # 8 tiếng
            client_address=self.client_entity.client_address
        )
        
        # Lưu nonce để xác minh AS-REP sau này
        self.client_entity.last_as_nonce = as_request.nonce
        
        log_success("Client", f"AS-REQ created with nonce: {as_request.nonce[:8]}...")
        return as_request
    
    def process_as_reply(self, as_reply, as_request: ASRequest, password: str = None) -> bool:
        """Xử lý AS-REP từ AS - Bước 2 của pha AS Exchange
        
        Theo giao thức Kerberos, AS-REP chứa 2 phần:
        - Phần 1: TGT (mã hóa bằng khóa của TGS) - Client không thể đọc được
        - Phần 2: Client_Portion (mã hóa bằng khóa bí mật của Client)
                   chứa: K_c,tgs || IDtgs || TS2 || Lifetime2 || Nonce1
        
        Args:
            as_reply: AS-REP message từ AS
            as_request: AS-REQ message gốc (để lấy nonce)
            password: Mật khẩu của Client (nếu None, sẽ hỏi người dùng)
        
        Returns:
            True nếu thành công, False nếu thất bại
        """
        log_info("Client", "Processing AS-REP - Pha 1 bước 2 (AS Exchange Reply)...")
        
        if not as_reply.ok:
            log_error("Client", f"AS-REP error: {as_reply.error_message}")
            return False
        
        # BƯỚC 1: Yêu cầu người dùng nhập mật khẩu nếu chưa có
        if password is None:
            # Nếu không có mật khẩu từ tham số, hỏi người dùng
            if self.client_entity.password:
                password = self.client_entity.password
            else:
                password = input(f"[Client] Nhập mật khẩu cho {self.client_entity.client_id}: ")
                if not password:
                    log_error("Client", "Password is required to decrypt AS-REP")
                    return False
        
        # BƯỚC 2: Tính toán khóa bí mật của Client (Kc) bằng hash mật khẩu
        # Kc = hash(password)
        client_key_kc = self.crypto.hash_password(password)
        log_debug("Client", f"Derived client key Kc from password")
        
        # BƯỚC 3: Giải mã phần Client_Portion bằng khóa Kc
        # Client_Portion = E_Kc[K_c,tgs || IDtgs || TS2 || Lifetime2 || Nonce1]
        if not as_reply.client_portion_encrypted:
            log_error("Client", "No client portion found in AS-REP")
            return False
        
        client_portion_dict = self.crypto.decrypt_dict(
            as_reply.client_portion_encrypted, 
            client_key_kc
        )
        
        if not client_portion_dict:
            log_error("Client", "Failed to decrypt client portion - wrong password?")
            return False
        
        log_debug("Client", f"Successfully decrypted client portion")
        
        # BƯỚC 4: Trích xuất dữ liệu từ Client_Portion
        try:
            session_key = client_portion_dict.get("session_key")
            server_id = client_portion_dict.get("server_id")
            timestamp = client_portion_dict.get("timestamp")
            lifetime = client_portion_dict.get("lifetime")
            nonce_reply = client_portion_dict.get("nonce")
            
            if not all([session_key, server_id, timestamp, lifetime, nonce_reply]):
                log_error("Client", "Missing required fields in client portion")
                return False
            
            # BƯỚC 5: Xác minh Nonce để chống Replay Attack
            # Nonce từ AS-REP phải trùng với Nonce từ AS-REQ
            if nonce_reply != as_request.nonce:
                log_error("Client", f"Nonce mismatch! Expected {as_request.nonce[:8]}..., got {nonce_reply[:8]}...")
                log_error("Client", "This could be a Replay Attack!")
                return False
            
            log_debug("Client", f"Nonce verification SUCCESS: {nonce_reply[:8]}...")
            
            # BƯỚC 6: Lưu TGT (từ phần 1 của AS-REP, đã được AS server mã hóa) 
            # và Session Key vào RAM của Client
            self.client_entity.tgt = as_reply.tgt
            self.client_entity.session_key_c_tgs = session_key
            self.client_entity.tgs_id = server_id
            
            log_success("Client", f"AS-REP processed successfully!")
            log_success("Client", f"Received TGT (valid for {lifetime}s) and K_c,tgs")
            log_debug("Client", f"AS-REP:"
                      f"\n  - TGT decrypted with K_tgs (stored encrypted in RAM)\n"
                      f"  - K_c,tgs: {session_key[:16]}...\n"
                      f"  - Server: {server_id}\n"
                      f"  - Lifetime: {lifetime}s\n"
                      f"  - Nonce verified: {nonce_reply[:8]}...")
            
            return True
            
        except Exception as e:
            log_error("Client", f"Error processing AS-REP: {str(e)}")
            return False

    def create_tgs_request(self, service_name: str) -> TGSRequest:
        """Create TGS-REQ to request a Service Ticket.

        The authenticator is encrypted with K_c,tgs, while the TGT stays opaque
        to the client and is forwarded as received from AS.
        """
        log_info("Client", f"Creating TGS-REQ for service: {service_name}...")

        if not self.client_entity.tgt:
            log_error("Client", "Cannot create TGS-REQ: missing TGT")
            return None

        if not self.client_entity.session_key_c_tgs:
            log_error("Client", "Cannot create TGS-REQ: missing K_c,tgs")
            return None

        authenticator = Authenticator(
            client_id=self.client_entity.client_id,
            timestamp=get_current_timestamp(),
            client_address=self.client_entity.client_address,
            realm=self.client_entity.realm
        )
        authenticator_data = {
            "client_id": authenticator.client_id,
            "timestamp": authenticator.timestamp,
            "client_address": authenticator.client_address,
            "realm": authenticator.realm
        }
        authenticator.encrypted_data = self.crypto.encrypt_dict(
            authenticator_data,
            self.client_entity.session_key_c_tgs
        )

        tgs_request = TGSRequest(
            client_id=self.client_entity.client_id,
            server_id=service_name,
            tgt=self.client_entity.tgt,
            authenticator=authenticator,
            nonce=generate_nonce(),
            lifetime=3600
        )

        log_success("Client", f"TGS-REQ created for service: {service_name}")
        return tgs_request

    def process_tgs_reply(self, tgs_reply: TGSReply, tgs_request: TGSRequest) -> bool:
        """Process TGS-REP and store Service Ticket plus K_c,s in client RAM."""
        log_info("Client", "Processing TGS-REP - Phase 2 step 4 (TGS Exchange Reply)...")

        if not tgs_reply.ok:
            log_error("Client", f"TGS-REP error: {tgs_reply.error_message}")
            return False

        if not self.client_entity.session_key_c_tgs:
            log_error("Client", "Cannot process TGS-REP: missing K_c,tgs")
            return False

        if not tgs_reply.client_portion_encrypted:
            log_error("Client", "No client portion found in TGS-REP")
            return False

        client_portion_dict = self.crypto.decrypt_dict(
            tgs_reply.client_portion_encrypted,
            self.client_entity.session_key_c_tgs
        )
        if not client_portion_dict:
            log_error("Client", "Failed to decrypt TGS client portion")
            return False

        try:
            session_key = client_portion_dict.get("session_key")
            server_id = client_portion_dict.get("server_id")
            timestamp = client_portion_dict.get("timestamp")
            lifetime = client_portion_dict.get("lifetime")
            nonce_reply = client_portion_dict.get("nonce")

            if not all([session_key, server_id, timestamp, lifetime, nonce_reply]):
                log_error("Client", "Missing required fields in TGS client portion")
                return False

            if nonce_reply != tgs_request.nonce:
                log_error("Client", "TGS-REP nonce does not match TGS-REQ")
                return False

            if server_id != tgs_request.server_id:
                log_error("Client", f"Service mismatch! Expected {tgs_request.server_id}, got {server_id}")
                return False

            if tgs_reply.client_id != self.client_entity.client_id:
                log_error("Client", "TGS-REP client does not match current client")
                return False

            if not tgs_reply.service_ticket or tgs_reply.service_ticket.server_id != server_id:
                log_error("Client", "Invalid Service Ticket in TGS-REP")
                return False

            self.client_entity.service_ticket = tgs_reply.service_ticket
            self.client_entity.session_key_c_s = session_key

            log_success("Client", "TGS-REP processed successfully!")
            log_success("Client", f"Received Service Ticket for {server_id} and K_c,s")
            log_debug("Client", f"TGS-REP:"
                      f"\n  - Service Ticket encrypted with service key (stored in RAM)"
                      f"\n  - K_c,s: {session_key[:16]}..."
                      f"\n  - Service: {server_id}"
                      f"\n  - Lifetime: {lifetime}s")
            return True

        except Exception as e:
            log_error("Client", f"Error processing TGS-REP: {str(e)}")
            return False

    def create_ap_request(self) -> APRequest:
        """Create AP-REQ to access the target service server."""
        log_info("Client", "Creating AP-REQ for service access...")

        if not self.client_entity.service_ticket:
            log_error("Client", "Cannot create AP-REQ: missing Service Ticket")
            return None

        if not self.client_entity.session_key_c_s:
            log_error("Client", "Cannot create AP-REQ: missing K_c,s")
            return None

        authenticator = Authenticator(
            client_id=self.client_entity.client_id,
            timestamp=get_current_timestamp(),
            client_address=self.client_entity.client_address,
            realm=self.client_entity.realm
        )
        authenticator_data = {
            "client_id": authenticator.client_id,
            "timestamp": authenticator.timestamp,
            "client_address": authenticator.client_address,
            "realm": authenticator.realm
        }
        authenticator.encrypted_data = self.crypto.encrypt_dict(
            authenticator_data,
            self.client_entity.session_key_c_s
        )

        ap_request = APRequest(
            service_ticket=self.client_entity.service_ticket,
            authenticator=authenticator
        )

        log_success("Client", "AP-REQ created")
        return ap_request

    def process_ap_reply(self, ap_reply: APReply, ap_request: APRequest) -> bool:
        """Process AP-REP and verify mutual authentication."""
        log_info("Client", "Processing AP-REP - Phase 3 step 6 (Mutual Authentication)...")

        if not ap_reply.ok:
            log_error("Client", f"AP-REP error: {ap_reply.error_message}")
            return False

        if not self.client_entity.session_key_c_s:
            log_error("Client", "Cannot process AP-REP: missing K_c,s")
            return False

        if not ap_reply.server_proof_encrypted:
            log_error("Client", "No encrypted server proof found in AP-REP")
            return False

        proof_dict = self.crypto.decrypt_dict(
            ap_reply.server_proof_encrypted,
            self.client_entity.session_key_c_s
        )
        if not proof_dict:
            log_error("Client", "Failed to decrypt AP-REP server proof")
            return False

        expected_proof = ap_request.authenticator.timestamp + 1
        actual_proof = proof_dict.get("client_timestamp_proof")
        if actual_proof != expected_proof:
            log_error("Client", "AP-REP timestamp proof is invalid")
            return False

        log_success("Client", "AP-REP verified successfully!")
        log_success("Client", "Mutual authentication completed; service is trusted")
        return True

    
