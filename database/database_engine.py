"""
Database Engine: Logic xử lý của KDC Database
"""

from database.database_entity import KDCDatabaseEntity, Principal
from database.database_crypto import DatabaseCryptoEngine
from shared.utils import log_info, log_success, log_error, log_debug


class DatabaseEngine:
    """Engine xử lý logic của KDC Database"""
    
    def __init__(self, database: KDCDatabaseEntity):
        self.database = database
        self.crypto = DatabaseCryptoEngine()
    
    def initialize_database(self):
        """Khởi tạo database với các Principal mặc định"""
        log_info("Database", "Initializing KDC Database...")
        
        # Tạo TGS Service (KDC's own service)
        tgs_principal = Principal(
            name="krbtgt",
            realm=self.database.realm,
            master_key=self.crypto.hash_password("TGS_SECRET_KEY")
        )
        self.database.add_principal(tgs_principal)
        log_success("Database", f"Added Principal: {tgs_principal}")
        
        # Tạo Mail Service
        mail_principal = Principal(
            name="mail-service",
            realm=self.database.realm,
            master_key=self.crypto.hash_password("MAIL_SERVICE_SECRET")
        )
        self.database.add_principal(mail_principal)
        log_success("Database", f"Added Principal: {mail_principal}")
        
        # Tạo User Alice
        alice_principal = Principal(
            name="alice",
            realm=self.database.realm,
            password_hash=self.crypto.hash_password("alice_password_123")
        )
        self.database.add_principal(alice_principal)
        log_success("Database", f"Added Principal: {alice_principal}")
    
    def get_principal_master_key(self, principal_name: str) -> str:
        """Lấy Master Key của một Principal"""
        principal = self.database.get_principal(principal_name)
        
        if not principal:
            log_error("Database", f"Principal not found: {principal_name}")
            return ""
        
        key = principal.password_hash if principal.password_hash else principal.master_key
        
        if not key:
            log_error("Database", f"No key found for Principal: {principal_name}")
            return ""
        
        log_debug("Database", f"Retrieved key for Principal: {principal_name}")
        return key
    
    def verify_principal_exists(self, principal_name: str) -> bool:
        """Kiểm tra Principal có tồn tại không"""
        exists = self.database.principal_exists(principal_name)
        
        if not exists:
            log_error("Database", f"Principal not found: {principal_name}")
            return False
        
        log_debug("Database", f"Principal exists: {principal_name}")
        return True
    
    def get_tgs_principal_name(self) -> str:
        """Lấy tên đầy đủ của TGS Service"""
        return f"krbtgt@{self.database.realm}"
    
    def get_database_info(self) -> str:
        """Lấy thông tin database"""
        info = f"Database: {self.database.realm}\n"
        info += f"Total Principals: {len(self.database.principals)}\n"
        info += "Principals:\n"
        for principal_name in self.database.principals:
            info += f"  - {principal_name}\n"
        return info
