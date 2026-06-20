"""
messages.py - Standardized protocol constants for Kerberos V5.

Defines message types, error codes, and configuration constants
used across all components of the Kerberos authentication system.
"""

import os

from core.principal import DEFAULT_REALM, service_principal, tgs_principal

# ============================================================
# Message Types (KRB_MSG_TYPE)
# ============================================================
AS_REQ = "AS_REQ"       # Authentication Service Request
AS_REP = "AS_REP"       # Authentication Service Reply
TGS_REQ = "TGS_REQ"    # Ticket-Granting Service Request
TGS_REP = "TGS_REP"    # Ticket-Granting Service Reply
AP_REQ = "AP_REQ"       # Application Service Request
AP_REP = "AP_REP"       # Application Service Reply
ERROR = "KRB_ERROR"     # Error message

# ============================================================
# Error Codes
# ============================================================
KDC_ERR_C_PRINCIPAL_UNKNOWN = "KDC_ERR_C_PRINCIPAL_UNKNOWN"   # Client not found in DB
KDC_ERR_S_PRINCIPAL_UNKNOWN = "KDC_ERR_S_PRINCIPAL_UNKNOWN"   # Service not found in DB
KDC_ERR_CLIENT_REVOKED = "KDC_ERR_CLIENT_REVOKED"             # Client disabled or locked
KDC_ERR_PREAUTH_FAILED = "KDC_ERR_PREAUTH_FAILED"             # Wrong password / decryption failure
KDC_ERR_WRONG_REALM = "KDC_ERR_WRONG_REALM"                   # Request is for another realm
KRB_AP_ERR_MODIFIED = "KRB_AP_ERR_MODIFIED"                   # Ticket integrity error
KRB_AP_ERR_SKEW = "KRB_AP_ERR_SKEW"                           # Clock skew too great
KRB_AP_ERR_TKT_EXPIRED = "KRB_AP_ERR_TKT_EXPIRED"            # Ticket has expired
KRB_AP_ERR_TKT_NYV = "KRB_AP_ERR_TKT_NYV"                    # Ticket not yet valid
KRB_AP_ERR_REPEAT = "KRB_AP_ERR_REPEAT"                       # Replayed authenticator
KRB_ERR_GENERIC = "KRB_ERR_GENERIC"                           # Generic processing error

# ============================================================
# Configuration Constants
# ============================================================
TICKET_LIFETIME = 600           # Ticket lifetime in seconds (10 minutes)
RENEWABLE_LIFETIME = 3600       # Renewable lifetime in seconds (1 hour)
MAX_CLOCK_SKEW = 300            # Maximum allowed clock skew in seconds (5 minutes)
AUTH_FAILURE_THRESHOLD = int(os.getenv("KRB_AUTH_FAILURE_THRESHOLD", "3"))
AUTH_LOCKOUT_SECONDS = int(os.getenv("KRB_AUTH_LOCKOUT_SECONDS", "300"))
DEFAULT_TICKET_FLAGS = ["initial", "pre_authent", "renewable"]
SERVICE_TICKET_FLAGS = ["pre_authent"]

# ============================================================
# Network Configuration
# ============================================================
KDC_HOST = os.getenv("KDC_HOST", "127.0.0.1")
KDC_PORT = int(os.getenv("KDC_PORT", "4321"))
APP_SERVER_HOST = os.getenv("APP_SERVER_HOST", "127.0.0.1")
APP_SERVER_PORT = int(os.getenv("APP_SERVER_PORT", "8000"))
APP_SERVICE_NAME = os.getenv("APP_SERVICE_NAME", "fileserver")
APP_SERVER_NAME = os.getenv("APP_SERVER_NAME", "localhost")
WIRE_FORMAT = os.getenv("KRB_WIRE_FORMAT", "der").lower()

# ============================================================
# Principal Names
# ============================================================
REALM = DEFAULT_REALM
TGS_PRINCIPAL = tgs_principal(REALM)
APP_SERVICE_PRINCIPAL = service_principal(APP_SERVICE_NAME, APP_SERVER_NAME, REALM)
