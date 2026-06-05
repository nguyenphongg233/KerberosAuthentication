"""
messages.py - Standardized protocol constants for Kerberos V5.

Defines message types, error codes, and configuration constants
used across all components of the Kerberos authentication system.
"""

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
KDC_ERR_PREAUTH_FAILED = "KDC_ERR_PREAUTH_FAILED"             # Wrong password / decryption failure
KRB_AP_ERR_MODIFIED = "KRB_AP_ERR_MODIFIED"                   # Ticket integrity error
KRB_AP_ERR_SKEW = "KRB_AP_ERR_SKEW"                           # Clock skew too great
KRB_AP_ERR_TKT_EXPIRED = "KRB_AP_ERR_TKT_EXPIRED"            # Ticket has expired
KRB_ERR_GENERIC = "KRB_ERR_GENERIC"                           # Generic processing error

# ============================================================
# Configuration Constants
# ============================================================
TICKET_LIFETIME = 600           # Ticket lifetime in seconds (10 minutes)
MAX_CLOCK_SKEW = 300            # Maximum allowed clock skew in seconds (5 minutes)

# ============================================================
# Network Configuration
# ============================================================
KDC_HOST = "127.0.0.1"
KDC_PORT = 8888
APP_SERVER_HOST = "127.0.0.1"
APP_SERVER_PORT = 8000

# ============================================================
# Principal Names
# ============================================================
TGS_PRINCIPAL = "krbtgt"       # TGS principal name
