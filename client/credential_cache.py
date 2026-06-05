"""
credential_cache.py - In-memory storage for TGT and Session Keys.

Provides a simple credential cache that the client uses to store
and retrieve tickets and session keys obtained during the Kerberos
authentication process.
"""


class CredentialCache:
    """
    In-memory credential cache for Kerberos tickets and session keys.

    Stores:
        - TGT and client-TGS session key (from AS Exchange)
        - Service Ticket and client-service session key (from TGS Exchange)
    """

    def __init__(self):
        """Initialize an empty credential cache."""
        self._tgt = None
        self._client_tgs_session_key = None
        self._service_tickets = {}  # service_principal -> (ticket, session_key)

    def store_tgt(self, tgt: str, client_tgs_session_key: bytes):
        """
        Store the TGT and associated session key.

        Args:
            tgt: The encrypted TGT string.
            client_tgs_session_key: The session key for Client ↔ TGS communication.
        """
        self._tgt = tgt
        self._client_tgs_session_key = client_tgs_session_key

    def get_tgt(self) -> tuple:
        """
        Retrieve the stored TGT and session key.

        Returns:
            Tuple of (tgt, client_tgs_session_key), or (None, None) if not cached.
        """
        return self._tgt, self._client_tgs_session_key

    def store_service_ticket(self, service_principal: str,
                              service_ticket: str,
                              client_service_session_key: bytes):
        """
        Store a service ticket and associated session key.

        Args:
            service_principal: The name of the target service.
            service_ticket: The encrypted service ticket string.
            client_service_session_key: The session key for Client ↔ Service communication.
        """
        self._service_tickets[service_principal] = (
            service_ticket, client_service_session_key
        )

    def get_service_ticket(self, service_principal: str) -> tuple:
        """
        Retrieve a stored service ticket and session key.

        Args:
            service_principal: The name of the target service.

        Returns:
            Tuple of (service_ticket, client_service_session_key),
            or (None, None) if not cached.
        """
        if service_principal in self._service_tickets:
            return self._service_tickets[service_principal]
        return None, None

    def clear(self):
        """Clear all cached credentials."""
        self._tgt = None
        self._client_tgs_session_key = None
        self._service_tickets.clear()

    def has_tgt(self) -> bool:
        """Check if a TGT is currently cached."""
        return self._tgt is not None

    def has_service_ticket(self, service_principal: str) -> bool:
        """Check if a service ticket is cached for the given service."""
        return service_principal in self._service_tickets
