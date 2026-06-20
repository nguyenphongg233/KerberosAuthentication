"""Credential-cache metadata tests."""

from __future__ import annotations

import unittest
from pathlib import Path

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class CCacheMetadataTests(KerberosTestCase):
    def test_ccache_preserves_tgt_ticket_metadata_after_reload(self) -> None:
        cache_path = str(Path(self.runtime.name) / "client" / "krb5cc_demo")
        cache = self.mods.credential_cache.CredentialCache(cache_path)
        cache.store_tgt(
            b"demo-ticket",
            b"0" * 32,
            {
                "ticket_kvno": 7,
                "ticket_enctype": 18,
                "enctype": "aes256-cts-hmac-sha1-96",
                "authtime": 1,
                "starttime": 1,
                "endtime": 4_102_444_800,
                "renew_till": 4_102_445_400,
                "client_principal": "alice@DEMO.LOCAL",
                "server_principal": "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
            },
        )

        reloaded = self.mods.credential_cache.CredentialCache(cache_path)
        metadata = reloaded.get_tgt_metadata()
        self.assertEqual(7, metadata["ticket_kvno"])
        self.assertEqual(18, metadata["ticket_enctype"])

    def test_ccache_drops_expired_service_ticket_on_read(self) -> None:
        cache_path = str(Path(self.runtime.name) / "client" / "krb5cc_demo")
        cache = self.mods.credential_cache.CredentialCache(cache_path)
        service = "fileserver/localhost@DEMO.LOCAL"
        cache.store_service_ticket(
            service,
            b"expired-ticket",
            b"1" * 32,
            {
                "ticket_kvno": 1,
                "ticket_enctype": 18,
                "authtime": 1,
                "starttime": 1,
                "endtime": 2,
                "renew_till": 0,
            },
        )

        ticket, session_key = cache.get_service_ticket(service)
        self.assertIsNone(ticket)
        self.assertIsNone(session_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
