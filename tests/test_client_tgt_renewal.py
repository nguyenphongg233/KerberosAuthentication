"""Client-level TGT renewal tests."""

from __future__ import annotations

import importlib
import time
import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class ClientTGTRenewalTests(KerberosTestCase):
    def test_client_renew_tgt_exchange_updates_cache_and_allows_tgs(self) -> None:
        from core.messages import TGS_REQ, TGS_PRINCIPAL

        conn = self.init_database()
        now = time.time()
        old_tgt = self.make_custom_tgt_bundle(
            conn,
            endtime=now - 30,
            renew_till=now + 900,
        )

        import client.client_app as client_app

        client_app = importlib.reload(client_app)
        client_app.client_principal_global = "alice@DEMO.LOCAL"
        client_app.cache.clear()
        client_app.cache.store_tgt(
            old_tgt["response"]["tgt"],
            old_tgt["session_key"],
            {
                **old_tgt["enc_part"],
                "client_principal": old_tgt["principal"],
                "server_principal": TGS_PRINCIPAL,
                "service_principal": TGS_PRINCIPAL,
                "ticket_enctype": old_tgt["response"]["tgt_enctype"],
                "ticket_kvno": old_tgt["response"]["tgt_kvno"],
            },
        )

        def fake_send_to_kdc(message: dict, phase_name: str) -> dict:
            self.assertEqual(TGS_REQ, message["msg_type"], phase_name)
            return self.mods.tgs_handler.handle_tgs_request(message, conn.cursor())

        original_send = client_app._send_to_kdc
        try:
            client_app._send_to_kdc = fake_send_to_kdc
            self.assertTrue(client_app.renew_tgt_exchange())
            renewed_metadata = client_app.cache.get_tgt_metadata()
            self.assertGreater(renewed_metadata["endtime"], now)
            self.assertLessEqual(renewed_metadata["endtime"], old_tgt["enc_part"]["renew_till"])

            self.assertTrue(client_app.phase2_tgs_exchange("fileserver"))
        finally:
            client_app._send_to_kdc = original_send


if __name__ == "__main__":
    unittest.main(verbosity=2)
