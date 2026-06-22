"""Ticket integrity and tampering tests."""

from __future__ import annotations

import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class TicketIntegrityTests(KerberosTestCase):
    def test_tampered_tgt_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_MODIFIED

        conn = self.init_database()
        tgt_bundle = self.issue_tgt(conn)
        request = self.make_tgs_req(tgt_bundle)

        tampered_tgt = bytearray(request["tgt"])
        tampered_tgt[-1] ^= 0x01
        request["tgt"] = bytes(tampered_tgt)

        response = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual(KRB_AP_ERR_MODIFIED, response["error_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
