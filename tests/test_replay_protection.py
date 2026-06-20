"""Replay protection tests."""

from __future__ import annotations

import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class ReplayProtectionTests(KerberosTestCase):
    def test_tgs_replayed_authenticator_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_REPEAT, TGS_REP

        conn = self.init_database()
        tgt_bundle = self.issue_tgt(conn)
        request = self.make_tgs_req(tgt_bundle)

        first = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual(TGS_REP, first["msg_type"], first)

        second = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual("KRB_ERROR", second["msg_type"])
        self.assertEqual(KRB_AP_ERR_REPEAT, second["error_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
