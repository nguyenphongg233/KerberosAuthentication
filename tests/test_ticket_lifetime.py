"""Ticket lifetime validation tests."""

from __future__ import annotations

import time
import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class TicketLifetimeTests(KerberosTestCase):
    def test_expired_tgt_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_TKT_EXPIRED

        conn = self.init_database()
        now = time.time()
        expired_bundle = self.make_custom_tgt_bundle(
            conn,
            starttime=now - 900,
            endtime=now - 60,
        )
        request = self.make_tgs_req(expired_bundle)
        response = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual(KRB_AP_ERR_TKT_EXPIRED, response["error_code"])

    def test_not_yet_valid_tgt_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_TKT_NYV, MAX_CLOCK_SKEW

        conn = self.init_database()
        now = time.time()
        future_start = now + MAX_CLOCK_SKEW + 60
        future_bundle = self.make_custom_tgt_bundle(
            conn,
            starttime=future_start,
            endtime=future_start + 600,
        )
        request = self.make_tgs_req(future_bundle)
        response = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual(KRB_AP_ERR_TKT_NYV, response["error_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
