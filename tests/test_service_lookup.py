"""Service-principal lookup tests."""

from __future__ import annotations

import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class ServiceLookupTests(KerberosTestCase):
    def test_unknown_service_rejected(self) -> None:
        from core.messages import KDC_ERR_S_PRINCIPAL_UNKNOWN

        conn = self.init_database()
        tgt_bundle = self.issue_tgt(conn)
        request = self.make_tgs_req(
            tgt_bundle,
            service_principal="missing/localhost@DEMO.LOCAL",
        )

        response = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual(KDC_ERR_S_PRINCIPAL_UNKNOWN, response["error_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
