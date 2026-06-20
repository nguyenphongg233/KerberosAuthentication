"""AS pre-authentication tests."""

from __future__ import annotations

import time
import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class ASPreauthTests(KerberosTestCase):
    def test_wrong_password_returns_preauth_failed(self) -> None:
        conn = self.init_database()
        response = self.mods.as_handler.handle_as_request(
            self.make_as_req("alice@DEMO.LOCAL", "wrong_password"),
            conn.cursor(),
        )
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual("KDC_ERR_PREAUTH_FAILED", response["error_code"])

    def test_repeated_wrong_password_temporarily_locks_principal(self) -> None:
        from core.messages import KDC_ERR_CLIENT_REVOKED, KDC_ERR_PREAUTH_FAILED

        conn = self.init_database()
        cursor = conn.cursor()

        for _attempt in range(2):
            response = self.mods.as_handler.handle_as_request(
                self.make_as_req("alice@DEMO.LOCAL", "wrong_password"),
                cursor,
            )
            self.assertEqual("KRB_ERROR", response["msg_type"])
            self.assertEqual(KDC_ERR_PREAUTH_FAILED, response["error_code"])

        third = self.mods.as_handler.handle_as_request(
            self.make_as_req("alice@DEMO.LOCAL", "wrong_password"),
            cursor,
        )
        self.assertEqual("KRB_ERROR", third["msg_type"])
        self.assertEqual(KDC_ERR_CLIENT_REVOKED, third["error_code"])

        locked_record = self.mods.database.get_principal(
            cursor,
            "alice@DEMO.LOCAL",
            include_disabled=True,
        )
        self.assertEqual(3, locked_record["failed_auth_count"])
        self.assertGreater(locked_record["locked_until"], 0)

        valid_while_locked = self.mods.as_handler.handle_as_request(
            self.make_as_req("alice@DEMO.LOCAL", "alice_password"),
            cursor,
        )
        self.assertEqual("KRB_ERROR", valid_while_locked["msg_type"])
        self.assertEqual(KDC_ERR_CLIENT_REVOKED, valid_while_locked["error_code"])

    def test_unknown_principal_returns_client_unknown(self) -> None:
        conn = self.init_database()
        response = self.mods.as_handler.handle_as_request(
            self.make_as_req("mallory@DEMO.LOCAL", "anything"),
            conn.cursor(),
        )
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual("KDC_ERR_C_PRINCIPAL_UNKNOWN", response["error_code"])

    def test_missing_preauth_returns_preauth_failed(self) -> None:
        conn = self.init_database()
        request = self.make_as_req("alice@DEMO.LOCAL", "alice_password")
        request.pop("preauth")
        response = self.mods.as_handler.handle_as_request(request, conn.cursor())
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual("KDC_ERR_PREAUTH_FAILED", response["error_code"])

    def test_old_preauth_timestamp_rejected(self) -> None:
        from core.messages import MAX_CLOCK_SKEW

        conn = self.init_database()
        old_time = time.time() - MAX_CLOCK_SKEW - 60
        response = self.mods.as_handler.handle_as_request(
            self.make_as_req("alice@DEMO.LOCAL", "alice_password", timestamp=old_time),
            conn.cursor(),
        )
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual("KRB_AP_ERR_SKEW", response["error_code"])

    def test_valid_as_rep_echoes_nonce(self) -> None:
        conn = self.init_database()
        bundle = self.issue_tgt(conn)
        self.assertEqual(bundle["response"]["msg_type"], "AS_REP")
        self.assertEqual(
            bundle["response"]["server_principal"],
            "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
