"""Application Server AP exchange security tests."""

from __future__ import annotations

import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class ApplicationServerAPTests(KerberosTestCase):
    def test_valid_ap_req_returns_ap_rep(self) -> None:
        from core.messages import AP_REP

        conn = self.init_database()
        service_bundle = self.issue_service_ticket(conn)
        ap_req = self.make_ap_req(service_bundle)

        response = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(200, response["status"], response["body"])
        self.assertIsNotNone(response["token"])
        self.assertEqual(AP_REP, response["token"]["msg_type"])
        body = response["body"].decode("utf-8")
        self.assertIn("Protected File Server access granted", body)
        self.assertIn("authorized_action: LIST_PROTECTED_FILES", body)
        self.assertIn("project-overview.txt", body)
        self.assertIn("kdc-audit-log.txt", body)
        self.assertIn(b"Protected File Catalog", response["body"])

    def test_non_admin_user_gets_only_user_visible_resources(self) -> None:
        conn = self.init_database()
        service_bundle = self.issue_service_ticket(
            conn,
            principal="bob@DEMO.LOCAL",
            password="bob_password",
        )
        ap_req = self.make_ap_req(service_bundle)

        response = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(200, response["status"], response["body"])
        body = response["body"].decode("utf-8")
        self.assertIn("access_level: standard-user", body)
        self.assertIn("project-overview.txt", body)
        self.assertIn("admin_resources: hidden", body)
        self.assertNotIn("kdc-audit-log.txt", body)

    def test_ap_replayed_authenticator_rejected(self) -> None:
        from core.messages import AP_REP, KRB_AP_ERR_REPEAT

        conn = self.init_database()
        service_bundle = self.issue_service_ticket(conn)
        ap_req = self.make_ap_req(service_bundle)

        first = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(200, first["status"], first["body"])
        self.assertEqual(AP_REP, first["token"]["msg_type"])

        second = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(403, second["status"], second["body"])
        self.assertEqual("KRB_ERROR", second["token"]["msg_type"])
        self.assertEqual(KRB_AP_ERR_REPEAT, second["token"]["error_code"])

    def test_ap_req_for_unknown_service_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_MODIFIED

        conn = self.init_database()
        service_bundle = self.issue_service_ticket(conn)
        ap_req = self.make_ap_req(
            service_bundle,
            service_principal="mailserver/localhost@DEMO.LOCAL",
        )

        response = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(403, response["status"], response["body"])
        self.assertEqual("KRB_ERROR", response["token"]["msg_type"])
        self.assertEqual(KRB_AP_ERR_MODIFIED, response["token"]["error_code"])

    def test_wrong_service_rejected_even_when_keytab_has_that_service(self) -> None:
        from core.keytab import write_keytab
        from core.messages import KRB_AP_ERR_MODIFIED, REALM

        conn = self.init_database()
        mail_record = self.mods.database.upsert_principal(
            conn,
            "mailserver/localhost@DEMO.LOCAL",
            "mailserver_secret",
            "service",
        )
        write_keytab(
            self.mods.service_server.KEYTAB_PATH,
            mail_record["principal_name"],
            mail_record["key"],
            mail_record["kvno"],
            mail_record["enctype"],
            REALM,
        )

        service_bundle = self.issue_service_ticket(conn)
        ap_req = self.make_ap_req(
            service_bundle,
            service_principal="mailserver/localhost@DEMO.LOCAL",
        )

        response = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(403, response["status"], response["body"])
        self.assertEqual("KRB_ERROR", response["token"]["msg_type"])
        self.assertEqual(KRB_AP_ERR_MODIFIED, response["token"]["error_code"])

    def test_tampered_service_ticket_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_MODIFIED

        conn = self.init_database()
        service_bundle = self.issue_service_ticket(conn)
        ap_req = self.make_ap_req(service_bundle)
        tampered = bytearray(ap_req["service_ticket"])
        tampered[-1] ^= 0x01
        ap_req["service_ticket"] = bytes(tampered)

        response = self.send_ap_req_to_app_server(ap_req)
        self.assertEqual(403, response["status"], response["body"])
        self.assertEqual("KRB_ERROR", response["token"]["msg_type"])
        self.assertEqual(KRB_AP_ERR_MODIFIED, response["token"]["error_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
