"""Key rotation and key-history tests."""

from __future__ import annotations

import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class KeyRotationTests(KerberosTestCase):
    def test_old_tgt_survives_tgs_key_rotation(self) -> None:
        from core.messages import TGS_PRINCIPAL, TGS_REP

        conn = self.init_database()
        tgt_bundle = self.issue_tgt(conn)
        cursor = conn.cursor()
        old_tgs = self.mods.database.get_principal(
            cursor,
            TGS_PRINCIPAL,
            resolve_alias=False,
        )
        self.mods.database.upsert_principal(
            conn,
            TGS_PRINCIPAL,
            "rotated_tgs_secret_after_ticket_issue",
            old_tgs["principal_type"],
            kvno=int(old_tgs["kvno"]) + 1,
            groups=old_tgs.get("groups", "[]"),
        )
        conn.commit()

        request = self.make_tgs_req(tgt_bundle)
        response = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual(TGS_REP, response["msg_type"], response)

    def test_database_keeps_key_history_and_init_does_not_reset_kvno(self) -> None:
        from core.messages import TGS_PRINCIPAL

        conn = self.init_database()
        cursor = conn.cursor()
        old = self.mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
        old_kvno = int(old["kvno"])
        old_key = old["key"]

        rotated = self.mods.database.upsert_principal(
            conn,
            TGS_PRINCIPAL,
            "rotated_tgs_secret",
            old["principal_type"],
            kvno=old_kvno + 1,
            groups=old.get("groups", "[]"),
        )
        conn.commit()
        self.assertEqual(old_kvno + 1, int(rotated["kvno"]))
        self.assertNotEqual(old_key, rotated["key"])

        historical = self.mods.database.get_principal_key(
            cursor,
            TGS_PRINCIPAL,
            kvno=old_kvno,
            enctype=old["enctype"],
            resolve_alias=False,
        )
        self.assertIsNotNone(historical)
        self.assertEqual(old_key, historical["key"])

        self.mods.database.init_database()
        current = self.mods.database.get_principal(
            conn.cursor(),
            TGS_PRINCIPAL,
            resolve_alias=False,
        )
        self.assertEqual(old_kvno + 1, int(current["kvno"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
