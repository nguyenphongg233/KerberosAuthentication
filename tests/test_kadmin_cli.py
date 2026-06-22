"""KAdmin CLI behavior tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class KAdminCLITests(KerberosTestCase):
    def test_cpw_preserves_groups_bumps_kvno_and_keeps_key_history(self) -> None:
        from core.messages import APP_SERVICE_PRINCIPAL

        conn = self.init_database()
        before = self.mods.database.get_principal(
            conn.cursor(),
            APP_SERVICE_PRINCIPAL,
            resolve_alias=False,
        )
        self.assertEqual(1, before["kvno"])

        self.mods.kadmin.cmd_cpw(
            SimpleNamespace(
                principal=APP_SERVICE_PRINCIPAL,
                password="rotated_fileserver_secret",
            )
        )

        after = self.mods.database.get_principal(
            conn.cursor(),
            APP_SERVICE_PRINCIPAL,
            resolve_alias=False,
        )
        self.assertEqual(2, after["kvno"])
        self.assertEqual(before["groups"], after["groups"])

        key_versions = self.mods.database.list_principal_keys(
            conn.cursor(),
            APP_SERVICE_PRINCIPAL,
            resolve_alias=False,
        )
        self.assertEqual([1, 2], sorted(row["kvno"] for row in key_versions))

        audit_cursor = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_log
            WHERE component = 'KDC'
              AND event = 'principal_upserted'
              AND principal = ?
              AND detail LIKE '%"kvno": 2%'
            """,
            (APP_SERVICE_PRINCIPAL,),
        )
        self.assertGreater(audit_cursor.fetchone()[0], 0)

    def test_ktadd_all_versions_exports_key_history(self) -> None:
        from core.keytab import load_keytab
        from core.messages import APP_SERVICE_PRINCIPAL

        conn = self.init_database()
        self.mods.kadmin.cmd_cpw(
            SimpleNamespace(
                principal=APP_SERVICE_PRINCIPAL,
                password="rotated_fileserver_secret",
            )
        )

        keytab_path = Path(self.runtime.name) / "exports" / "fileserver-all.keytab"
        self.mods.kadmin.cmd_ktadd(
            SimpleNamespace(
                principal=APP_SERVICE_PRINCIPAL,
                keytab=str(keytab_path),
                all_versions=True,
            )
        )

        v1 = load_keytab(str(keytab_path), APP_SERVICE_PRINCIPAL, kvno=1)
        v2 = load_keytab(str(keytab_path), APP_SERVICE_PRINCIPAL, kvno=2)
        latest = load_keytab(str(keytab_path), APP_SERVICE_PRINCIPAL)

        self.assertEqual(1, v1["kvno"])
        self.assertEqual(2, v2["kvno"])
        self.assertEqual(2, latest["kvno"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
