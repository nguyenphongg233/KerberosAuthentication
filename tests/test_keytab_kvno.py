"""MIT keytab kvno-selection tests."""

from __future__ import annotations

import unittest
from pathlib import Path

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class KeytabKvnoTests(KerberosTestCase):
    def test_keytab_selects_exact_kvno_and_highest_fallback(self) -> None:
        from core.crypto import str_to_key
        from core.keytab import load_keytab, write_keytab

        keytab_path = str(Path(self.runtime.name) / "service.keytab")
        principal = "fileserver/localhost@DEMO.LOCAL"
        key_v1 = b"\x01" * 32
        key_v2 = b"\x02" * 32

        write_keytab(keytab_path, principal, key_v1, 1, 18, "DEMO.LOCAL")
        write_keytab(keytab_path, principal, key_v2, 2, 18, "DEMO.LOCAL")

        exact_v1 = load_keytab(keytab_path, principal, kvno=1, enctype=18)
        fallback = load_keytab(keytab_path, principal, enctype=18)

        self.assertEqual(1, exact_v1["kvno"])
        self.assertEqual(key_v1, str_to_key(exact_v1["key"]))
        self.assertEqual(2, fallback["kvno"])
        self.assertEqual(key_v2, str_to_key(fallback["key"]))

    def test_keytab_wrong_service_not_selected(self) -> None:
        from core.keytab import load_keytab, write_keytab

        keytab_path = str(Path(self.runtime.name) / "service.keytab")
        write_keytab(
            keytab_path,
            "fileserver/localhost@DEMO.LOCAL",
            b"\x03" * 32,
            1,
            18,
            "DEMO.LOCAL",
        )

        with self.assertRaises(KeyError):
            load_keytab(keytab_path, "http/localhost@DEMO.LOCAL", kvno=1, enctype=18)


if __name__ == "__main__":
    unittest.main(verbosity=2)
