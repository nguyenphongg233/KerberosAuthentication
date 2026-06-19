"""Focused regression tests for the Kerberos demo.

The tests use temporary runtime files and call AS/TGS handlers in-process. They
do not start listening sockets and do not touch the repository database,
keytab, or credential cache.
"""

from __future__ import annotations

import importlib
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class KerberosRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_env = dict(os.environ)
        self.runtime = tempfile.TemporaryDirectory(
            prefix="krb-regression-",
            ignore_cleanup_errors=True,
        )
        self.addCleanup(self.runtime.cleanup)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        os.environ.clear()
        os.environ.update(self._old_env)

    def _fresh_modules(self) -> SimpleNamespace:
        root = Path(self.runtime.name)
        os.environ.update(
            {
                "KDC_DB_PATH": str(root / "kdc" / "database.db"),
                "APP_SERVER_KEYTAB": str(root / "app" / "fileserver.keytab"),
                "KRB5CCNAME": str(root / "client" / "krb5cc_demo"),
                "KRB_REPLAY_CACHE": str(root / "replay" / "replay.db"),
                "KDC_HOST": "127.0.0.1",
                "APP_SERVER_HOST": "127.0.0.1",
            }
        )

        module_names = [
            "kdc.database",
            "core.replay_cache",
            "kdc.as_handler",
            "kdc.tgs_handler",
            "client.credential_cache",
        ]
        modules = {}
        for name in module_names:
            module = importlib.import_module(name)
            modules[name] = importlib.reload(module)
        return SimpleNamespace(
            database=modules["kdc.database"],
            replay_cache=modules["core.replay_cache"],
            as_handler=modules["kdc.as_handler"],
            tgs_handler=modules["kdc.tgs_handler"],
            credential_cache=modules["client.credential_cache"],
        )

    def _make_as_req(self, principal: str, password: str, nonce: int | None = None) -> dict:
        from core.asn1_codec import encode_pa_enc_timestamp
        from core.crypto import (
            DEFAULT_ENCTYPE,
            KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
            derive_key,
            encrypt,
        )
        from core.messages import AS_REQ, REALM
        from core.principal import principal_realm, principal_salt
        from core.replay_cache import current_kerberos_time

        realm = principal_realm(principal, REALM)
        client_key = derive_key(
            password,
            salt=principal_salt(principal, realm),
            enctype=DEFAULT_ENCTYPE,
        )
        _timestamp, ctime, cusec = current_kerberos_time()
        preauth = encrypt(
            encode_pa_enc_timestamp({"ctime": ctime, "cusec": cusec}),
            client_key,
            KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
        )
        return {
            "msg_type": AS_REQ,
            "client_principal": principal,
            "realm": realm,
            "nonce": nonce if nonce is not None else secrets.randbits(31),
            "preauth": preauth,
            "preauth_enctype": DEFAULT_ENCTYPE,
            "kdc_options": ["renewable"],
        }

    def _issue_tgt(self, mods: SimpleNamespace, conn, principal: str = "alice@DEMO.LOCAL") -> dict:
        from core.asn1_codec import decode_enc_kdc_rep_part
        from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AS_REP_ENCPART, decrypt, derive_key
        from core.messages import AS_REP, REALM
        from core.principal import principal_salt

        nonce = secrets.randbits(31)
        response = mods.as_handler.handle_as_request(
            self._make_as_req(principal, "alice_password", nonce=nonce),
            conn.cursor(),
        )
        self.assertEqual(AS_REP, response["msg_type"], response)

        client_key = derive_key(
            "alice_password",
            salt=principal_salt(principal, REALM),
            enctype=DEFAULT_ENCTYPE,
        )
        decrypted = decrypt(
            response["encrypted_data"],
            client_key,
            KEY_USAGE_AS_REP_ENCPART,
        )
        enc_part = decode_enc_kdc_rep_part(decrypted, AS_REP)
        self.assertEqual(nonce, enc_part["nonce"])
        return {
            "response": response,
            "enc_part": enc_part,
            "session_key": enc_part["key"]["keyvalue"],
        }

    def _make_tgs_req(self, tgt_bundle: dict, nonce: int | None = None) -> dict:
        from core.asn1_codec import encode_authenticator
        from core.crypto import (
            DEFAULT_ENCTYPE,
            KEY_USAGE_TGS_REQ_AUTH,
            encrypt,
        )
        from core.messages import APP_SERVICE_PRINCIPAL, REALM, TGS_PRINCIPAL, TGS_REQ
        from core.replay_cache import current_kerberos_time

        _timestamp, ctime, cusec = current_kerberos_time()
        authenticator = encrypt(
            encode_authenticator(
                {
                    "client_principal": "alice@DEMO.LOCAL",
                    "realm": REALM,
                    "ctime": ctime,
                    "cusec": cusec,
                }
            ),
            tgt_bundle["session_key"],
            KEY_USAGE_TGS_REQ_AUTH,
        )
        as_response = tgt_bundle["response"]
        return {
            "msg_type": TGS_REQ,
            "realm": REALM,
            "service_principal": APP_SERVICE_PRINCIPAL,
            "tgt": as_response["tgt"],
            "tgt_service_principal": TGS_PRINCIPAL,
            "tgt_enctype": as_response["tgt_enctype"],
            "tgt_kvno": as_response["tgt_kvno"],
            "authenticator": authenticator,
            "authenticator_enctype": DEFAULT_ENCTYPE,
            "nonce": nonce if nonce is not None else secrets.randbits(31),
        }

    def test_as_rejects_wrong_password_and_unknown_principal(self) -> None:
        mods = self._fresh_modules()
        mods.database.init_database()
        conn = mods.database.connect()
        try:
            wrong_password = mods.as_handler.handle_as_request(
                self._make_as_req("alice@DEMO.LOCAL", "wrong_password"),
                conn.cursor(),
            )
            self.assertEqual("KRB_ERROR", wrong_password["msg_type"])
            self.assertEqual("KDC_ERR_PREAUTH_FAILED", wrong_password["error_code"])

            unknown = mods.as_handler.handle_as_request(
                self._make_as_req("mallory@DEMO.LOCAL", "anything"),
                conn.cursor(),
            )
            self.assertEqual("KRB_ERROR", unknown["msg_type"])
            self.assertEqual("KDC_ERR_C_PRINCIPAL_UNKNOWN", unknown["error_code"])
        finally:
            conn.close()

    def test_tgs_rejects_replayed_authenticator(self) -> None:
        from core.messages import KRB_AP_ERR_REPEAT, TGS_REP

        mods = self._fresh_modules()
        mods.database.init_database()
        conn = mods.database.connect()
        try:
            tgt_bundle = self._issue_tgt(mods, conn)
            request = self._make_tgs_req(tgt_bundle)

            first = mods.tgs_handler.handle_tgs_request(request, conn.cursor())
            self.assertEqual(TGS_REP, first["msg_type"], first)

            second = mods.tgs_handler.handle_tgs_request(request, conn.cursor())
            self.assertEqual("KRB_ERROR", second["msg_type"])
            self.assertEqual(KRB_AP_ERR_REPEAT, second["error_code"])
        finally:
            conn.close()

    def test_old_tgt_survives_tgs_key_rotation(self) -> None:
        from core.messages import TGS_PRINCIPAL, TGS_REP

        mods = self._fresh_modules()
        mods.database.init_database()
        conn = mods.database.connect()
        try:
            tgt_bundle = self._issue_tgt(mods, conn)
            cursor = conn.cursor()
            old_tgs = mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
            mods.database.upsert_principal(
                conn,
                TGS_PRINCIPAL,
                "rotated_tgs_secret_after_ticket_issue",
                old_tgs["principal_type"],
                kvno=int(old_tgs["kvno"]) + 1,
                groups=old_tgs.get("groups", "[]"),
            )
            conn.commit()

            request = self._make_tgs_req(tgt_bundle)
            response = mods.tgs_handler.handle_tgs_request(request, conn.cursor())
            self.assertEqual(TGS_REP, response["msg_type"], response)
        finally:
            conn.close()

    def test_database_keeps_key_history_and_init_does_not_reset_kvno(self) -> None:
        from core.messages import TGS_PRINCIPAL

        mods = self._fresh_modules()
        mods.database.init_database()
        conn = mods.database.connect()
        try:
            cursor = conn.cursor()
            old = mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
            old_kvno = int(old["kvno"])
            old_key = old["key"]

            rotated = mods.database.upsert_principal(
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

            historical = mods.database.get_principal_key(
                cursor,
                TGS_PRINCIPAL,
                kvno=old_kvno,
                enctype=old["enctype"],
                resolve_alias=False,
            )
            self.assertIsNotNone(historical)
            self.assertEqual(old_key, historical["key"])
        finally:
            conn.close()

        mods.database.init_database()
        conn = mods.database.connect()
        try:
            current = mods.database.get_principal(
                conn.cursor(),
                TGS_PRINCIPAL,
                resolve_alias=False,
            )
            self.assertEqual(old_kvno + 1, int(current["kvno"]))
        finally:
            conn.close()

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

    def test_ccache_preserves_ticket_metadata_after_reload(self) -> None:
        mods = self._fresh_modules()
        cache_path = str(Path(self.runtime.name) / "client" / "krb5cc_demo")
        cache = mods.credential_cache.CredentialCache(cache_path)
        cache.store_tgt(
            b"demo-ticket",
            b"0" * 32,
            {
                "ticket_kvno": 7,
                "ticket_enctype": 18,
                "enctype": "aes256-cts-hmac-sha1-96",
                "authtime": 1,
                "starttime": 1,
                "endtime": 4_102_444_800,
                "renew_till": 4_102_445_400,
                "client_principal": "alice@DEMO.LOCAL",
                "server_principal": "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
            },
        )

        reloaded = mods.credential_cache.CredentialCache(cache_path)
        metadata = reloaded.get_tgt_metadata()
        self.assertEqual(7, metadata["ticket_kvno"])
        self.assertEqual(18, metadata["ticket_enctype"])


if __name__ == "__main__":
    unittest.main()
