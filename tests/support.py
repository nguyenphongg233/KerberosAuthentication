"""Shared helpers for in-process Kerberos tests."""

from __future__ import annotations

import importlib
import os
import base64
import socket
import secrets
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


class KerberosTestCase(unittest.TestCase):
    """Base class that gives every test an isolated Kerberos runtime."""

    def setUp(self) -> None:
        self._old_env = dict(os.environ)
        self.runtime = tempfile.TemporaryDirectory(
            prefix="krb-test-",
            ignore_cleanup_errors=True,
        )
        self.addCleanup(self.runtime.cleanup)
        self.addCleanup(self._restore_env)
        self.mods = self.fresh_modules()

    def _restore_env(self) -> None:
        os.environ.clear()
        os.environ.update(self._old_env)

    def fresh_modules(self) -> SimpleNamespace:
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
            "core.principal",
            "core.messages",
            "kdc.database",
            "core.replay_cache",
            "kdc.as_handler",
            "kdc.tgs_handler",
            "kdc.kadmin",
            "kdc.kadmin_web",
            "app_server.service_server",
            "client.credential_cache",
        ]
        modules = {}
        for name in module_names:
            module = importlib.import_module(name)
            modules[name] = importlib.reload(module)
        return SimpleNamespace(
            messages=modules["core.messages"],
            database=modules["kdc.database"],
            replay_cache=modules["core.replay_cache"],
            as_handler=modules["kdc.as_handler"],
            tgs_handler=modules["kdc.tgs_handler"],
            kadmin=modules["kdc.kadmin"],
            kadmin_web=modules["kdc.kadmin_web"],
            service_server=modules["app_server.service_server"],
            credential_cache=modules["client.credential_cache"],
        )

    def init_database(self):
        self.mods.database.init_database()
        conn = self.mods.database.connect()
        self.addCleanup(conn.close)
        return conn

    def make_as_req(
        self,
        principal: str,
        password: str,
        nonce: int | None = None,
        timestamp: float | None = None,
    ) -> dict:
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
        if timestamp is None:
            _timestamp, ctime, cusec = current_kerberos_time()
        else:
            ctime = int(timestamp)
            cusec = int(round((timestamp - ctime) * 1_000_000))

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

    def issue_tgt(
        self,
        conn,
        principal: str = "alice@DEMO.LOCAL",
        password: str = "alice_password",
    ) -> dict:
        from core.asn1_codec import decode_enc_kdc_rep_part
        from core.crypto import (
            DEFAULT_ENCTYPE,
            KEY_USAGE_AS_REP_ENCPART,
            decrypt,
            derive_key,
        )
        from core.messages import AS_REP, REALM
        from core.principal import principal_salt

        nonce = secrets.randbits(31)
        response = self.mods.as_handler.handle_as_request(
            self.make_as_req(principal, password, nonce=nonce),
            conn.cursor(),
        )
        self.assertEqual(AS_REP, response["msg_type"], response)

        client_key = derive_key(
            password,
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
            "principal": principal,
            "response": response,
            "enc_part": enc_part,
            "session_key": enc_part["key"]["keyvalue"],
        }

    def make_tgs_req(
        self,
        tgt_bundle: dict,
        nonce: int | None = None,
        service_principal: str | None = None,
        authenticator_principal: str | None = None,
    ) -> dict:
        from core.asn1_codec import encode_authenticator
        from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REQ_AUTH, encrypt
        from core.messages import APP_SERVICE_PRINCIPAL, REALM, TGS_PRINCIPAL, TGS_REQ
        from core.replay_cache import current_kerberos_time

        _timestamp, ctime, cusec = current_kerberos_time()
        auth_principal = authenticator_principal or tgt_bundle.get("principal", "alice@DEMO.LOCAL")
        authenticator = encrypt(
            encode_authenticator(
                {
                    "client_principal": auth_principal,
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
            "service_principal": service_principal or APP_SERVICE_PRINCIPAL,
            "tgt": as_response["tgt"],
            "tgt_service_principal": TGS_PRINCIPAL,
            "tgt_enctype": as_response["tgt_enctype"],
            "tgt_kvno": as_response["tgt_kvno"],
            "authenticator": authenticator,
            "authenticator_enctype": DEFAULT_ENCTYPE,
            "nonce": nonce if nonce is not None else secrets.randbits(31),
        }

    def make_custom_tgt_bundle(
        self,
        conn,
        client_principal: str = "alice@DEMO.LOCAL",
        starttime: float | None = None,
        endtime: float | None = None,
        renew_till: float | None = None,
    ) -> dict:
        from core.asn1_codec import encode_enc_ticket_part
        from core.crypto import (
            DEFAULT_ENCTYPE,
            KEY_USAGE_TICKET,
            NAME_TO_ENCTYPE,
            encrypt,
            generate_session_key,
            str_to_key,
        )
        from core.messages import DEFAULT_TICKET_FLAGS, REALM, TGS_PRINCIPAL

        now = time.time()
        start = now if starttime is None else starttime
        end = now + 600 if endtime is None else endtime

        tgs_record = self.mods.database.get_principal(
            conn.cursor(),
            TGS_PRINCIPAL,
            resolve_alias=False,
        )
        session_key = generate_session_key(DEFAULT_ENCTYPE)
        plaintext = {
            "flags": list(DEFAULT_TICKET_FLAGS),
            "key": {"keytype": DEFAULT_ENCTYPE, "keyvalue": session_key},
            "realm": REALM,
            "client_principal": client_principal,
            "authtime": now,
            "starttime": start,
            "endtime": end,
            "renew_till": renew_till,
            "authorization_data": [],
        }
        tgt_der = encode_enc_ticket_part(plaintext)
        encrypted_tgt = encrypt(tgt_der, str_to_key(tgs_record["key"]), KEY_USAGE_TICKET)
        tgs_enctype = NAME_TO_ENCTYPE.get(tgs_record["enctype"], DEFAULT_ENCTYPE)
        return {
            "principal": client_principal,
            "response": {
                "tgt": encrypted_tgt,
                "tgt_enctype": tgs_enctype,
                "tgt_kvno": tgs_record["kvno"],
            },
            "enc_part": plaintext,
            "session_key": session_key,
        }

    def issue_service_ticket(
        self,
        conn,
        principal: str = "alice@DEMO.LOCAL",
        password: str = "alice_password",
        service_principal: str | None = None,
    ) -> dict:
        from core.asn1_codec import decode_enc_kdc_rep_part
        from core.crypto import KEY_USAGE_TGS_REP_ENCPART, decrypt
        from core.messages import APP_SERVICE_PRINCIPAL, TGS_REP

        tgt_bundle = self.issue_tgt(conn, principal=principal, password=password)
        nonce = secrets.randbits(31)
        request = self.make_tgs_req(
            tgt_bundle,
            nonce=nonce,
            service_principal=service_principal or APP_SERVICE_PRINCIPAL,
        )
        response = self.mods.tgs_handler.handle_tgs_request(request, conn.cursor())
        self.assertEqual(TGS_REP, response["msg_type"], response)

        decrypted = decrypt(
            response["encrypted_data"],
            tgt_bundle["session_key"],
            KEY_USAGE_TGS_REP_ENCPART,
        )
        enc_part = decode_enc_kdc_rep_part(decrypted, TGS_REP)
        self.assertEqual(nonce, enc_part["nonce"])
        return {
            "principal": principal,
            "service_principal": response["service_principal"],
            "response": response,
            "enc_part": enc_part,
            "session_key": enc_part["key"]["keyvalue"],
        }

    def make_ap_req(
        self,
        service_bundle: dict,
        service_principal: str | None = None,
        authenticator_principal: str | None = None,
        timestamp: float | None = None,
        include_subkey: bool = True,
    ) -> dict:
        from core.asn1_codec import encode_authenticator
        from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AP_REQ_AUTH, encrypt
        from core.messages import AP_REQ, REALM
        from core.replay_cache import current_kerberos_time

        if timestamp is None:
            _timestamp, ctime, cusec = current_kerberos_time()
        else:
            ctime = int(timestamp)
            cusec = int(round((timestamp - ctime) * 1_000_000))

        auth_plaintext = {
            "client_principal": authenticator_principal or service_bundle["principal"],
            "realm": REALM,
            "ctime": ctime,
            "cusec": cusec,
        }
        if include_subkey:
            auth_plaintext["subkey"] = {
                "keytype": DEFAULT_ENCTYPE,
                "keyvalue": secrets.token_bytes(32),
            }
            auth_plaintext["seq_number"] = secrets.randbits(30)

        authenticator = encrypt(
            encode_authenticator(auth_plaintext),
            service_bundle["session_key"],
            KEY_USAGE_AP_REQ_AUTH,
        )
        response = service_bundle["response"]
        return {
            "msg_type": AP_REQ,
            "service_principal": service_principal or response["service_principal"],
            "service_ticket": response["service_ticket"],
            "ticket_enctype": response["service_ticket_enctype"],
            "ticket_kvno": response["service_ticket_kvno"],
            "authenticator": authenticator,
            "authenticator_enctype": DEFAULT_ENCTYPE,
        }

    def send_ap_req_to_app_server(self, ap_req: dict) -> dict:
        from core.asn1_codec import decode_message, encode_message

        token = base64.b64encode(encode_message(ap_req)).decode("ascii")
        request_bytes = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            f"Authorization: Negotiate {token}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        raw_response = self._send_raw_http_request(request_bytes)
        status, headers, body = self._parse_http_response(raw_response)

        negotiate = headers.get("www-authenticate", "")
        decoded_token = None
        if negotiate.startswith("Negotiate "):
            decoded_token = decode_message(base64.b64decode(negotiate[len("Negotiate "):]))

        return {
            "status": status,
            "headers": headers,
            "body": body,
            "token": decoded_token,
        }

    def _send_raw_http_request(self, request_bytes: bytes) -> bytes:
        client_sock, server_sock = socket.socketpair()
        client_sock.settimeout(5)
        server_sock.settimeout(5)
        try:
            client_sock.sendall(request_bytes)
            client_sock.shutdown(socket.SHUT_WR)
            self.mods.service_server.NegotiateRequestHandler(
                server_sock,
                ("127.0.0.1", 0),
                object(),
            )
            server_sock.close()
            chunks = []
            while True:
                try:
                    chunk = client_sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            client_sock.close()
            try:
                server_sock.close()
            except OSError:
                pass

    def _parse_http_response(self, raw_response: bytes) -> tuple[int, dict[str, str], bytes]:
        head, _sep, body = raw_response.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return status, headers, body
