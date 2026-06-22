"""Verbose Kerberos security-flow demo.

This script prints the protocol messages and attack steps behind selected
regression cases. It uses a temporary runtime and does not touch the repository
database, keytab, or credential cache.
"""

from __future__ import annotations

import importlib
import base64
import os
import secrets
import socket
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def _fresh_modules(runtime: Path) -> SimpleNamespace:
    os.environ.update(
        {
            "KDC_DB_PATH": str(runtime / "kdc" / "database.db"),
            "APP_SERVER_KEYTAB": str(runtime / "app" / "fileserver.keytab"),
            "KRB5CCNAME": str(runtime / "client" / "krb5cc_demo"),
            "KRB_REPLAY_CACHE": str(runtime / "replay" / "replay.db"),
            "KDC_HOST": "127.0.0.1",
            "APP_SERVER_HOST": "127.0.0.1",
        }
    )
    module_names = [
        "kdc.database",
        "core.replay_cache",
        "kdc.as_handler",
        "kdc.tgs_handler",
        "app_server.service_server",
    ]
    modules = {}
    for name in module_names:
        module = importlib.import_module(name)
        modules[name] = importlib.reload(module)
    return SimpleNamespace(
        database=modules["kdc.database"],
        as_handler=modules["kdc.as_handler"],
        tgs_handler=modules["kdc.tgs_handler"],
        service_server=modules["app_server.service_server"],
    )


def _banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _step(text: str) -> None:
    print(f"\n[STEP] {text}")


def _msg(direction: str, name: str, fields: dict) -> None:
    print(f"[MSG]  {direction}: {name}")
    for key, value in fields.items():
        print(f"       - {key}: {value}")


def _result(status: str, detail: str) -> None:
    print(f"[RESULT] {status}: {detail}")


def _make_as_req(principal: str, password: str, nonce: int | None = None) -> tuple[dict, bytes]:
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
    preauth_plain = encode_pa_enc_timestamp({"ctime": ctime, "cusec": cusec})
    preauth = encrypt(
        preauth_plain,
        client_key,
        KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
    )
    request = {
        "msg_type": AS_REQ,
        "client_principal": principal,
        "realm": realm,
        "nonce": nonce if nonce is not None else secrets.randbits(31),
        "preauth": preauth,
        "preauth_enctype": DEFAULT_ENCTYPE,
        "kdc_options": ["renewable"],
    }
    return request, client_key


def _decrypt_as_rep(response: dict, client_key: bytes) -> dict:
    from core.asn1_codec import decode_enc_kdc_rep_part
    from core.crypto import KEY_USAGE_AS_REP_ENCPART, decrypt
    from core.messages import AS_REP

    decrypted = decrypt(
        response["encrypted_data"],
        client_key,
        KEY_USAGE_AS_REP_ENCPART,
    )
    return decode_enc_kdc_rep_part(decrypted, AS_REP)


def _issue_tgt(mods: SimpleNamespace, conn, principal: str = "alice@DEMO.LOCAL") -> dict:
    from core.messages import AS_REP

    nonce = secrets.randbits(31)
    as_req, client_key = _make_as_req(principal, "alice_password", nonce=nonce)
    response = mods.as_handler.handle_as_request(as_req, conn.cursor())
    if response.get("msg_type") != AS_REP:
        raise RuntimeError(f"AS failed: {response}")
    enc_part = _decrypt_as_rep(response, client_key)
    if enc_part.get("nonce") != nonce:
        raise RuntimeError("AS_REP nonce mismatch")
    return {
        "principal": principal,
        "as_req": as_req,
        "as_rep": response,
        "as_part": enc_part,
        "client_key": client_key,
        "session_key": enc_part["key"]["keyvalue"],
    }


def _make_tgs_req(
    tgt_bundle: dict,
    nonce: int | None = None,
    service_principal: str | None = None,
) -> dict:
    from core.asn1_codec import encode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REQ_AUTH, encrypt
    from core.messages import APP_SERVICE_PRINCIPAL, REALM, TGS_PRINCIPAL, TGS_REQ
    from core.replay_cache import current_kerberos_time

    _timestamp, ctime, cusec = current_kerberos_time()
    authenticator_plain = encode_authenticator(
        {
            "client_principal": tgt_bundle["principal"],
            "realm": REALM,
            "ctime": ctime,
            "cusec": cusec,
        }
    )
    authenticator = encrypt(
        authenticator_plain,
        tgt_bundle["session_key"],
        KEY_USAGE_TGS_REQ_AUTH,
    )
    as_rep = tgt_bundle["as_rep"]
    return {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": service_principal or APP_SERVICE_PRINCIPAL,
        "tgt": as_rep["tgt"],
        "tgt_service_principal": TGS_PRINCIPAL,
        "tgt_enctype": as_rep["tgt_enctype"],
        "tgt_kvno": as_rep["tgt_kvno"],
        "authenticator": authenticator,
        "authenticator_enctype": DEFAULT_ENCTYPE,
        "nonce": nonce if nonce is not None else secrets.randbits(31),
    }


def _issue_service_ticket(
    mods: SimpleNamespace,
    conn,
    principal: str = "alice@DEMO.LOCAL",
    password: str = "alice_password",
    service_principal: str | None = None,
) -> dict:
    from core.asn1_codec import decode_enc_kdc_rep_part
    from core.crypto import KEY_USAGE_TGS_REP_ENCPART, decrypt
    from core.messages import TGS_REP

    tgt_bundle = _issue_tgt(mods, conn, principal)
    tgs_req = _make_tgs_req(tgt_bundle, service_principal=service_principal)
    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    if response.get("msg_type") != TGS_REP:
        raise RuntimeError(f"TGS failed: {response}")

    decrypted = decrypt(
        response["encrypted_data"],
        tgt_bundle["session_key"],
        KEY_USAGE_TGS_REP_ENCPART,
    )
    enc_part = decode_enc_kdc_rep_part(decrypted, TGS_REP)
    return {
        "principal": principal,
        "service_principal": response["service_principal"],
        "response": response,
        "enc_part": enc_part,
        "session_key": enc_part["key"]["keyvalue"],
    }


def _make_ap_req(service_bundle: dict, service_principal: str | None = None) -> dict:
    from core.asn1_codec import encode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AP_REQ_AUTH, encrypt
    from core.messages import AP_REQ, REALM
    from core.replay_cache import current_kerberos_time

    _timestamp, ctime, cusec = current_kerberos_time()
    authenticator = encrypt(
        encode_authenticator(
            {
                "client_principal": service_bundle["principal"],
                "realm": REALM,
                "ctime": ctime,
                "cusec": cusec,
                "subkey": {
                    "keytype": DEFAULT_ENCTYPE,
                    "keyvalue": secrets.token_bytes(32),
                },
                "seq_number": secrets.randbits(30),
            }
        ),
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


def _send_ap_req_to_app_server(mods: SimpleNamespace, ap_req: dict) -> dict:
    from core.asn1_codec import decode_message, encode_message

    token = base64.b64encode(encode_message(ap_req)).decode("ascii")
    request_bytes = (
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        f"Authorization: Negotiate {token}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    client_sock, server_sock = socket.socketpair()
    client_sock.settimeout(5)
    server_sock.settimeout(5)
    try:
        client_sock.sendall(request_bytes)
        client_sock.shutdown(socket.SHUT_WR)
        mods.service_server.NegotiateRequestHandler(
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
    finally:
        client_sock.close()
        try:
            server_sock.close()
        except OSError:
            pass

    raw_response = b"".join(chunks)
    head, _sep, body = raw_response.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    token_msg = None
    negotiate = headers.get("www-authenticate", "")
    if negotiate.startswith("Negotiate "):
        token_msg = decode_message(base64.b64decode(negotiate[len("Negotiate "):]))
    return {"status": status, "headers": headers, "body": body, "token": token_msg}


def scenario_normal_flow(mods: SimpleNamespace, conn) -> None:
    from core.messages import TGS_REP

    _banner("SCENARIO 1 - Normal AS -> TGS flow")
    _step("Client derives Kc locally from password and sends AS_REQ. Password is not sent.")
    nonce = secrets.randbits(31)
    as_req, client_key = _make_as_req("alice@DEMO.LOCAL", "alice_password", nonce=nonce)
    _msg(
        "Client -> AS",
        "AS_REQ",
        {
            "client_principal": as_req["client_principal"],
            "realm": as_req["realm"],
            "nonce": as_req["nonce"],
            "preauth": f"EncryptedData len={len(as_req['preauth'])}",
        },
    )
    as_rep = mods.as_handler.handle_as_request(as_req, conn.cursor())
    _msg(
        "AS -> Client",
        as_rep["msg_type"],
        {
            "client_principal": as_rep.get("client_principal"),
            "server_principal": as_rep.get("server_principal"),
            "tgt_kvno": as_rep.get("tgt_kvno"),
            "tgt": f"cipher len={len(as_rep.get('tgt', b''))}",
        },
    )
    as_part = _decrypt_as_rep(as_rep, client_key)
    _step("Client decrypts AS_REP client part with Kc and checks nonce.")
    _result("ALLOWED", f"nonce ok={as_part.get('nonce') == nonce}; Kc_tgs established")

    bundle = {
        "principal": "alice@DEMO.LOCAL",
        "as_rep": as_rep,
        "as_part": as_part,
        "client_key": client_key,
        "session_key": as_part["key"]["keyvalue"],
    }
    tgs_req = _make_tgs_req(bundle)
    _msg(
        "Client -> TGS",
        "TGS_REQ",
        {
            "service_principal": tgs_req["service_principal"],
            "tgt_kvno": tgs_req["tgt_kvno"],
            "tgt": f"cipher len={len(tgs_req['tgt'])}",
            "authenticator": f"EncryptedData len={len(tgs_req['authenticator'])}",
        },
    )
    tgs_rep = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _msg(
        "TGS -> Client",
        tgs_rep["msg_type"],
        {
            "service_principal": tgs_rep.get("service_principal"),
            "service_ticket_kvno": tgs_rep.get("service_ticket_kvno"),
        },
    )
    _result("ALLOWED", f"TGS returned {tgs_rep['msg_type'] == TGS_REP}")


def scenario_wrong_password(mods: SimpleNamespace, conn) -> None:
    _banner("SCENARIO 2 - Attack: wrong password / forged pre-auth")
    _step("Attacker guesses alice's password incorrectly and encrypts PA-ENC-TIMESTAMP with the wrong key.")
    as_req, _wrong_key = _make_as_req("alice@DEMO.LOCAL", "wrong_password")
    _msg(
        "Attacker -> AS",
        "AS_REQ",
        {
            "client_principal": as_req["client_principal"],
            "preauth": f"EncryptedData len={len(as_req['preauth'])} encrypted with wrong Kc",
        },
    )
    response = mods.as_handler.handle_as_request(as_req, conn.cursor())
    _msg("AS -> Attacker", response["msg_type"], {"error_code": response.get("error_code")})
    blocked = response.get("error_code") == "KDC_ERR_PREAUTH_FAILED"
    _result("BLOCKED" if blocked else "UNEXPECTED", "AS cannot decrypt pre-auth with stored Kc")


def scenario_account_lockout(mods: SimpleNamespace, conn) -> None:
    from core.messages import AUTH_FAILURE_THRESHOLD

    _banner("SCENARIO 3 - Defense: account lockout after repeated bad pre-auth")
    _step("Attacker repeatedly sends bad AS_REQ for bob. KDC counts failed pre-auth attempts.")

    response = None
    for attempt in range(1, AUTH_FAILURE_THRESHOLD + 1):
        as_req, _wrong_key = _make_as_req("bob@DEMO.LOCAL", "wrong_password")
        response = mods.as_handler.handle_as_request(as_req, conn.cursor())
        _msg(
            f"Attacker -> AS attempt {attempt}",
            "AS_REQ",
            {
                "client_principal": "bob@DEMO.LOCAL",
                "preauth": "encrypted with wrong Kc",
            },
        )
        _msg(
            "AS -> Attacker",
            response["msg_type"],
            {"error_code": response.get("error_code")},
        )

    _step("Attacker now tries the real password while the principal is locked.")
    valid_req, _client_key = _make_as_req("bob@DEMO.LOCAL", "bob_password")
    valid_response = mods.as_handler.handle_as_request(valid_req, conn.cursor())
    _msg(
        "Client -> AS",
        "AS_REQ with correct password",
        {"client_principal": "bob@DEMO.LOCAL"},
    )
    _msg(
        "AS -> Client",
        valid_response["msg_type"],
        {"error_code": valid_response.get("error_code")},
    )
    blocked = valid_response.get("error_code") == "KDC_ERR_CLIENT_REVOKED"
    _result("BLOCKED" if blocked else "UNEXPECTED", "AS temporarily rejects even valid pre-auth until lockout expires")


def scenario_tampered_tgt(mods: SimpleNamespace, conn) -> None:
    _banner("SCENARIO 4 - Attack: tampered TGT")
    bundle = _issue_tgt(mods, conn)
    tgs_req = _make_tgs_req(bundle)
    tampered = bytearray(tgs_req["tgt"])
    tampered[-1] ^= 0x01
    tgs_req["tgt"] = bytes(tampered)

    _step("Attacker flips one byte in the encrypted TGT before it reaches TGS.")
    _msg(
        "Attacker -> TGS",
        "TGS_REQ",
        {
            "tgt_kvno": tgs_req["tgt_kvno"],
            "tampered_tgt": f"cipher len={len(tgs_req['tgt'])}, one byte modified",
            "authenticator": f"EncryptedData len={len(tgs_req['authenticator'])}",
        },
    )
    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _msg("TGS -> Attacker", response["msg_type"], {"error_code": response.get("error_code")})
    blocked = response.get("error_code") == "KRB_AP_ERR_MODIFIED"
    _result("BLOCKED" if blocked else "UNEXPECTED", "Ticket decrypt/integrity check failed")


def scenario_replay_tgs_authenticator(mods: SimpleNamespace, conn) -> None:
    _banner("SCENARIO 5 - Attack: replayed TGS authenticator")
    bundle = _issue_tgt(mods, conn)
    tgs_req = _make_tgs_req(bundle)

    _step("Legitimate client sends a fresh TGS_REQ first.")
    first = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _msg("TGS -> Client", first["msg_type"], {"service_principal": first.get("service_principal")})

    _step("Attacker replays the exact same TGS_REQ with the same authenticator ctime/cusec.")
    second = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _msg("TGS -> Attacker", second["msg_type"], {"error_code": second.get("error_code")})
    blocked = second.get("error_code") == "KRB_AP_ERR_REPEAT"
    _result("BLOCKED" if blocked else "UNEXPECTED", "Replay cache already has this authenticator fingerprint")


def scenario_ap_replay_authenticator(mods: SimpleNamespace, conn) -> None:
    _banner("SCENARIO 6 - Attack: replayed AP authenticator at Application Server")
    service_bundle = _issue_service_ticket(mods, conn)
    ap_req = _make_ap_req(service_bundle)

    _step("Legitimate client sends AP_REQ over HTTP Authorization: Negotiate.")
    _msg(
        "Client -> App Server",
        "AP_REQ",
        {
            "service_principal": ap_req["service_principal"],
            "ticket_kvno": ap_req["ticket_kvno"],
            "service_ticket": f"EncryptedData len={len(ap_req['service_ticket'])}",
            "authenticator": f"EncryptedData len={len(ap_req['authenticator'])}",
        },
    )
    first = _send_ap_req_to_app_server(mods, ap_req)
    _msg(
        "App Server -> Client",
        f"HTTP {first['status']}",
        {"token": first["token"]["msg_type"] if first.get("token") else "none"},
    )

    _step("Attacker replays the exact same AP_REQ with the same authenticator ctime/cusec.")
    second = _send_ap_req_to_app_server(mods, ap_req)
    token = second.get("token") or {}
    _msg(
        "App Server -> Attacker",
        f"HTTP {second['status']}",
        {"error_code": token.get("error_code")},
    )
    blocked = second["status"] == 403 and token.get("error_code") == "KRB_AP_ERR_REPEAT"
    _result("BLOCKED" if blocked else "UNEXPECTED", "Application Server replay cache rejects reused AP authenticator")


def scenario_ap_tampered_service_ticket(mods: SimpleNamespace, conn) -> None:
    _banner("SCENARIO 7 - Attack: tampered service ticket at Application Server")
    service_bundle = _issue_service_ticket(mods, conn)
    ap_req = _make_ap_req(service_bundle)
    tampered = bytearray(ap_req["service_ticket"])
    tampered[-1] ^= 0x01
    ap_req["service_ticket"] = bytes(tampered)

    _step("Attacker flips one byte in the encrypted service ticket before AP_REQ reaches the service.")
    _msg(
        "Attacker -> App Server",
        "AP_REQ",
        {
            "service_principal": ap_req["service_principal"],
            "tampered_service_ticket": f"cipher len={len(ap_req['service_ticket'])}, one byte modified",
            "authenticator": f"EncryptedData len={len(ap_req['authenticator'])}",
        },
    )
    response = _send_ap_req_to_app_server(mods, ap_req)
    token = response.get("token") or {}
    _msg(
        "App Server -> Attacker",
        f"HTTP {response['status']}",
        {"error_code": token.get("error_code")},
    )
    blocked = response["status"] == 403 and token.get("error_code") == "KRB_AP_ERR_MODIFIED"
    _result("BLOCKED" if blocked else "UNEXPECTED", "Service ticket decrypt/integrity check failed")


def scenario_ap_wrong_service_with_multi_keytab(mods: SimpleNamespace, conn) -> None:
    from core.keytab import write_keytab

    _banner("SCENARIO 8 - Attack: wrong-service AP_REQ with multi-service keytab")
    _step("Admin adds a second service key to the same keytab to prove keytab lookup is not the issue.")
    mail_record = mods.database.upsert_principal(
        conn,
        "mailserver/localhost@DEMO.LOCAL",
        "mailserver_secret",
        "service",
        groups="[]",
    )
    write_keytab(
        mods.database.DEFAULT_KEYTAB_PATH,
        mail_record["principal_name"],
        mail_record["key"],
        mail_record["kvno"],
        mail_record["enctype"],
        mail_record["realm"],
    )
    conn.commit()
    _msg(
        "Admin -> keytab",
        "write_keytab",
        {
            "existing_service": "fileserver/localhost@DEMO.LOCAL",
            "added_service": mail_record["principal_name"],
            "keytab": mods.database.DEFAULT_KEYTAB_PATH,
        },
    )

    service_bundle = _issue_service_ticket(mods, conn)
    ap_req = _make_ap_req(service_bundle, service_principal="mailserver/localhost@DEMO.LOCAL")
    _step("Attacker changes the outer AP_REQ service principal to mailserver but keeps a fileserver ticket.")
    _msg(
        "Attacker -> App Server",
        "AP_REQ",
        {
            "outer_service_principal": ap_req["service_principal"],
            "ticket_was_issued_for": service_bundle["service_principal"],
            "keytab_contains": "fileserver and mailserver",
        },
    )
    response = _send_ap_req_to_app_server(mods, ap_req)
    token = response.get("token") or {}
    _msg(
        "App Server -> Attacker",
        f"HTTP {response['status']}",
        {"error_code": token.get("error_code")},
    )
    blocked = response["status"] == 403 and token.get("error_code") == "KRB_AP_ERR_MODIFIED"
    _result("BLOCKED" if blocked else "UNEXPECTED", "A service ticket cannot be reused for another service")


def scenario_key_rotation(mods: SimpleNamespace, conn) -> None:
    from core.messages import TGS_PRINCIPAL, TGS_REP

    _banner("SCENARIO 9 - Key rotation: old TGT still valid by kvno")
    bundle = _issue_tgt(mods, conn)
    old_kvno = bundle["as_rep"]["tgt_kvno"]

    _step("Admin rotates krbtgt long-term key after the TGT has already been issued.")
    cursor = conn.cursor()
    old_tgs = mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
    rotated = mods.database.upsert_principal(
        conn,
        TGS_PRINCIPAL,
        "rotated_tgs_secret_for_verbose_demo",
        old_tgs["principal_type"],
        kvno=int(old_tgs["kvno"]) + 1,
        groups=old_tgs.get("groups", "[]"),
    )
    conn.commit()
    _msg(
        "Admin -> KDC DB",
        "kadmin cpw",
        {
            "old_tgt_kvno": old_kvno,
            "current_krbtgt_kvno": rotated["kvno"],
            "history_table": "principal_keys keeps old kvno",
        },
    )

    _step("Client uses the old TGT. TGS reads tgt_kvno and selects the old key from key history.")
    tgs_req = _make_tgs_req(bundle)
    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _msg(
        "TGS -> Client",
        response["msg_type"],
        {
            "request_tgt_kvno": tgs_req["tgt_kvno"],
            "current_krbtgt_kvno": rotated["kvno"],
        },
    )
    allowed = response.get("msg_type") == TGS_REP
    _result("ALLOWED" if allowed else "UNEXPECTED", "Old, unexpired TGT remains usable because kvno selects old key")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="krb-flow-demo-", ignore_cleanup_errors=True) as temp_dir:
        runtime = Path(temp_dir)
        print(f"[INFO] Temporary runtime: {runtime}")
        mods = _fresh_modules(runtime)
        mods.database.init_database()
        conn = mods.database.connect()
        try:
            scenario_normal_flow(mods, conn)
            scenario_wrong_password(mods, conn)
            scenario_account_lockout(mods, conn)
            scenario_tampered_tgt(mods, conn)
            scenario_replay_tgs_authenticator(mods, conn)
            scenario_ap_replay_authenticator(mods, conn)
            scenario_ap_tampered_service_ticket(mods, conn)
            scenario_ap_wrong_service_with_multi_keytab(mods, conn)
            scenario_key_rotation(mods, conn)
        finally:
            conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
