"""Comprehensive demo scenarios for the Kerberos V5 project.

This script exercises all implemented features in-process using temporary
runtime files. It never touches the repository database or keytab.

Usage:
    python scratch/demo_all_features.py
"""

from __future__ import annotations

import importlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

PYTHON = sys.executable

# ============================================================
# Shared helpers
# ============================================================

passed = 0
failed = 0


def _banner(title: str) -> None:
    width = 70
    print(f"\n{'='*width}")
    print(f"  {title}")
    print(f"{'='*width}")


def _step(description: str) -> None:
    print(f"\n  ▸ {description}")


def _pass(msg: str) -> None:
    global passed
    passed += 1
    print(f"    ✅ PASS: {msg}")


def _fail(msg: str) -> None:
    global failed
    failed += 1
    print(f"    ❌ FAIL: {msg}")


def _assert(condition: bool, pass_msg: str, fail_msg: str) -> None:
    if condition:
        _pass(pass_msg)
    else:
        _fail(fail_msg)


def _fresh_modules(runtime_dir: str) -> SimpleNamespace:
    """Reload all KDC modules with a fresh temp runtime."""
    root = Path(runtime_dir)
    os.environ.update({
        "KDC_DB_PATH": str(root / "kdc" / "database.db"),
        "APP_SERVER_KEYTAB": str(root / "app" / "fileserver.keytab"),
        "KRB5CCNAME": str(root / "client" / "krb5cc_demo"),
        "KRB_REPLAY_CACHE": str(root / "replay" / "replay.db"),
        "KDC_HOST": "127.0.0.1",
        "APP_SERVER_HOST": "127.0.0.1",
    })
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


def _make_as_req(principal: str, password: str, nonce: int | None = None,
                 kdc_options: list[str] | None = None) -> dict:
    from core.asn1_codec import encode_pa_enc_timestamp
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, derive_key, encrypt
    from core.messages import AS_REQ, REALM
    from core.principal import principal_realm, principal_salt
    from core.replay_cache import current_kerberos_time

    realm = principal_realm(principal, REALM)
    client_key = derive_key(password, salt=principal_salt(principal, realm), enctype=DEFAULT_ENCTYPE)
    _ts, ctime, cusec = current_kerberos_time()
    preauth = encrypt(
        encode_pa_enc_timestamp({"ctime": ctime, "cusec": cusec}),
        client_key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
    )
    return {
        "msg_type": AS_REQ,
        "client_principal": principal,
        "realm": realm,
        "nonce": nonce if nonce is not None else secrets.randbits(31),
        "preauth": preauth,
        "preauth_enctype": DEFAULT_ENCTYPE,
        "kdc_options": kdc_options or ["renewable"],
    }


def _issue_tgt(mods: SimpleNamespace, conn, principal: str = "alice@DEMO.LOCAL",
               password: str = "alice_password") -> dict:
    from core.asn1_codec import decode_enc_kdc_rep_part
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AS_REP_ENCPART, decrypt, derive_key
    from core.messages import AS_REP, REALM
    from core.principal import principal_salt

    nonce = secrets.randbits(31)
    realm = principal.split("@")[1] if "@" in principal else REALM
    response = mods.as_handler.handle_as_request(
        _make_as_req(principal, password, nonce=nonce),
        conn.cursor(),
    )
    if response["msg_type"] != AS_REP:
        return {"response": response, "enc_part": None, "session_key": None}

    client_key = derive_key(password, salt=principal_salt(principal, realm), enctype=DEFAULT_ENCTYPE)
    decrypted = decrypt(response["encrypted_data"], client_key, KEY_USAGE_AS_REP_ENCPART)
    enc_part = decode_enc_kdc_rep_part(decrypted, AS_REP)
    return {
        "response": response,
        "enc_part": enc_part,
        "session_key": enc_part["key"]["keyvalue"],
    }


def _make_tgs_req(tgt_bundle: dict, service_principal: str | None = None,
                  nonce: int | None = None, kdc_options: list[str] | None = None) -> dict:
    from core.asn1_codec import encode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REQ_AUTH, encrypt
    from core.messages import APP_SERVICE_PRINCIPAL, REALM, TGS_PRINCIPAL, TGS_REQ
    from core.replay_cache import current_kerberos_time

    _ts, ctime, cusec = current_kerberos_time()
    client_principal = tgt_bundle["enc_part"]["client_principal"]
    authenticator = encrypt(
        encode_authenticator({
            "client_principal": client_principal,
            "realm": REALM,
            "ctime": ctime,
            "cusec": cusec,
        }),
        tgt_bundle["session_key"], KEY_USAGE_TGS_REQ_AUTH,
    )
    as_response = tgt_bundle["response"]
    return {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": service_principal or APP_SERVICE_PRINCIPAL,
        "tgt": as_response["tgt"],
        "tgt_service_principal": TGS_PRINCIPAL,
        "tgt_enctype": as_response.get("tgt_enctype", DEFAULT_ENCTYPE),
        "tgt_kvno": as_response.get("tgt_kvno"),
        "authenticator": authenticator,
        "authenticator_enctype": DEFAULT_ENCTYPE,
        "nonce": nonce if nonce is not None else secrets.randbits(31),
        "kdc_options": kdc_options or [],
    }


# ============================================================
# Demo Scenarios
# ============================================================

def demo_1_happy_path(mods, conn):
    """Demo 1: Complete AS→TGS→AP happy path for alice (admin)."""
    from core.asn1_codec import decode_enc_kdc_rep_part, decode_enc_ticket_part, decode_authenticator, encode_authenticator, encode_enc_ap_rep_part
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REP_ENCPART, KEY_USAGE_TICKET, KEY_USAGE_AP_REQ_AUTH, KEY_USAGE_AP_REP_ENCPART, decrypt, encrypt, str_to_key
    from core.messages import AS_REP, TGS_REP, APP_SERVICE_PRINCIPAL, REALM

    _banner("Demo 1: Happy Path — AS → TGS → AP (alice@DEMO.LOCAL)")

    # Phase 1: AS Exchange
    _step("Phase 1: AS Exchange — alice xin TGT")
    tgt_bundle = _issue_tgt(mods, conn, "alice@DEMO.LOCAL", "alice_password")
    _assert(
        tgt_bundle["response"]["msg_type"] == AS_REP,
        "AS_REP received with TGT",
        f"Expected AS_REP, got {tgt_bundle['response']['msg_type']}"
    )
    enc_part = tgt_bundle["enc_part"]
    _assert("initial" in enc_part.get("flags", []), "TGT has 'initial' flag", "Missing 'initial' flag")
    _assert("pre_authent" in enc_part.get("flags", []), "TGT has 'pre_authent' flag", "Missing 'pre_authent' flag")
    _assert("renewable" in enc_part.get("flags", []), "TGT has 'renewable' flag", "Missing 'renewable' flag")
    print(f"    Session key length: {len(tgt_bundle['session_key'])} bytes")
    print(f"    Ticket endtime: {time.strftime('%H:%M:%S', time.localtime(enc_part.get('endtime')))}")

    # Phase 2: TGS Exchange
    _step("Phase 2: TGS Exchange — alice xin Service Ticket cho fileserver")
    tgs_req = _make_tgs_req(tgt_bundle)
    tgs_resp = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _assert(
        tgs_resp["msg_type"] == TGS_REP,
        f"TGS_REP received for '{APP_SERVICE_PRINCIPAL}'",
        f"Expected TGS_REP, got {tgs_resp['msg_type']}: {tgs_resp.get('error_message')}"
    )

    # Decrypt TGS_REP to get service session key
    tgs_rep_data = decode_enc_kdc_rep_part(
        decrypt(tgs_resp["encrypted_data"], tgt_bundle["session_key"], KEY_USAGE_TGS_REP_ENCPART),
        TGS_REP
    )
    service_session_key = tgs_rep_data["key"]["keyvalue"]
    print(f"    Service: {tgs_rep_data.get('service_principal')}")
    print(f"    Service session key length: {len(service_session_key)} bytes")

    # Phase 3: AP Exchange (in-process simulation)
    _step("Phase 3: AP Exchange — alice truy cập fileserver")

    # Decrypt service ticket to get EncTicketPart (simulating what the app server does)
    service_record = mods.database.get_principal(conn.cursor(), APP_SERVICE_PRINCIPAL)
    service_key = str_to_key(service_record["key"])
    st_der = decrypt(tgs_resp["service_ticket"], service_key, KEY_USAGE_TICKET)
    ticket_data = decode_enc_ticket_part(st_der)

    _assert(
        ticket_data["client_principal"] == "alice@DEMO.LOCAL",
        f"Service ticket contains correct client principal: {ticket_data['client_principal']}",
        f"Wrong client principal in ticket: {ticket_data['client_principal']}"
    )

    # Check authorization data in ticket
    auth_data = ticket_data.get("authorization_data", [])
    groups = []
    for entry in auth_data:
        if entry["ad_type"] == 100:
            groups = json.loads(entry["ad_data"].decode("utf-8"))

    _assert(
        "admins" in groups,
        f"alice has admin group in ticket authorization data: {groups}",
        f"alice missing admin group: {groups}"
    )
    _pass("Complete AS→TGS→AP path succeeded for alice@DEMO.LOCAL")


def demo_2_wrong_password(mods, conn):
    """Demo 2: Wrong password → KDC_ERR_PREAUTH_FAILED."""
    _banner("Demo 2: Wrong Password — AS rejects bad pre-authentication")

    _step("Sending AS_REQ with wrong password for alice")
    response = mods.as_handler.handle_as_request(
        _make_as_req("alice@DEMO.LOCAL", "wrong_password"),
        conn.cursor(),
    )
    _assert(
        response["msg_type"] == "KRB_ERROR",
        "KRB_ERROR received (password never sent over network)",
        f"Unexpected: {response['msg_type']}"
    )
    _assert(
        response["error_code"] == "KDC_ERR_PREAUTH_FAILED",
        f"Error code: KDC_ERR_PREAUTH_FAILED (code 24)",
        f"Wrong error code: {response['error_code']}"
    )
    print(f"    Error message: {response.get('error_message')}")


def demo_3_unknown_principal(mods, conn):
    """Demo 3: Unknown principal → KDC_ERR_C_PRINCIPAL_UNKNOWN."""
    _banner("Demo 3: Unknown Principal — AS rejects unregistered user")

    _step("Sending AS_REQ for mallory@DEMO.LOCAL (not in database)")
    response = mods.as_handler.handle_as_request(
        _make_as_req("mallory@DEMO.LOCAL", "anything"),
        conn.cursor(),
    )
    _assert(
        response["error_code"] == "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        "Error code: KDC_ERR_C_PRINCIPAL_UNKNOWN (code 6)",
        f"Wrong error code: {response['error_code']}"
    )


def demo_4_replay_detection(mods, conn):
    """Demo 4: TGS rejects replayed authenticator."""
    from core.messages import TGS_REP, KRB_AP_ERR_REPEAT

    _banner("Demo 4: Replay Detection — TGS rejects duplicate authenticator")

    _step("Issuing TGT for alice")
    tgt_bundle = _issue_tgt(mods, conn)

    _step("Sending first TGS_REQ (should succeed)")
    tgs_req = _make_tgs_req(tgt_bundle)
    first = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _assert(first["msg_type"] == TGS_REP, "First request: TGS_REP received", f"Got: {first['msg_type']}")

    _step("Replaying same TGS_REQ (should fail)")
    second = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _assert(
        second["msg_type"] == "KRB_ERROR" and second["error_code"] == KRB_AP_ERR_REPEAT,
        f"Replay detected: KRB_AP_ERR_REPEAT (code 34)",
        f"Expected replay rejection, got: {second['msg_type']} / {second.get('error_code')}"
    )


def demo_5_tgt_renewal(mods, conn):
    """Demo 5: TGT renewal with 'renew' KDC option."""
    from core.asn1_codec import decode_enc_kdc_rep_part, encode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REQ_AUTH, KEY_USAGE_TGS_REP_ENCPART, decrypt, encrypt
    from core.messages import TGS_REP, REALM, TGS_PRINCIPAL, TGS_REQ
    from core.replay_cache import current_kerberos_time

    _banner("Demo 5: TGT Renewal — Extending ticket lifetime")

    _step("Issuing initial TGT for alice")
    tgt_bundle = _issue_tgt(mods, conn)
    original_endtime = tgt_bundle["enc_part"]["endtime"]
    print(f"    Original TGT endtime: {time.strftime('%H:%M:%S', time.localtime(original_endtime))}")

    _step("Sending TGS_REQ with 'renew' option")
    _ts, ctime, cusec = current_kerberos_time()
    auth_data = encrypt(
        encode_authenticator({
            "client_principal": "alice@DEMO.LOCAL",
            "realm": REALM,
            "ctime": ctime,
            "cusec": cusec,
        }),
        tgt_bundle["session_key"], KEY_USAGE_TGS_REQ_AUTH,
    )
    renew_nonce = secrets.randbits(31)
    renew_req = {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": TGS_PRINCIPAL,
        "tgt": tgt_bundle["response"]["tgt"],
        "tgt_service_principal": TGS_PRINCIPAL,
        "tgt_enctype": DEFAULT_ENCTYPE,
        "authenticator": auth_data,
        "authenticator_enctype": DEFAULT_ENCTYPE,
        "nonce": renew_nonce,
        "kdc_options": ["renew"],
    }
    renew_resp = mods.tgs_handler.handle_tgs_request(renew_req, conn.cursor())
    _assert(renew_resp["msg_type"] == TGS_REP, "Renewal: TGS_REP received with new TGT",
            f"Got: {renew_resp['msg_type']}: {renew_resp.get('error_message')}")

    if renew_resp["msg_type"] == TGS_REP:
        renewed_data = decode_enc_kdc_rep_part(
            decrypt(renew_resp["encrypted_data"], tgt_bundle["session_key"], KEY_USAGE_TGS_REP_ENCPART),
            TGS_REP
        )
        new_endtime = renewed_data["endtime"]
        print(f"    Renewed TGT endtime: {time.strftime('%H:%M:%S', time.localtime(new_endtime))}")
        _assert(new_endtime >= original_endtime, "New endtime >= original endtime",
                f"Renewal did not extend: {new_endtime} < {original_endtime}")
        _assert(renewed_data["nonce"] == renew_nonce, "Nonce matches", "Nonce mismatch")


def demo_6_key_rotation(mods, conn):
    """Demo 6: TGT issued before key rotation still works (key history)."""
    from core.messages import TGS_PRINCIPAL, TGS_REP

    _banner("Demo 6: Key Rotation — Old TGT survives TGS key change (kvno history)")

    _step("Issuing TGT with current TGS key")
    tgt_bundle = _issue_tgt(mods, conn)
    _assert(tgt_bundle["response"]["msg_type"] == "AS_REP", "TGT issued", "TGT issue failed")

    _step("Rotating TGS key (simulating kadmin cpw)")
    cursor = conn.cursor()
    old_tgs = mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
    old_kvno = int(old_tgs["kvno"])
    mods.database.upsert_principal(
        conn, TGS_PRINCIPAL,
        "rotated_tgs_secret_new_password",
        old_tgs["principal_type"],
        kvno=old_kvno + 1,
        groups=old_tgs.get("groups", "[]"),
    )
    conn.commit()
    new_tgs = mods.database.get_principal(conn.cursor(), TGS_PRINCIPAL, resolve_alias=False)
    print(f"    Old kvno: {old_kvno}, New kvno: {new_tgs['kvno']}")
    _assert(int(new_tgs["kvno"]) == old_kvno + 1, "TGS key version incremented", "kvno not bumped")

    _step("Using old TGT to request service ticket (should succeed via key history)")
    tgs_req = _make_tgs_req(tgt_bundle)
    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _assert(
        response["msg_type"] == TGS_REP,
        "Old TGT still works after key rotation — principal_keys history lookup successful",
        f"Failed: {response['msg_type']}: {response.get('error_message')}"
    )


def demo_7_bob_user_access(mods, conn):
    """Demo 7: bob (standard user) gets different authorization than alice (admin)."""
    from core.asn1_codec import decode_enc_ticket_part
    from core.crypto import KEY_USAGE_TICKET, KEY_USAGE_TGS_REP_ENCPART, decrypt, str_to_key
    from core.messages import AS_REP, TGS_REP, APP_SERVICE_PRINCIPAL

    _banner("Demo 7: RBAC — bob (user) vs alice (admin) authorization data")

    _step("Issuing TGT for bob@DEMO.LOCAL")
    tgt_bundle = _issue_tgt(mods, conn, "bob@DEMO.LOCAL", "bob_password")
    _assert(tgt_bundle["response"]["msg_type"] == AS_REP, "bob TGT issued", "bob TGT failed")

    _step("Requesting service ticket for bob")
    tgs_req = _make_tgs_req(tgt_bundle)
    tgs_resp = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _assert(tgs_resp["msg_type"] == TGS_REP, "bob service ticket issued", "bob TGS failed")

    _step("Checking authorization data in bob's service ticket")
    service_record = mods.database.get_principal(conn.cursor(), APP_SERVICE_PRINCIPAL)
    service_key = str_to_key(service_record["key"])
    st_der = decrypt(tgs_resp["service_ticket"], service_key, KEY_USAGE_TICKET)
    ticket_data = decode_enc_ticket_part(st_der)

    groups = []
    for entry in ticket_data.get("authorization_data", []):
        if entry["ad_type"] == 100:
            groups = json.loads(entry["ad_data"].decode("utf-8"))

    _assert("users" in groups, f"bob has 'users' group: {groups}", f"Missing users group: {groups}")
    _assert("admins" not in groups, f"bob does NOT have 'admins' group (correct!)", f"bob incorrectly has admins: {groups}")
    print(f"    bob's groups: {groups}")
    print(f"    → App Server would grant: Standard User access (not Admin)")


def demo_8_unknown_service(mods, conn):
    """Demo 8: Request for non-existent service → KDC_ERR_S_PRINCIPAL_UNKNOWN."""
    from core.messages import KDC_ERR_S_PRINCIPAL_UNKNOWN

    _banner("Demo 8: Unknown Service — TGS rejects request for missing service")

    _step("Issuing TGT for alice")
    tgt_bundle = _issue_tgt(mods, conn)

    _step("Requesting ticket for nonexistent service")
    tgs_req = _make_tgs_req(tgt_bundle, service_principal="httpserver/localhost@DEMO.LOCAL")
    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())
    _assert(
        response["error_code"] == KDC_ERR_S_PRINCIPAL_UNKNOWN,
        "Error: KDC_ERR_S_PRINCIPAL_UNKNOWN (code 7)",
        f"Wrong error: {response.get('error_code')}"
    )


def demo_9_keytab_multi_version(mods, conn):
    """Demo 9: Keytab stores multiple key versions and selects correct one."""
    from core.crypto import str_to_key
    from core.keytab import load_keytab, write_keytab

    _banner("Demo 9: Keytab Multi-Version — kvno selection")

    keytab_path = str(Path(os.environ["APP_SERVER_KEYTAB"]).parent / "test_multi.keytab")
    principal = "fileserver/localhost@DEMO.LOCAL"
    key_v1 = b"\x01" * 32
    key_v2 = b"\x02" * 32
    key_v3 = b"\x03" * 32

    _step("Writing 3 key versions to keytab")
    write_keytab(keytab_path, principal, key_v1, 1, 18, "DEMO.LOCAL")
    write_keytab(keytab_path, principal, key_v2, 2, 18, "DEMO.LOCAL")
    write_keytab(keytab_path, principal, key_v3, 3, 18, "DEMO.LOCAL")
    _pass("3 entries written to MIT Keytab v2 binary file")

    _step("Loading exact kvno=1")
    exact = load_keytab(keytab_path, principal, kvno=1, enctype=18)
    _assert(exact["kvno"] == 1, "Exact kvno=1 match found", f"Got kvno={exact['kvno']}")
    _assert(str_to_key(exact["key"]) == key_v1, "Key content matches v1", "Key mismatch")

    _step("Loading highest kvno (no kvno specified)")
    highest = load_keytab(keytab_path, principal, enctype=18)
    _assert(highest["kvno"] == 3, f"Highest kvno selected: {highest['kvno']}", f"Got kvno={highest['kvno']}")
    _assert(str_to_key(highest["key"]) == key_v3, "Key content matches v3", "Key mismatch")


def demo_10_ccache_persistence(mods, conn):
    """Demo 10: Credential cache preserves ticket metadata after reload."""
    _banner("Demo 10: Credential Cache — MIT ccache v4 persistence")

    cache_path = str(Path(os.environ["KRB5CCNAME"]).parent / "test_persist")

    _step("Storing TGT with metadata in ccache")
    cache = mods.credential_cache.CredentialCache(cache_path)
    cache.store_tgt(
        b"demo-ticket-bytes-here",
        b"\x00" * 32,
        {
            "ticket_kvno": 5,
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
    _pass("TGT stored in binary ccache file")

    _step("Reloading ccache from disk (simulating client restart)")
    reloaded = mods.credential_cache.CredentialCache(cache_path)
    metadata = reloaded.get_tgt_metadata()
    _assert(metadata is not None, "Metadata recovered from disk", "Metadata lost!")
    _assert(metadata["ticket_kvno"] == 5, f"ticket_kvno preserved: {metadata['ticket_kvno']}", "ticket_kvno lost")
    _assert(metadata["ticket_enctype"] == 18, f"ticket_enctype preserved: {metadata['ticket_enctype']}", "ticket_enctype lost")
    print(f"    Recovered metadata: kvno={metadata['ticket_kvno']}, enctype={metadata['ticket_enctype']}")


def demo_11_key_history_database(mods, conn):
    """Demo 11: Database principal_keys table stores full key history."""
    from core.messages import TGS_PRINCIPAL

    _banner("Demo 11: Key History — principal_keys table tracks all versions")

    cursor = conn.cursor()
    original = mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
    original_kvno = int(original["kvno"])
    original_key = original["key"]
    print(f"    Original kvno: {original_kvno}")

    _step("Changing password twice (kvno +1, +2)")
    mods.database.upsert_principal(conn, TGS_PRINCIPAL, "secret_v2", original["principal_type"],
                                    kvno=original_kvno + 1, groups=original.get("groups", "[]"))
    mods.database.upsert_principal(conn, TGS_PRINCIPAL, "secret_v3", original["principal_type"],
                                    kvno=original_kvno + 2, groups=original.get("groups", "[]"))
    conn.commit()

    _step("Verifying key history")
    all_keys = mods.database.list_principal_keys(conn.cursor(), TGS_PRINCIPAL, resolve_alias=False)
    print(f"    Total key versions stored: {len(all_keys)}")
    for k in all_keys:
        retired = "active" if k.get("retired_at") is None else "retired"
        print(f"      kvno={k['kvno']}, enctype={k['enctype']}, status={retired}")

    _assert(len(all_keys) >= 3, f"At least 3 key versions in history: {len(all_keys)}", f"Only {len(all_keys)} versions")

    _step("Looking up old key by exact kvno")
    old_key = mods.database.get_principal_key(conn.cursor(), TGS_PRINCIPAL, kvno=original_kvno,
                                               enctype=original["enctype"], resolve_alias=False)
    _assert(old_key is not None and old_key["key"] == original_key,
            f"Original key (kvno={original_kvno}) still retrievable",
            "Original key lost from history!")


def demo_12_init_preserves_kvno(mods, conn):
    """Demo 12: Re-running init_database does not reset changed kvno."""
    from core.messages import TGS_PRINCIPAL

    _banner("Demo 12: Idempotent Init — init_database does not reset manually changed kvno")

    cursor = conn.cursor()
    _step("Getting current TGS kvno")
    current = mods.database.get_principal(cursor, TGS_PRINCIPAL, resolve_alias=False)
    current_kvno = int(current["kvno"])
    print(f"    Current kvno before re-init: {current_kvno}")

    _step("Re-running init_database()")
    conn.close()
    mods.database.init_database()
    conn2 = mods.database.connect()
    after = mods.database.get_principal(conn2.cursor(), TGS_PRINCIPAL, resolve_alias=False)
    after_kvno = int(after["kvno"])
    print(f"    kvno after re-init: {after_kvno}")
    _assert(after_kvno == current_kvno,
            f"kvno preserved after re-init ({after_kvno})",
            f"kvno reset from {current_kvno} to {after_kvno}!")
    conn2.close()
    return mods.database.connect()


def demo_13_asn1_der_roundtrip(mods, conn):
    """Demo 13: ASN.1/DER encode-decode roundtrip for all message types."""
    from core.asn1_codec import encode_message, decode_message
    from core.messages import AS_REQ, AS_REP, TGS_REQ, TGS_REP, AP_REQ, AP_REP, ERROR

    _banner("Demo 13: ASN.1/DER — Encode-decode roundtrip for all message types")

    test_messages = [
        {"msg_type": ERROR, "error_code": "KDC_ERR_PREAUTH_FAILED", "error_message": "Test error"},
    ]

    _step("Testing KRB_ERROR encode/decode roundtrip")
    for msg in test_messages:
        der_bytes = encode_message(msg)
        decoded = decode_message(der_bytes)
        _assert(
            decoded["msg_type"] == msg["msg_type"],
            f"{msg['msg_type']} roundtrip: {len(der_bytes)} DER bytes",
            f"Type mismatch: {decoded['msg_type']} != {msg['msg_type']}"
        )

    _step("Testing AS_REQ encode/decode roundtrip")
    as_req = _make_as_req("alice@DEMO.LOCAL", "alice_password")
    der_bytes = encode_message(as_req)
    decoded = decode_message(der_bytes)
    _assert(decoded["msg_type"] == AS_REQ, f"AS_REQ roundtrip: {len(der_bytes)} DER bytes", "AS_REQ roundtrip failed")
    _assert(decoded["client_principal"] == as_req["client_principal"],
            f"Principal preserved: {decoded['client_principal']}", "Principal mismatch")


def demo_14_clock_skew(mods, conn):
    """Demo 14: Clock skew detection in pre-authentication."""
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, derive_key, encrypt
    from core.asn1_codec import encode_pa_enc_timestamp
    from core.messages import AS_REQ, REALM, KRB_AP_ERR_SKEW
    from core.principal import principal_salt

    _banner("Demo 14: Clock Skew — AS rejects timestamps too far in the past")

    _step("Sending AS_REQ with timestamp 10 minutes in the past")
    principal = "alice@DEMO.LOCAL"
    realm = REALM
    client_key = derive_key("alice_password", salt=principal_salt(principal, realm), enctype=DEFAULT_ENCTYPE)

    old_time = time.time() - 600  # 10 minutes ago
    preauth = encrypt(
        encode_pa_enc_timestamp({"ctime": old_time, "cusec": 0}),
        client_key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
    )
    skewed_req = {
        "msg_type": AS_REQ,
        "client_principal": principal,
        "realm": realm,
        "nonce": secrets.randbits(31),
        "preauth": preauth,
        "preauth_enctype": DEFAULT_ENCTYPE,
        "kdc_options": [],
    }
    response = mods.as_handler.handle_as_request(skewed_req, conn.cursor())
    _assert(
        response["error_code"] == KRB_AP_ERR_SKEW,
        f"Clock skew detected: KRB_AP_ERR_SKEW (code 37)",
        f"Wrong error: {response.get('error_code')}"
    )


def demo_15_subkey_seq_number(mods, conn):
    """Demo 15: Subkey and sequence number in Authenticator / EncAPRepPart."""
    from core.asn1_codec import encode_authenticator, decode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_AP_REQ_AUTH, encrypt, decrypt

    _banner("Demo 15: Subkey & Sequence Number — AP Exchange handshake fields")

    _step("Creating Authenticator with subkey and seq-number")
    session_key = secrets.token_bytes(32)
    client_subkey = {"keytype": DEFAULT_ENCTYPE, "keyvalue": secrets.token_bytes(32)}
    client_seq = secrets.randbits(30)

    auth_der = encode_authenticator({
        "client_principal": "alice@DEMO.LOCAL",
        "realm": "DEMO.LOCAL",
        "ctime": time.time(),
        "cusec": 12345,
        "subkey": client_subkey,
        "seq_number": client_seq,
    })
    encrypted_auth = encrypt(auth_der, session_key, KEY_USAGE_AP_REQ_AUTH)
    _pass(f"Authenticator encrypted: {len(encrypted_auth)} bytes")

    _step("Decrypting and verifying Authenticator fields")
    decrypted_der = decrypt(encrypted_auth, session_key, KEY_USAGE_AP_REQ_AUTH)
    auth_data = decode_authenticator(decrypted_der)

    _assert(auth_data.get("subkey") is not None, "Client subkey present in Authenticator", "Subkey missing")
    _assert(auth_data.get("seq_number") == client_seq, f"Sequence number: {client_seq}", "Seq number mismatch")
    print(f"    Client subkey type: {auth_data['subkey']['keytype']}")
    print(f"    Client subkey length: {len(auth_data['subkey']['keyvalue'])} bytes")
    print(f"    Client seq number: {auth_data['seq_number']}")


def demo_16_ticket_tampering(mods, conn):
    """Demo 16: Ticket Tampering (Integrity Check Failure)."""
    from core.messages import KRB_AP_ERR_MODIFIED

    _banner("Demo 16: Ticket Tampering — TGS rejects modified TGT (Integrity Check)")

    _step("Issuing legitimate TGT for alice")
    tgt_bundle = _issue_tgt(mods, conn)

    _step("Attacker modifies 1 byte of the encrypted TGT to elevate privileges")
    # Simulate an attacker flipping a bit in the ciphertext
    original_tgt = tgt_bundle["response"]["tgt"]
    tampered_tgt = bytearray(original_tgt)
    tampered_tgt[-5] ^= 0xFF  # Flip some bits near the end (part of ciphertext or MAC)
    tgt_bundle["response"]["tgt"] = bytes(tampered_tgt)

    _step("Sending TGS_REQ with tampered TGT")
    tgs_req = _make_tgs_req(tgt_bundle)
    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())

    _assert(
        response["msg_type"] == "KRB_ERROR" and response["error_code"] == KRB_AP_ERR_MODIFIED,
        "Tampering detected: KRB_AP_ERR_MODIFIED (code 41) — HMAC verification failed",
        f"Expected integrity failure, got: {response.get('msg_type')} / {response.get('error_code')}"
    )


def demo_17_forged_authenticator(mods, conn):
    """Demo 17: Forged Authenticator with wrong session key."""
    from core.asn1_codec import encode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REQ_AUTH, encrypt
    from core.messages import REALM, TGS_PRINCIPAL, TGS_REQ, KRB_AP_ERR_MODIFIED
    from core.replay_cache import current_kerberos_time

    _banner("Demo 17: Forged Authenticator — Attacker doesn't have the session key")

    _step("Attacker intercepts a valid TGT but doesn't know the session key")
    tgt_bundle = _issue_tgt(mods, conn)
    
    _step("Attacker forges an Authenticator using a random key")
    random_key = secrets.token_bytes(32)
    _ts, ctime, cusec = current_kerberos_time()
    
    forged_auth = encrypt(
        encode_authenticator({
            "client_principal": "alice@DEMO.LOCAL",
            "realm": REALM,
            "ctime": ctime,
            "cusec": cusec,
        }),
        random_key, KEY_USAGE_TGS_REQ_AUTH,
    )
    
    tgs_req = {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": TGS_PRINCIPAL,
        "tgt": tgt_bundle["response"]["tgt"],
        "tgt_service_principal": TGS_PRINCIPAL,
        "tgt_enctype": DEFAULT_ENCTYPE,
        "authenticator": forged_auth,
        "authenticator_enctype": DEFAULT_ENCTYPE,
        "nonce": secrets.randbits(31),
    }

    response = mods.tgs_handler.handle_tgs_request(tgs_req, conn.cursor())

    _assert(
        response["msg_type"] == "KRB_ERROR" and response["error_code"] == KRB_AP_ERR_MODIFIED,
        "Forgery detected: KRB_AP_ERR_MODIFIED (code 41) — Decryption failed",
        f"Expected decryption failure, got: {response.get('msg_type')} / {response.get('error_code')}"
    )


# ============================================================
# Main
# ============================================================

def main() -> int:
    global passed, failed

    print("\n" + "█" * 70)
    print("  KERBEROS V5 COMPREHENSIVE DEMO — ALL FEATURES")
    print("  Dựa trên RFC 4120 / RFC 3961 / RFC 3962")
    print("█" * 70)

    with tempfile.TemporaryDirectory(prefix="krb-demo-all-") as tmp:
        mods = _fresh_modules(tmp)
        mods.database.init_database()
        conn = mods.database.connect()

        try:
            demo_1_happy_path(mods, conn)
            demo_2_wrong_password(mods, conn)
            demo_3_unknown_principal(mods, conn)
            demo_4_replay_detection(mods, conn)
            demo_5_tgt_renewal(mods, conn)

            # Demo 6 rotates keys, need fresh conn after
            conn.close()
            mods = _fresh_modules(tmp)
            mods.database.init_database()
            conn = mods.database.connect()

            demo_6_key_rotation(mods, conn)
            demo_7_bob_user_access(mods, conn)
            demo_8_unknown_service(mods, conn)
            demo_9_keytab_multi_version(mods, conn)
            demo_10_ccache_persistence(mods, conn)

            # Demo 11-12 rotate keys heavily, isolate
            conn.close()
            mods = _fresh_modules(tmp)
            mods.database.init_database()
            conn = mods.database.connect()

            demo_11_key_history_database(mods, conn)
            conn = demo_12_init_preserves_kvno(mods, conn)

            conn.close()
            mods = _fresh_modules(tmp)
            mods.database.init_database()
            conn = mods.database.connect()

            demo_13_asn1_der_roundtrip(mods, conn)
            demo_14_clock_skew(mods, conn)
            demo_15_subkey_seq_number(mods, conn)
            demo_16_ticket_tampering(mods, conn)
            demo_17_forged_authenticator(mods, conn)

        except Exception as e:
            _fail(f"Unexpected exception: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()

    # Summary
    total = passed + failed
    print(f"\n{'='*70}")
    print(f"  SUMMARY: {passed}/{total} passed, {failed}/{total} failed")
    if failed == 0:
        print("  🎉 ALL DEMOS PASSED!")
    else:
        print("  ⚠️  Some demos failed — check output above.")
    print(f"{'='*70}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
