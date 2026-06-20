"""Verbose TGT renewal demo for the Kerberos project.

The script uses a temporary runtime and does not touch the repository database,
keytab, replay cache, or client credential cache.
"""

from __future__ import annotations

import secrets
import sys
import tempfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scratch.demo_security_flows import _banner, _fresh_modules, _msg, _result, _step


def _make_expired_renewable_tgt(mods, conn) -> dict:
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
    tgs_record = mods.database.get_principal(
        conn.cursor(),
        TGS_PRINCIPAL,
        resolve_alias=False,
    )
    session_key = generate_session_key(DEFAULT_ENCTYPE)
    plaintext = {
        "flags": list(DEFAULT_TICKET_FLAGS),
        "key": {"keytype": DEFAULT_ENCTYPE, "keyvalue": session_key},
        "realm": REALM,
        "client_principal": "alice@DEMO.LOCAL",
        "authtime": now - 500,
        "starttime": now - 500,
        "endtime": now - 30,
        "renew_till": now + 900,
        "authorization_data": [],
    }
    tgt_der = encode_enc_ticket_part(plaintext)
    encrypted_tgt = encrypt(tgt_der, str_to_key(tgs_record["key"]), KEY_USAGE_TICKET)
    return {
        "principal": "alice@DEMO.LOCAL",
        "response": {
            "tgt": encrypted_tgt,
            "tgt_enctype": NAME_TO_ENCTYPE.get(tgs_record["enctype"], DEFAULT_ENCTYPE),
            "tgt_kvno": tgs_record["kvno"],
        },
        "enc_part": plaintext,
        "session_key": session_key,
    }


def _make_tgs_req(mods, tgt_bundle: dict, service_principal: str, renew: bool = False) -> dict:
    from core.asn1_codec import encode_authenticator
    from core.crypto import DEFAULT_ENCTYPE, KEY_USAGE_TGS_REQ_AUTH, encrypt
    from core.messages import REALM, TGS_PRINCIPAL, TGS_REQ
    from core.replay_cache import current_kerberos_time

    _timestamp, ctime, cusec = current_kerberos_time()
    authenticator = encrypt(
        encode_authenticator(
            {
                "client_principal": tgt_bundle["principal"],
                "realm": REALM,
                "ctime": ctime,
                "cusec": cusec,
            }
        ),
        tgt_bundle["session_key"],
        KEY_USAGE_TGS_REQ_AUTH,
    )
    request = {
        "msg_type": TGS_REQ,
        "realm": REALM,
        "service_principal": service_principal,
        "tgt": tgt_bundle["response"]["tgt"],
        "tgt_service_principal": TGS_PRINCIPAL,
        "tgt_enctype": tgt_bundle["response"]["tgt_enctype"],
        "tgt_kvno": tgt_bundle["response"]["tgt_kvno"],
        "authenticator": authenticator,
        "authenticator_enctype": DEFAULT_ENCTYPE,
        "nonce": secrets.randbits(31),
    }
    if renew:
        request["kdc_options"] = ["renew"]
    return request


def main() -> int:
    with tempfile.TemporaryDirectory(
        prefix="krb-renewal-demo-",
        ignore_cleanup_errors=True,
    ) as temp_dir:
        runtime = Path(temp_dir)
        mods = _fresh_modules(runtime)
        mods.database.init_database()
        conn = mods.database.connect()
        try:
            from core.asn1_codec import decode_enc_kdc_rep_part
            from core.crypto import KEY_USAGE_TGS_REP_ENCPART, decrypt
            from core.messages import APP_SERVICE_PRINCIPAL, TGS_PRINCIPAL, TGS_REP

            print(f"[INFO] Temporary runtime: {runtime}")
            _banner("TGT Renewal Demo")

            tgt_bundle = _make_expired_renewable_tgt(mods, conn)
            old_ticket = tgt_bundle["enc_part"]
            _step("Client has an expired TGT, but the TGT is still inside renew_till.")
            _msg(
                "Client cache",
                "Expired renewable TGT",
                {
                    "client_principal": tgt_bundle["principal"],
                    "tgt_kvno": tgt_bundle["response"]["tgt_kvno"],
                    "endtime": int(old_ticket["endtime"]),
                    "renew_till": int(old_ticket["renew_till"]),
                    "flags": ",".join(old_ticket["flags"]),
                },
            )

            renew_req = _make_tgs_req(mods, tgt_bundle, TGS_PRINCIPAL, renew=True)
            _step("Client sends TGS_REQ with kdc_options=['renew'] to renew the TGT.")
            _msg(
                "Client -> TGS",
                "TGS_REQ renew",
                {
                    "service_principal": TGS_PRINCIPAL,
                    "kdc_options": "renew",
                    "tgt_kvno": renew_req["tgt_kvno"],
                },
            )
            renew_rep = mods.tgs_handler.handle_tgs_request(renew_req, conn.cursor())
            if renew_rep.get("msg_type") != TGS_REP:
                _msg("TGS -> Client", "KRB_ERROR", renew_rep)
                _result("BLOCKED", "TGT renewal failed")
                return 1

            decrypted = decrypt(
                renew_rep["encrypted_data"],
                tgt_bundle["session_key"],
                KEY_USAGE_TGS_REP_ENCPART,
            )
            renewed_part = decode_enc_kdc_rep_part(decrypted, TGS_REP)
            _msg(
                "TGS -> Client",
                "TGS_REP renewed TGT",
                {
                    "old_endtime": int(old_ticket["endtime"]),
                    "new_endtime": int(renewed_part["endtime"]),
                    "renew_till": int(renewed_part["renew_till"]),
                    "new_tgt_kvno": renew_rep["service_ticket_kvno"],
                },
            )
            _result("ALLOWED", "Expired TGT was renewed because renew_till has not passed")

            renewed_bundle = {
                "principal": tgt_bundle["principal"],
                "response": {
                    "tgt": renew_rep["service_ticket"],
                    "tgt_enctype": renew_rep["service_ticket_enctype"],
                    "tgt_kvno": renew_rep["service_ticket_kvno"],
                },
                "enc_part": renewed_part,
                "session_key": renewed_part["key"]["keyvalue"],
            }

            service_req = _make_tgs_req(mods, renewed_bundle, APP_SERVICE_PRINCIPAL)
            _step("Client uses the renewed TGT to request a normal service ticket.")
            _msg(
                "Client -> TGS",
                "TGS_REQ service ticket",
                {
                    "service_principal": APP_SERVICE_PRINCIPAL,
                    "renewed_tgt_kvno": service_req["tgt_kvno"],
                },
            )
            service_rep = mods.tgs_handler.handle_tgs_request(service_req, conn.cursor())
            if service_rep.get("msg_type") != TGS_REP:
                _msg("TGS -> Client", "KRB_ERROR", service_rep)
                _result("BLOCKED", "Renewed TGT could not obtain a service ticket")
                return 1
            _msg(
                "TGS -> Client",
                "TGS_REP service ticket",
                {
                    "service_principal": service_rep["service_principal"],
                    "service_ticket_kvno": service_rep["service_ticket_kvno"],
                },
            )
            _result("ALLOWED", "Renewed TGT can be used for normal TGS exchange")
            return 0
        finally:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
