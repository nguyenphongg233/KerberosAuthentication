"""TGT renewal tests."""

from __future__ import annotations

import secrets
import time
import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class TGTRenewalTests(KerberosTestCase):
    def test_expired_renewable_tgt_can_be_renewed_until_renew_till(self) -> None:
        from core.asn1_codec import decode_enc_kdc_rep_part
        from core.crypto import KEY_USAGE_TGS_REP_ENCPART, decrypt
        from core.messages import APP_SERVICE_PRINCIPAL, TGS_PRINCIPAL, TGS_REP

        conn = self.init_database()
        now = time.time()
        old_tgt = self.make_custom_tgt_bundle(
            conn,
            endtime=now - 30,
            renew_till=now + 900,
        )
        nonce = secrets.randbits(31)
        renew_req = self.make_tgs_req(
            old_tgt,
            nonce=nonce,
            service_principal=TGS_PRINCIPAL,
        )
        renew_req["kdc_options"] = ["renew"]

        renew_rep = self.mods.tgs_handler.handle_tgs_request(renew_req, conn.cursor())
        self.assertEqual(TGS_REP, renew_rep["msg_type"], renew_rep)

        decrypted = decrypt(
            renew_rep["encrypted_data"],
            old_tgt["session_key"],
            KEY_USAGE_TGS_REP_ENCPART,
        )
        enc_part = decode_enc_kdc_rep_part(decrypted, TGS_REP)
        self.assertEqual(nonce, enc_part["nonce"])
        self.assertGreater(enc_part["endtime"], now)
        self.assertLessEqual(enc_part["endtime"], old_tgt["enc_part"]["renew_till"])
        self.assertNotEqual(old_tgt["session_key"], enc_part["key"]["keyvalue"])

        renewed_bundle = {
            "principal": old_tgt["principal"],
            "response": {
                "tgt": renew_rep["service_ticket"],
                "tgt_enctype": renew_rep["service_ticket_enctype"],
                "tgt_kvno": renew_rep["service_ticket_kvno"],
            },
            "enc_part": enc_part,
            "session_key": enc_part["key"]["keyvalue"],
        }
        service_req = self.make_tgs_req(
            renewed_bundle,
            service_principal=APP_SERVICE_PRINCIPAL,
        )
        service_rep = self.mods.tgs_handler.handle_tgs_request(service_req, conn.cursor())
        self.assertEqual(TGS_REP, service_rep["msg_type"], service_rep)

    def test_tgt_renewal_after_renew_till_is_rejected(self) -> None:
        from core.messages import KRB_AP_ERR_TKT_EXPIRED, TGS_PRINCIPAL

        conn = self.init_database()
        now = time.time()
        old_tgt = self.make_custom_tgt_bundle(
            conn,
            endtime=now - 300,
            renew_till=now - 30,
        )
        renew_req = self.make_tgs_req(
            old_tgt,
            service_principal=TGS_PRINCIPAL,
        )
        renew_req["kdc_options"] = ["renew"]

        response = self.mods.tgs_handler.handle_tgs_request(renew_req, conn.cursor())
        self.assertEqual("KRB_ERROR", response["msg_type"])
        self.assertEqual(KRB_AP_ERR_TKT_EXPIRED, response["error_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
