"""ASN.1/DER message-format tests."""

from __future__ import annotations

import unittest
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


class ASN1MessageFormatTests(unittest.TestCase):
    def test_application_tags_for_outer_messages(self) -> None:
        from core.asn1_codec import encode_message
        from core.messages import AP_REP, AP_REQ, AS_REP, ERROR, TGS_REP

        samples = [
            (
                {
                    "msg_type": "AS_REQ",
                    "client_principal": "alice@DEMO.LOCAL",
                    "realm": "DEMO.LOCAL",
                    "nonce": 1,
                    "preauth": b"cipher",
                    "preauth_enctype": 18,
                    "kdc_options": [],
                },
                0x6A,
            ),
            (
                {
                    "msg_type": AS_REP,
                    "realm": "DEMO.LOCAL",
                    "client_principal": "alice@DEMO.LOCAL",
                    "server_principal": "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
                    "encrypted_data": b"cipher",
                    "tgt": b"ticket",
                    "ticket_enctype": 18,
                    "ticket_kvno": 1,
                    "enc_part_enctype": 18,
                },
                0x6B,
            ),
            (
                {
                    "msg_type": "TGS_REQ",
                    "realm": "DEMO.LOCAL",
                    "service_principal": "fileserver/localhost@DEMO.LOCAL",
                    "tgt": b"tgt",
                    "tgt_service_principal": "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
                    "tgt_enctype": 18,
                    "tgt_kvno": 1,
                    "authenticator": b"auth",
                    "authenticator_enctype": 18,
                    "nonce": 2,
                },
                0x6C,
            ),
            (
                {
                    "msg_type": TGS_REP,
                    "realm": "DEMO.LOCAL",
                    "client_principal": "alice@DEMO.LOCAL",
                    "service_principal": "fileserver/localhost@DEMO.LOCAL",
                    "encrypted_data": b"cipher",
                    "service_ticket": b"ticket",
                    "ticket_enctype": 18,
                    "ticket_kvno": 1,
                    "enc_part_enctype": 18,
                },
                0x6D,
            ),
            (
                {
                    "msg_type": AP_REQ,
                    "service_principal": "fileserver/localhost@DEMO.LOCAL",
                    "service_ticket": b"ticket",
                    "ticket_enctype": 18,
                    "ticket_kvno": 1,
                    "authenticator": b"auth",
                    "authenticator_enctype": 18,
                },
                0x6E,
            ),
            (
                {
                    "msg_type": AP_REP,
                    "service_principal": "fileserver/localhost@DEMO.LOCAL",
                    "encrypted_data": b"cipher",
                    "enctype": 18,
                },
                0x6F,
            ),
            (
                {
                    "msg_type": ERROR,
                    "error_code": "KRB_AP_ERR_MODIFIED",
                    "error_message": "modified",
                },
                0x7E,
            ),
        ]

        for message, expected_tag in samples:
            with self.subTest(message=message["msg_type"]):
                self.assertEqual(expected_tag, encode_message(message)[0])

    def test_as_req_der_roundtrip_keeps_fields(self) -> None:
        from core.asn1_codec import decode_message, encode_message

        request = {
            "msg_type": "AS_REQ",
            "client_principal": "alice@DEMO.LOCAL",
            "realm": "DEMO.LOCAL",
            "nonce": 123,
            "preauth": b"encrypted-timestamp",
            "preauth_enctype": 18,
            "kdc_options": ["renewable"],
        }
        decoded = decode_message(encode_message(request))
        self.assertEqual("AS_REQ", decoded["msg_type"])
        self.assertEqual("alice@DEMO.LOCAL", decoded["client_principal"])
        self.assertEqual(123, decoded["nonce"])
        self.assertEqual(b"encrypted-timestamp", decoded["preauth"])
        self.assertIn("renewable", decoded["kdc_options"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
