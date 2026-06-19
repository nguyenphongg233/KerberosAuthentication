"""ASN.1/DER codec for the Kerberos wire messages and inner structures.

This module implements the full outer message wrappers and the inner
decrypted structures (EncTicketPart, EncKDCRepPart, Authenticator, EncAPRepPart)
using pyasn1 DER serialization to conform with RFC 4120.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import char, namedtype, tag, univ, useful

from core.messages import (
    AP_REP,
    AP_REQ,
    AS_REP,
    AS_REQ,
    ERROR,
    KDC_ERR_C_PRINCIPAL_UNKNOWN,
    KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_WRONG_REALM,
    KRB_AP_ERR_MODIFIED,
    KRB_AP_ERR_REPEAT,
    KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED,
    KRB_AP_ERR_TKT_NYV,
    KRB_ERR_GENERIC,
    REALM,
    TGS_REP,
    TGS_REQ,
    TGS_PRINCIPAL,
)
from core.principal import principal_realm, service_principal


PVNO = 5
SUPPORTED_ETYPES = [17, 18]  # aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96

MSG_TYPE_NUMBERS = {
    AS_REQ: 10,
    AS_REP: 11,
    TGS_REQ: 12,
    TGS_REP: 13,
    AP_REQ: 14,
    AP_REP: 15,
    ERROR: 30,
}
NUMBERS_TO_MSG_TYPE = {value: key for key, value in MSG_TYPE_NUMBERS.items()}

PA_TGS_REQ = 1
PA_ENC_TIMESTAMP = 2

NT_PRINCIPAL = 1
NT_SRV_INST = 2

ERROR_TO_CODE = {
    KDC_ERR_C_PRINCIPAL_UNKNOWN: 6,
    KDC_ERR_S_PRINCIPAL_UNKNOWN: 7,
    KDC_ERR_PREAUTH_FAILED: 24,
    KRB_AP_ERR_TKT_EXPIRED: 32,
    KRB_AP_ERR_TKT_NYV: 33,
    KRB_AP_ERR_REPEAT: 34,
    KRB_AP_ERR_SKEW: 37,
    KRB_AP_ERR_MODIFIED: 41,
    KRB_ERR_GENERIC: 60,
    KDC_ERR_WRONG_REALM: 68,
}
CODE_TO_ERROR = {value: key for key, value in ERROR_TO_CODE.items()}


def _context_tag(tag_id: int) -> tag.Tag:
    return tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, tag_id)


class Int32(univ.Integer):
    pass


class UInt32(univ.Integer):
    pass


class KerberosString(char.GeneralString):
    pass


class Realm(KerberosString):
    pass


class KerberosTime(useful.GeneralizedTime):
    pass


class Microseconds(univ.Integer):
    pass


class KerberosFlags(univ.BitString):
    pass


class SequenceOfKerberosString(univ.SequenceOf):
    componentType = KerberosString()


class SequenceOfInt32(univ.SequenceOf):
    componentType = Int32()


class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "name-type",
            Int32().subtype(explicitTag=_context_tag(0)),
        ),
        namedtype.NamedType(
            "name-string",
            SequenceOfKerberosString().subtype(explicitTag=_context_tag(1)),
        ),
    )


class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("etype", Int32().subtype(explicitTag=_context_tag(0))),
        namedtype.OptionalNamedType("kvno", UInt32().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("cipher", univ.OctetString().subtype(explicitTag=_context_tag(2))),
    )


class Ticket(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tkt-vno", univ.Integer().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("realm", Realm().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("sname", PrincipalName().subtype(explicitTag=_context_tag(2))),
        namedtype.NamedType("enc-part", EncryptedData().subtype(explicitTag=_context_tag(3))),
    )


class PAData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("padata-type", Int32().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("padata-value", univ.OctetString().subtype(explicitTag=_context_tag(2))),
    )


class SequenceOfPAData(univ.SequenceOf):
    componentType = PAData()


class SequenceOfTicket(univ.SequenceOf):
    componentType = Ticket()


class KDCReqBody(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("kdc-options", KerberosFlags().subtype(explicitTag=_context_tag(0))),
        namedtype.OptionalNamedType("cname", PrincipalName().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("realm", Realm().subtype(explicitTag=_context_tag(2))),
        namedtype.OptionalNamedType("sname", PrincipalName().subtype(explicitTag=_context_tag(3))),
        namedtype.OptionalNamedType("from", KerberosTime().subtype(explicitTag=_context_tag(4))),
        namedtype.NamedType("till", KerberosTime().subtype(explicitTag=_context_tag(5))),
        namedtype.OptionalNamedType("rtime", KerberosTime().subtype(explicitTag=_context_tag(6))),
        namedtype.NamedType("nonce", UInt32().subtype(explicitTag=_context_tag(7))),
        namedtype.NamedType("etype", SequenceOfInt32().subtype(explicitTag=_context_tag(8))),
        namedtype.OptionalNamedType("addresses", univ.SequenceOf().subtype(explicitTag=_context_tag(9))),
        namedtype.OptionalNamedType("enc-authorization-data", EncryptedData().subtype(explicitTag=_context_tag(10))),
        namedtype.OptionalNamedType("additional-tickets", SequenceOfTicket().subtype(explicitTag=_context_tag(11))),
    )


class KDCReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("pvno", univ.Integer().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("msg-type", univ.Integer().subtype(explicitTag=_context_tag(2))),
        namedtype.OptionalNamedType("padata", SequenceOfPAData().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("req-body", KDCReqBody().subtype(explicitTag=_context_tag(4))),
    )


class ASReq(KDCReq):
    tagSet = KDCReq.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 10)
    )


class TGSReq(KDCReq):
    tagSet = KDCReq.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 12)
    )


class KDCRep(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("pvno", univ.Integer().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("msg-type", univ.Integer().subtype(explicitTag=_context_tag(1))),
        namedtype.OptionalNamedType("padata", SequenceOfPAData().subtype(explicitTag=_context_tag(2))),
        namedtype.NamedType("crealm", Realm().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("cname", PrincipalName().subtype(explicitTag=_context_tag(4))),
        namedtype.NamedType("ticket", Ticket().subtype(explicitTag=_context_tag(5))),
        namedtype.NamedType("enc-part", EncryptedData().subtype(explicitTag=_context_tag(6))),
    )


class ASRep(KDCRep):
    tagSet = KDCRep.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11)
    )


class TGSRep(KDCRep):
    tagSet = KDCRep.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 13)
    )


class APReq(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("pvno", univ.Integer().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("msg-type", univ.Integer().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("ap-options", KerberosFlags().subtype(explicitTag=_context_tag(2))),
        namedtype.NamedType("ticket", Ticket().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("authenticator", EncryptedData().subtype(explicitTag=_context_tag(4))),
    )


class APRep(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 15)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("pvno", univ.Integer().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("msg-type", univ.Integer().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("enc-part", EncryptedData().subtype(explicitTag=_context_tag(2))),
    )


class KRBError(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 30)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("pvno", univ.Integer().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("msg-type", univ.Integer().subtype(explicitTag=_context_tag(1))),
        namedtype.OptionalNamedType("ctime", KerberosTime().subtype(explicitTag=_context_tag(2))),
        namedtype.OptionalNamedType("cusec", Microseconds().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("stime", KerberosTime().subtype(explicitTag=_context_tag(4))),
        namedtype.NamedType("susec", Microseconds().subtype(explicitTag=_context_tag(5))),
        namedtype.NamedType("error-code", Int32().subtype(explicitTag=_context_tag(6))),
        namedtype.OptionalNamedType("crealm", Realm().subtype(explicitTag=_context_tag(7))),
        namedtype.OptionalNamedType("cname", PrincipalName().subtype(explicitTag=_context_tag(8))),
        namedtype.NamedType("realm", Realm().subtype(explicitTag=_context_tag(9))),
        namedtype.NamedType("sname", PrincipalName().subtype(explicitTag=_context_tag(10))),
        namedtype.OptionalNamedType("e-text", char.GeneralString().subtype(explicitTag=_context_tag(11))),
        namedtype.OptionalNamedType("e-data", univ.OctetString().subtype(explicitTag=_context_tag(12))),
    )


# ============================================================
# Inner Encrypted Structures (RFC 4120)
# ============================================================

class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("keytype", Int32().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("keyvalue", univ.OctetString().subtype(explicitTag=_context_tag(1))),
    )


class TransitedEncoding(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tr-type", Int32().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("contents", univ.OctetString().subtype(explicitTag=_context_tag(1))),
    )


class AuthorizationData(univ.SequenceOf):
    class AuthorizationDataEntry(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("ad-type", Int32().subtype(explicitTag=_context_tag(0))),
            namedtype.NamedType("ad-data", univ.OctetString().subtype(explicitTag=_context_tag(1))),
        )
    componentType = AuthorizationDataEntry()


class EncTicketPart(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("flags", KerberosFlags().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("key", EncryptionKey().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("crealm", Realm().subtype(explicitTag=_context_tag(2))),
        namedtype.NamedType("cname", PrincipalName().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("transited", TransitedEncoding().subtype(explicitTag=_context_tag(4))),
        namedtype.NamedType("authtime", KerberosTime().subtype(explicitTag=_context_tag(5))),
        namedtype.OptionalNamedType("starttime", KerberosTime().subtype(explicitTag=_context_tag(6))),
        namedtype.NamedType("endtime", KerberosTime().subtype(explicitTag=_context_tag(7))),
        namedtype.OptionalNamedType("renew-till", KerberosTime().subtype(explicitTag=_context_tag(8))),
        namedtype.OptionalNamedType("authorization-data", AuthorizationData().subtype(explicitTag=_context_tag(10))),
    )


class LastReq(univ.SequenceOf):
    class LastReqEntry(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("lr-type", Int32().subtype(explicitTag=_context_tag(0))),
            namedtype.NamedType("lr-value", KerberosTime().subtype(explicitTag=_context_tag(1))),
        )
    componentType = LastReqEntry()


class EncKDCRepPart(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("key", EncryptionKey().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("last-req", LastReq().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("nonce", UInt32().subtype(explicitTag=_context_tag(2))),
        namedtype.OptionalNamedType("key-expiration", KerberosTime().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("flags", KerberosFlags().subtype(explicitTag=_context_tag(4))),
        namedtype.NamedType("authtime", KerberosTime().subtype(explicitTag=_context_tag(5))),
        namedtype.OptionalNamedType("starttime", KerberosTime().subtype(explicitTag=_context_tag(6))),
        namedtype.NamedType("endtime", KerberosTime().subtype(explicitTag=_context_tag(7))),
        namedtype.OptionalNamedType("renew-till", KerberosTime().subtype(explicitTag=_context_tag(8))),
        namedtype.NamedType("srealm", Realm().subtype(explicitTag=_context_tag(9))),
        namedtype.NamedType("sname", PrincipalName().subtype(explicitTag=_context_tag(10))),
    )


class EncASRepPart(EncKDCRepPart):
    tagSet = EncKDCRepPart.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25)
    )


class EncTGSRepPart(EncKDCRepPart):
    tagSet = EncKDCRepPart.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 26)
    )


class Checksum(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("cksumtype", Int32().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("checksum", univ.OctetString().subtype(explicitTag=_context_tag(1))),
    )


class Authenticator(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 2)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("authenticator-vno", univ.Integer().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("crealm", Realm().subtype(explicitTag=_context_tag(1))),
        namedtype.NamedType("cname", PrincipalName().subtype(explicitTag=_context_tag(2))),
        namedtype.OptionalNamedType("cksum", Checksum().subtype(explicitTag=_context_tag(3))),
        namedtype.NamedType("cusec", Microseconds().subtype(explicitTag=_context_tag(4))),
        namedtype.NamedType("ctime", KerberosTime().subtype(explicitTag=_context_tag(5))),
        namedtype.OptionalNamedType("subkey", EncryptionKey().subtype(explicitTag=_context_tag(6))),
        namedtype.OptionalNamedType("seq-number", UInt32().subtype(explicitTag=_context_tag(7))),
    )


class EncAPRepPart(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 27)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("ctime", KerberosTime().subtype(explicitTag=_context_tag(0))),
        namedtype.NamedType("cusec", Microseconds().subtype(explicitTag=_context_tag(1))),
        namedtype.OptionalNamedType("subkey", EncryptionKey().subtype(explicitTag=_context_tag(2))),
        namedtype.OptionalNamedType("seq-number", UInt32().subtype(explicitTag=_context_tag(3))),
    )


# ============================================================
# Helpers for Time Conversion
# ============================================================

def _to_krb_time(t: float | int | str | None) -> str | None:
    if t is None:
        return None
    if isinstance(t, (int, float)):
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y%m%d%H%M%SZ")
    return str(t)


def _from_krb_time(t_str: str | None) -> float | None:
    if not t_str:
        return None
    try:
        dt = datetime.strptime(str(t_str), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


# ============================================================
# Encode / Decode Outer Messages
# ============================================================

def encode_message(message: dict) -> bytes:
    """Encode an internal message dictionary to RFC 4120-style DER."""
    msg_type = message.get("msg_type")
    if msg_type == AS_REQ:
        return encoder.encode(_build_as_req(message))
    if msg_type == TGS_REQ:
        return encoder.encode(_build_tgs_req(message))
    if msg_type == AS_REP:
        return encoder.encode(_build_kdc_rep(message, ASRep(), AS_REP))
    if msg_type == TGS_REP:
        return encoder.encode(_build_kdc_rep(message, TGSRep(), TGS_REP))
    if msg_type == AP_REQ:
        return encoder.encode(_build_ap_req(message))
    if msg_type == AP_REP:
        return encoder.encode(_build_ap_rep(message))
    if msg_type == ERROR:
        return encoder.encode(_build_krb_error(message))
    raise ValueError(f"Unsupported Kerberos message type for DER: {msg_type}")


def decode_message(payload: bytes) -> dict:
    """Decode an RFC 4120-style DER message to the internal dictionary form."""
    if not payload:
        raise ValueError("Empty DER payload.")

    app_tag = _application_tag_number(payload)
    specs = {
        10: ASReq(),
        11: ASRep(),
        12: TGSReq(),
        13: TGSRep(),
        14: APReq(),
        15: APRep(),
        30: KRBError(),
    }
    spec = specs.get(app_tag)
    if spec is None:
        raise ValueError(f"Unsupported Kerberos application tag: {app_tag}")

    try:
        value, rest = decoder.decode(payload, asn1Spec=spec)
    except PyAsn1Error as exc:
        raise ValueError(f"Invalid DER payload: {exc}") from exc
    if rest:
        raise ValueError("DER payload contains trailing bytes.")

    if app_tag == 10:
        return _parse_as_req(value)
    if app_tag == 11:
        return _parse_kdc_rep(value, AS_REP)
    if app_tag == 12:
        return _parse_tgs_req(value)
    if app_tag == 13:
        return _parse_kdc_rep(value, TGS_REP)
    if app_tag == 14:
        return _parse_ap_req(value)
    if app_tag == 15:
        return _parse_ap_rep(value)
    return _parse_krb_error(value)


def _application_tag_number(payload: bytes) -> int:
    first = payload[0]
    tag_class = first & 0xC0
    if tag_class != 0x40:
        raise ValueError("DER payload is not an application-class Kerberos message.")
    tag_number = first & 0x1F
    if tag_number != 0x1F:
        return tag_number

    value = 0
    index = 1
    while index < len(payload):
        octet = payload[index]
        value = (value << 7) | (octet & 0x7F)
        index += 1
        if not (octet & 0x80):
            return value
    raise ValueError("Invalid high-tag-number DER encoding.")


def _build_as_req(message: dict) -> ASReq:
    req = ASReq()
    _fill_kdc_req_common(req, AS_REQ)
    enctype = message.get("preauth_enctype", 18)
    _append_padata(req, PA_ENC_TIMESTAMP, _encode_encrypted_data(message["preauth"], enctype=enctype))

    body = req.getComponentByName("req-body")
    _fill_kdc_req_body(
        body,
        realm=str(message.get("realm", REALM)),
        nonce=int(message.get("nonce", 0)),
        cname=message.get("client_principal"),
        sname=TGS_PRINCIPAL,
        kdc_options=message.get("kdc_options", []),
    )
    req.setComponentByName("req-body", body)
    return req


def _build_tgs_req(message: dict) -> TGSReq:
    req = TGSReq()
    _fill_kdc_req_common(req, TGS_REQ)

    ap_req = APReq()
    tgt_service = message.get("tgt_service_principal") or TGS_PRINCIPAL
    _fill_ap_req(
        ap_req,
        ticket_cipher=message["tgt"],
        ticket_principal=tgt_service,
        authenticator_cipher=message["authenticator"],
        ticket_enctype=message.get("tgt_enctype", 18),
        ticket_kvno=message.get("tgt_kvno"),
        authenticator_enctype=message.get("authenticator_enctype", 18),
    )
    _append_padata(req, PA_TGS_REQ, encoder.encode(ap_req))

    body = req.getComponentByName("req-body")
    service = message["service_principal"]
    _fill_kdc_req_body(
        body,
        realm=str(message.get("realm", principal_realm(service, REALM))),
        nonce=int(message.get("nonce", 0)),
        sname=service,
        kdc_options=message.get("kdc_options", []),
    )
    req.setComponentByName("req-body", body)
    return req


def _build_kdc_rep(message: dict, rep: KDCRep, msg_type: str) -> KDCRep:
    rep.setComponentByName("pvno", PVNO)
    rep.setComponentByName("msg-type", MSG_TYPE_NUMBERS[msg_type])
    rep.setComponentByName("crealm", str(message.get("realm", REALM)))
    cname = rep.getComponentByName("cname")
    _fill_principal(cname, message["client_principal"])
    rep.setComponentByName("cname", cname)

    ticket_principal = message.get("service_principal") or message.get("server_principal") or TGS_PRINCIPAL
    ticket = rep.getComponentByName("ticket")
    ticket_cipher = message.get("service_ticket") or message.get("tgt")
    
    ticket_enctype = message.get("ticket_enctype", 18)
    ticket_kvno = (
        message.get("ticket_kvno")
        or message.get("tgt_kvno")
        or message.get("service_ticket_kvno")
    )
    enc_part_enctype = message.get("enc_part_enctype", 18)

    _fill_ticket(ticket, ticket_cipher, ticket_principal,
                 enctype=ticket_enctype, kvno=ticket_kvno)
    rep.setComponentByName("ticket", ticket)

    enc_part = rep.getComponentByName("enc-part")
    _fill_encrypted_data(enc_part, message["encrypted_data"], enctype=enc_part_enctype)
    rep.setComponentByName("enc-part", enc_part)
    return rep


def _build_ap_req(message: dict) -> APReq:
    req = APReq()
    service = message.get("service_principal") or service_principal("fileserver")
    ticket_enctype = message.get("ticket_enctype", 18)
    ticket_kvno = message.get("ticket_kvno")
    authenticator_enctype = message.get("authenticator_enctype", 18)
    _fill_ap_req(req, message["service_ticket"], service, message["authenticator"],
                 ticket_enctype=ticket_enctype, ticket_kvno=ticket_kvno,
                 authenticator_enctype=authenticator_enctype)
    return req


def _build_ap_rep(message: dict) -> APRep:
    rep = APRep()
    rep.setComponentByName("pvno", PVNO)
    rep.setComponentByName("msg-type", MSG_TYPE_NUMBERS[AP_REP])
    enc_part = rep.getComponentByName("enc-part")
    _fill_encrypted_data(enc_part, message["encrypted_data"], enctype=message.get("enctype", 18))
    rep.setComponentByName("enc-part", enc_part)
    return rep


def _build_krb_error(message: dict) -> KRBError:
    err = KRBError()
    err.setComponentByName("pvno", PVNO)
    err.setComponentByName("msg-type", MSG_TYPE_NUMBERS[ERROR])
    now = datetime.now(timezone.utc)
    err.setComponentByName("stime", _kerberos_time(now))
    err.setComponentByName("susec", now.microsecond)
    error_code = ERROR_TO_CODE.get(message.get("error_code"), ERROR_TO_CODE[KRB_ERR_GENERIC])
    err.setComponentByName("error-code", error_code)
    err.setComponentByName("realm", REALM)
    sname = err.getComponentByName("sname")
    _fill_principal(sname, TGS_PRINCIPAL)
    err.setComponentByName("sname", sname)
    if message.get("error_message"):
        err.setComponentByName("e-text", str(message["error_message"]))
    if message.get("error_code"):
        err.setComponentByName("e-data", json.dumps({"error_code": message["error_code"]}).encode("utf-8"))
    return err


def _fill_kdc_req_common(req: KDCReq, msg_type: str) -> None:
    req.setComponentByName("pvno", PVNO)
    req.setComponentByName("msg-type", MSG_TYPE_NUMBERS[msg_type])


def _append_padata(req: KDCReq, padata_type: int, padata_value: bytes) -> None:
    seq = req.getComponentByName("padata")
    pa = PAData()
    pa.setComponentByName("padata-type", padata_type)
    pa.setComponentByName("padata-value", padata_value)
    seq.append(pa)
    req.setComponentByName("padata", seq)


def _fill_kdc_req_body(body: KDCReqBody, realm: str, nonce: int,
                       cname: str | None = None, sname: str | None = None,
                       kdc_options: list[str] | None = None) -> None:
    body.setComponentByName("kdc-options", _flags_to_bitstring(kdc_options or []))
    if cname:
        cname_field = body.getComponentByName("cname")
        _fill_principal(cname_field, cname)
        body.setComponentByName("cname", cname_field)
    body.setComponentByName("realm", realm.upper())
    if sname:
        sname_field = body.getComponentByName("sname")
        _fill_principal(sname_field, sname)
        body.setComponentByName("sname", sname_field)
    body.setComponentByName("till", _kerberos_time(datetime(2037, 12, 31, 23, 59, 59, tzinfo=timezone.utc)))
    body.setComponentByName("nonce", nonce)
    etypes = body.getComponentByName("etype")
    for etype in SUPPORTED_ETYPES:
        etypes.append(etype)
    body.setComponentByName("etype", etypes)


def _fill_ap_req(req: APReq, ticket_cipher: bytes, ticket_principal: str,
                 authenticator_cipher: bytes, ticket_enctype: int = 18,
                 ticket_kvno: int | None = None,
                 authenticator_enctype: int = 18) -> None:
    req.setComponentByName("pvno", PVNO)
    req.setComponentByName("msg-type", MSG_TYPE_NUMBERS[AP_REQ])
    req.setComponentByName("ap-options", _flags_to_bitstring([]))
    ticket = req.getComponentByName("ticket")
    _fill_ticket(ticket, ticket_cipher, ticket_principal,
                 enctype=ticket_enctype, kvno=ticket_kvno)
    req.setComponentByName("ticket", ticket)
    authenticator = req.getComponentByName("authenticator")
    _fill_encrypted_data(authenticator, authenticator_cipher, enctype=authenticator_enctype)
    req.setComponentByName("authenticator", authenticator)


def _fill_ticket(ticket: Ticket, encrypted_ticket: bytes, server_princ: str,
                 enctype: int = 18, kvno: int | None = None) -> None:
    ticket.setComponentByName("tkt-vno", PVNO)
    ticket.setComponentByName("realm", principal_realm(server_princ, REALM))
    sname = ticket.getComponentByName("sname")
    _fill_principal(sname, server_princ)
    ticket.setComponentByName("sname", sname)
    enc_part = ticket.getComponentByName("enc-part")
    _fill_encrypted_data(enc_part, encrypted_ticket, enctype=enctype, kvno=kvno)
    ticket.setComponentByName("enc-part", enc_part)


def _fill_encrypted_data(target: EncryptedData, cipher_bytes: bytes,
                         enctype: int = 18, kvno: int | None = None) -> None:
    target.setComponentByName("etype", enctype)
    if kvno is not None:
        target.setComponentByName("kvno", int(kvno))
    target.setComponentByName("cipher", cipher_bytes)


def _fill_principal(target: PrincipalName, principal: str) -> None:
    components, name_type, _realm = _split_principal(principal)
    target.setComponentByName("name-type", name_type)
    strings = target.getComponentByName("name-string").clone()
    for component in components:
        strings.append(component)
    target.setComponentByName("name-string", strings)


def _parse_as_req(req: ASReq) -> dict:
    body = req.getComponentByName("req-body")
    pa_data_field = req.getComponentByName("padata")
    
    # We can detect enctype from PA-DATA
    enctype = 18
    if pa_data_field.isValue:
        for pa in pa_data_field:
            if int(pa.getComponentByName("padata-type")) == PA_ENC_TIMESTAMP:
                val = _decode_encrypted_data(bytes(pa.getComponentByName("padata-value")))
                enctype = int(val.getComponentByName("etype"))
                break
                
    return {
        "msg_type": AS_REQ,
        "client_principal": _principal_to_string(body.getComponentByName("cname"), _as_str(body, "realm")),
        "realm": _as_str(body, "realm"),
        "nonce": int(body.getComponentByName("nonce")),
        "preauth": _padata_cipher_bytes(req, PA_ENC_TIMESTAMP),
        "preauth_enctype": enctype,
        "kdc_options": _bitstring_to_flags(body.getComponentByName("kdc-options")),
    }


def _parse_tgs_req(req: TGSReq) -> dict:
    body = req.getComponentByName("req-body")
    service = _principal_to_string(body.getComponentByName("sname"), _as_str(body, "realm"))
    ap_req_der = _padata_value(req, PA_TGS_REQ)
    ap_req, rest = decoder.decode(ap_req_der, asn1Spec=APReq())
    if rest:
        raise ValueError("PA-TGS-REQ AP-REQ contains trailing bytes.")
        
    ticket_val = ap_req.getComponentByName("ticket")
    auth_val = ap_req.getComponentByName("authenticator")
    ticket_enc_part = ticket_val.getComponentByName("enc-part")
    
    return {
        "msg_type": TGS_REQ,
        "realm": _as_str(body, "realm"),
        "service_principal": service,
        "nonce": int(body.getComponentByName("nonce")),
        "tgt": _ticket_cipher_bytes(ticket_val),
        "tgt_service_principal": _ticket_principal(ticket_val),
        "tgt_enctype": int(ticket_enc_part.getComponentByName("etype")),
        "tgt_kvno": _encrypted_data_kvno(ticket_enc_part),
        "authenticator": _encrypted_data_cipher(auth_val),
        "authenticator_enctype": int(auth_val.getComponentByName("etype")),
        "kdc_options": _bitstring_to_flags(body.getComponentByName("kdc-options")),
    }


def _parse_kdc_rep(rep: KDCRep, msg_type: str) -> dict:
    ticket = rep.getComponentByName("ticket")
    server_princ = _ticket_principal(ticket)
    ticket_enc_part = ticket.getComponentByName("enc-part")
    ticket_enctype = int(ticket_enc_part.getComponentByName("etype"))
    ticket_kvno = _encrypted_data_kvno(ticket_enc_part)
    enc_part = rep.getComponentByName("enc-part")
    
    result = {
        "msg_type": msg_type,
        "realm": _as_str(rep, "crealm"),
        "client_principal": _principal_to_string(rep.getComponentByName("cname"), _as_str(rep, "crealm")),
        "encrypted_data": _encrypted_data_cipher(enc_part),
        "enc_part_enctype": int(enc_part.getComponentByName("etype")),
    }
    if msg_type == AS_REP:
        result["tgt"] = _ticket_cipher_bytes(ticket)
        result["tgt_enctype"] = ticket_enctype
        result["tgt_kvno"] = ticket_kvno
        result["server_principal"] = server_princ
    else:
        result["service_ticket"] = _ticket_cipher_bytes(ticket)
        result["service_ticket_enctype"] = ticket_enctype
        result["service_ticket_kvno"] = ticket_kvno
        result["service_principal"] = server_princ
    return result


def _parse_ap_req(req: APReq) -> dict:
    ticket = req.getComponentByName("ticket")
    auth_val = req.getComponentByName("authenticator")
    ticket_enc_part = ticket.getComponentByName("enc-part")
    return {
        "msg_type": AP_REQ,
        "service_principal": _ticket_principal(ticket),
        "service_ticket": _ticket_cipher_bytes(ticket),
        "ticket_enctype": int(ticket_enc_part.getComponentByName("etype")),
        "ticket_kvno": _encrypted_data_kvno(ticket_enc_part),
        "authenticator": _encrypted_data_cipher(auth_val),
        "authenticator_enctype": int(auth_val.getComponentByName("etype")),
    }


def _parse_ap_rep(rep: APRep) -> dict:
    enc_part = rep.getComponentByName("enc-part")
    return {
        "msg_type": AP_REP,
        "encrypted_data": _encrypted_data_cipher(enc_part),
        "enctype": int(enc_part.getComponentByName("etype")),
    }


def _parse_krb_error(err: KRBError) -> dict:
    error_code = int(err.getComponentByName("error-code"))
    result = {
        "msg_type": ERROR,
        "error_code": CODE_TO_ERROR.get(error_code, KRB_ERR_GENERIC),
        "error_message": str(err.getComponentByName("e-text") or ""),
        "numeric_error_code": error_code,
    }
    e_data = err.getComponentByName("e-data")
    if e_data.isValue:
        try:
            detail = json.loads(bytes(e_data).decode("utf-8"))
            if detail.get("error_code"):
                result["error_code"] = detail["error_code"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return result


def _padata_cipher_bytes(req: KDCReq, padata_type: int) -> bytes:
    return _encrypted_data_cipher(_decode_encrypted_data(_padata_value(req, padata_type)))


def _padata_value(req: KDCReq, padata_type: int) -> bytes:
    padata = req.getComponentByName("padata")
    if not padata.isValue:
        raise ValueError(f"Missing PA-DATA type {padata_type}.")
    for pa in padata:
        if int(pa.getComponentByName("padata-type")) == padata_type:
            return bytes(pa.getComponentByName("padata-value"))
    raise ValueError(f"Missing PA-DATA type {padata_type}.")


def _encode_encrypted_data(cipher_bytes: bytes, enctype: int = 18) -> bytes:
    encrypted = EncryptedData()
    _fill_encrypted_data(encrypted, cipher_bytes, enctype=enctype)
    return encoder.encode(encrypted)


def _decode_encrypted_data(payload: bytes) -> EncryptedData:
    value, rest = decoder.decode(payload, asn1Spec=EncryptedData())
    if rest:
        raise ValueError("EncryptedData contains trailing bytes.")
    return value


def _encrypted_data_cipher(encrypted: EncryptedData) -> bytes:
    return bytes(encrypted.getComponentByName("cipher"))


def _encrypted_data_kvno(encrypted: EncryptedData) -> int | None:
    kvno = encrypted.getComponentByName("kvno")
    if kvno.isValue:
        return int(kvno)
    return None


def _ticket_cipher_bytes(ticket: Ticket) -> bytes:
    return _encrypted_data_cipher(ticket.getComponentByName("enc-part"))


def _ticket_principal(ticket: Ticket) -> str:
    return _principal_to_string(
        ticket.getComponentByName("sname"),
        _as_str(ticket, "realm"),
    )


def _principal_to_string(principal: PrincipalName, realm: str) -> str:
    strings = principal.getComponentByName("name-string")
    components = [str(component) for component in strings]
    if not components:
        return f"@{realm}"
    return f"{'/'.join(components)}@{realm.upper()}"


def _split_principal(principal: str) -> tuple[list[str], int, str]:
    if "@" in principal:
        local, realm = principal.rsplit("@", 1)
    else:
        local, realm = principal, REALM
    components = [part for part in local.split("/") if part]
    name_type = NT_SRV_INST if len(components) > 1 else NT_PRINCIPAL
    return components, name_type, realm.upper()


def _as_str(sequence: univ.Sequence, field_name: str) -> str:
    return str(sequence.getComponentByName(field_name))


def _flags_to_bitstring(flags: list[str]) -> str:
    flag_bits = {
        "forwardable": 1,
        "forwarded": 2,
        "proxiable": 3,
        "proxy": 4,
        "may_postdate": 5,
        "postdated": 6,
        "invalid": 7,
        "renewable": 8,
        "initial": 9,
        "pre_authent": 10,
        "hw_authent": 11,
        "transited_policy_checked": 12,
        "ok_as_delegate": 13,
        "anonymous": 14,
        "renew": 21,
    }
    bits = ["0"] * 32
    for flag_name in flags:
        bit = flag_bits.get(flag_name)
        if bit is not None:
            bits[bit] = "1"
    return "".join(bits)


def _bitstring_to_flags(bitstring: univ.BitString) -> list[str]:
    flag_bits = {
        1: "forwardable",
        2: "forwarded",
        3: "proxiable",
        4: "proxy",
        5: "may_postdate",
        6: "postdated",
        7: "invalid",
        8: "renewable",
        9: "initial",
        10: "pre_authent",
        11: "hw_authent",
        12: "transited_policy_checked",
        13: "ok_as_delegate",
        14: "anonymous",
        21: "renew",
    }
    flags = []
    for bit_idx, flag_name in flag_bits.items():
        if bit_idx < len(bitstring) and bitstring[bit_idx]:
            flags.append(flag_name)
    return flags


def _kerberos_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y%m%d%H%M%SZ")


# ============================================================
# Inner Encrypted Structure Encoding / Decoding Helpers
# ============================================================

def encode_enc_ticket_part(data: dict) -> bytes:
    """Encode the EncTicketPart dictionary structure to DER bytes."""
    part = EncTicketPart()
    part.setComponentByName("flags", _flags_to_bitstring(data.get("flags", [])))
    
    key_field = part.getComponentByName("key")
    key_field.setComponentByName("keytype", int(data["key"]["keytype"]))
    key_field.setComponentByName("keyvalue", data["key"]["keyvalue"])
    part.setComponentByName("key", key_field)
    
    part.setComponentByName("crealm", str(data["realm"]))
    
    cname_field = part.getComponentByName("cname")
    _fill_principal(cname_field, data["client_principal"])
    part.setComponentByName("cname", cname_field)
    
    transited_field = part.getComponentByName("transited")
    transited_field.setComponentByName("tr-type", 0)
    transited_field.setComponentByName("contents", b"")
    part.setComponentByName("transited", transited_field)
    
    part.setComponentByName("authtime", _to_krb_time(data.get("authtime")))
    if data.get("starttime"):
        part.setComponentByName("starttime", _to_krb_time(data["starttime"]))
    part.setComponentByName("endtime", _to_krb_time(data.get("endtime")))
    if data.get("renew_till"):
        part.setComponentByName("renew-till", _to_krb_time(data["renew_till"]))
        
    if data.get("authorization_data"):
        ad_field = part.getComponentByName("authorization-data")
        for entry in data["authorization_data"]:
            ad_entry = ad_field.componentType.clone()
            ad_entry.setComponentByName("ad-type", int(entry["ad_type"]))
            ad_entry.setComponentByName("ad-data", entry["ad_data"])
            ad_field.append(ad_entry)
        part.setComponentByName("authorization-data", ad_field)
        
    return encoder.encode(part)


def decode_enc_ticket_part(der: bytes) -> dict:
    """Decode DER bytes of EncTicketPart to dictionary structure."""
    part, rest = decoder.decode(der, asn1Spec=EncTicketPart())
    if rest:
        raise ValueError("Trailing bytes in EncTicketPart DER.")
    
    key_field = part.getComponentByName("key")
    flags_val = part.getComponentByName("flags")
    
    crealm = _as_str(part, "crealm")
    client_principal = _principal_to_string(part.getComponentByName("cname"), crealm)
    
    ad_val = []
    if part.getComponentByName("authorization-data").isValue:
        ad_field = part.getComponentByName("authorization-data")
        for entry in ad_field:
            ad_val.append({
                "ad_type": int(entry.getComponentByName("ad-type")),
                "ad_data": bytes(entry.getComponentByName("ad-data")),
            })
            
    return {
        "flags": _bitstring_to_flags(flags_val),
        "key": {
            "keytype": int(key_field.getComponentByName("keytype")),
            "keyvalue": bytes(key_field.getComponentByName("keyvalue")),
        },
        "realm": crealm,
        "client_principal": client_principal,
        "authtime": _from_krb_time(_as_str(part, "authtime")),
        "starttime": _from_krb_time(_as_str(part, "starttime")) if part.getComponentByName("starttime").isValue else None,
        "endtime": _from_krb_time(_as_str(part, "endtime")),
        "renew_till": _from_krb_time(_as_str(part, "renew-till")) if part.getComponentByName("renew-till").isValue else None,
        "authorization_data": ad_val,
    }


def encode_enc_kdc_rep_part(data: dict, msg_type: str) -> bytes:
    """Encode KDC response inner part (EncASRepPart or EncTGSRepPart) to DER bytes."""
    part = EncASRepPart() if msg_type == AS_REP else EncTGSRepPart()
    
    key_field = part.getComponentByName("key")
    key_field.setComponentByName("keytype", int(data["key"]["keytype"]))
    key_field.setComponentByName("keyvalue", data["key"]["keyvalue"])
    part.setComponentByName("key", key_field)
    
    last_req_field = part.getComponentByName("last-req")
    entry = last_req_field.componentType.clone()
    entry.setComponentByName("lr-type", 0)
    entry.setComponentByName("lr-value", _to_krb_time(data.get("authtime")))
    last_req_field.append(entry)
    part.setComponentByName("last-req", last_req_field)
    
    part.setComponentByName("nonce", int(data["nonce"]))
    part.setComponentByName("flags", _flags_to_bitstring(data.get("flags", [])))
    
    part.setComponentByName("authtime", _to_krb_time(data.get("authtime")))
    if data.get("starttime"):
        part.setComponentByName("starttime", _to_krb_time(data["starttime"]))
    part.setComponentByName("endtime", _to_krb_time(data.get("endtime")))
    if data.get("renew_till"):
        part.setComponentByName("renew-till", _to_krb_time(data["renew_till"]))
        
    part.setComponentByName("srealm", str(data["realm"]))
    
    sname_field = part.getComponentByName("sname")
    _fill_principal(sname_field, data["service_principal"])
    part.setComponentByName("sname", sname_field)
    
    return encoder.encode(part)


def decode_enc_kdc_rep_part(der: bytes, msg_type: str) -> dict:
    """Decode KDC response inner part DER bytes to dictionary structure."""
    spec = EncASRepPart() if msg_type == AS_REP else EncTGSRepPart()
    part, rest = decoder.decode(der, asn1Spec=spec)
    if rest:
        raise ValueError("Trailing bytes in EncKDCRepPart DER.")
        
    key_field = part.getComponentByName("key")
    flags_val = part.getComponentByName("flags")
    srealm = _as_str(part, "srealm")
    service_principal = _principal_to_string(part.getComponentByName("sname"), srealm)
    
    return {
        "key": {
            "keytype": int(key_field.getComponentByName("keytype")),
            "keyvalue": bytes(key_field.getComponentByName("keyvalue")),
        },
        "nonce": int(part.getComponentByName("nonce")),
        "flags": _bitstring_to_flags(flags_val),
        "authtime": _from_krb_time(_as_str(part, "authtime")),
        "starttime": _from_krb_time(_as_str(part, "starttime")) if part.getComponentByName("starttime").isValue else None,
        "endtime": _from_krb_time(_as_str(part, "endtime")),
        "renew_till": _from_krb_time(_as_str(part, "renew-till")) if part.getComponentByName("renew-till").isValue else None,
        "realm": srealm,
        "service_principal": service_principal,
    }


def encode_authenticator(data: dict) -> bytes:
    """Encode Authenticator dictionary structure to DER bytes."""
    auth = Authenticator()
    auth.setComponentByName("authenticator-vno", 5)
    auth.setComponentByName("crealm", str(data["realm"]))
    
    cname_field = auth.getComponentByName("cname")
    _fill_principal(cname_field, data["client_principal"])
    auth.setComponentByName("cname", cname_field)
    
    auth.setComponentByName("cusec", int(data.get("cusec", 0)))
    auth.setComponentByName("ctime", _to_krb_time(int(data.get("ctime", 0))))
    
    if data.get("subkey"):
        subkey_field = auth.getComponentByName("subkey")
        subkey_field.setComponentByName("keytype", int(data["subkey"]["keytype"]))
        subkey_field.setComponentByName("keyvalue", data["subkey"]["keyvalue"])
        auth.setComponentByName("subkey", subkey_field)
        
    if data.get("seq_number") is not None:
        auth.setComponentByName("seq-number", int(data["seq_number"]))
        
    return encoder.encode(auth)


def decode_authenticator(der: bytes) -> dict:
    """Decode Authenticator DER bytes to dictionary structure."""
    auth, rest = decoder.decode(der, asn1Spec=Authenticator())
    if rest:
        raise ValueError("Trailing bytes in Authenticator DER.")
        
    crealm = _as_str(auth, "crealm")
    client_principal = _principal_to_string(auth.getComponentByName("cname"), crealm)
    
    ctime_str = _as_str(auth, "ctime")
    cusec = int(auth.getComponentByName("cusec"))
    ctime_val = _from_krb_time(ctime_str)
    
    subkey_val = None
    if auth.getComponentByName("subkey").isValue:
        subkey_field = auth.getComponentByName("subkey")
        subkey_val = {
            "keytype": int(subkey_field.getComponentByName("keytype")),
            "keyvalue": bytes(subkey_field.getComponentByName("keyvalue")),
        }
    seq_number = None
    if auth.getComponentByName("seq-number").isValue:
        seq_number = int(auth.getComponentByName("seq-number"))
        
    return {
        "realm": crealm,
        "client_principal": client_principal,
        "ctime": ctime_val,
        "cusec": cusec,
        "timestamp": ctime_val + (cusec / 1000000.0) if ctime_val is not None else 0.0,
        "subkey": subkey_val,
        "seq_number": seq_number,
    }


def encode_enc_ap_rep_part(data: dict) -> bytes:
    """Encode EncAPRepPart dictionary structure to DER bytes."""
    part = EncAPRepPart()
    part.setComponentByName("ctime", _to_krb_time(int(data.get("ctime", 0))))
    part.setComponentByName("cusec", int(data.get("cusec", 0)))
    
    if data.get("subkey"):
        subkey_field = part.getComponentByName("subkey")
        subkey_field.setComponentByName("keytype", int(data["subkey"]["keytype"]))
        subkey_field.setComponentByName("keyvalue", data["subkey"]["keyvalue"])
        part.setComponentByName("subkey", subkey_field)
        
    if data.get("seq_number") is not None:
        part.setComponentByName("seq-number", int(data["seq_number"]))
        
    return encoder.encode(part)


def decode_enc_ap_rep_part(der: bytes) -> dict:
    """Decode EncAPRepPart DER bytes to dictionary structure."""
    part, rest = decoder.decode(der, asn1Spec=EncAPRepPart())
    if rest:
        raise ValueError("Trailing bytes in EncAPRepPart DER.")
        
    ctime_str = _as_str(part, "ctime")
    cusec = int(part.getComponentByName("cusec"))
    ctime_val = _from_krb_time(ctime_str)
    
    subkey_val = None
    if part.getComponentByName("subkey").isValue:
        subkey_field = part.getComponentByName("subkey")
        subkey_val = {
            "keytype": int(subkey_field.getComponentByName("keytype")),
            "keyvalue": bytes(subkey_field.getComponentByName("keyvalue")),
        }
    seq_number = None
    if part.getComponentByName("seq-number").isValue:
        seq_number = int(part.getComponentByName("seq-number"))
        
    return {
        "ctime": ctime_val,
        "cusec": cusec,
        "timestamp": ctime_val + (cusec / 1000000.0) if ctime_val is not None else 0.0,
        "subkey": subkey_val,
        "seq_number": seq_number,
    }


class PaEncTimestamp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("patimestamp", KerberosTime().subtype(explicitTag=_context_tag(0))),
        namedtype.OptionalNamedType("pausec", Microseconds().subtype(explicitTag=_context_tag(1))),
    )


def encode_pa_enc_timestamp(data: dict) -> bytes:
    """Encode PaEncTimestamp structure to DER bytes."""
    pat = PaEncTimestamp()
    pat.setComponentByName("patimestamp", _to_krb_time(int(data.get("ctime", 0))))
    pat.setComponentByName("pausec", int(data.get("cusec", 0)))
    return encoder.encode(pat)


def decode_pa_enc_timestamp(der: bytes) -> dict:
    """Decode PaEncTimestamp DER bytes to dictionary structure."""
    pat, rest = decoder.decode(der, asn1Spec=PaEncTimestamp())
    if rest:
        raise ValueError("Trailing bytes in PaEncTimestamp DER.")
    ctime_str = _as_str(pat, "patimestamp")
    cusec = int(pat.getComponentByName("pausec")) if pat.getComponentByName("pausec").isValue else 0
    ctime_val = _from_krb_time(ctime_str)
    return {
        "ctime": ctime_val,
        "cusec": cusec,
        "timestamp": ctime_val + (cusec / 1000000.0) if ctime_val is not None else 0.0,
    }
