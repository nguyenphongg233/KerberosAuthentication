"""ASN.1/DER codec for the Kerberos demo wire messages.

The schemas in this module follow the RFC 4120 application tags and field
layout used by the AS, TGS and AP exchanges implemented by the project. The
encrypted payloads still contain the demo Fernet ciphertext; DER is used for
the outer Kerberos message structure.
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
    KRB_ERR_GENERIC,
    REALM,
    TGS_REP,
    TGS_REQ,
    TGS_PRINCIPAL,
)
from core.principal import principal_realm, service_principal


PVNO = 5
DEMO_ENCTYPE_ID = -128
SUPPORTED_ETYPES = [DEMO_ENCTYPE_ID]

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
    _append_padata(req, PA_ENC_TIMESTAMP, _encode_encrypted_data(message["preauth"]))

    body = req.getComponentByName("req-body")
    _fill_kdc_req_body(
        body,
        realm=str(message.get("realm", REALM)),
        nonce=int(message.get("nonce", 0)),
        cname=message.get("client_principal"),
        sname=TGS_PRINCIPAL,
    )
    req.setComponentByName("req-body", body)
    return req


def _build_tgs_req(message: dict) -> TGSReq:
    req = TGSReq()
    _fill_kdc_req_common(req, TGS_REQ)

    ap_req = APReq()
    _fill_ap_req(
        ap_req,
        ticket_cipher=message["tgt"],
        ticket_principal=TGS_PRINCIPAL,
        authenticator_cipher=message["authenticator"],
    )
    _append_padata(req, PA_TGS_REQ, encoder.encode(ap_req))

    body = req.getComponentByName("req-body")
    service = message["service_principal"]
    _fill_kdc_req_body(
        body,
        realm=str(message.get("realm", principal_realm(service, REALM))),
        nonce=int(message.get("nonce", 0)),
        sname=service,
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
    _fill_ticket(ticket, ticket_cipher, ticket_principal)
    rep.setComponentByName("ticket", ticket)

    enc_part = rep.getComponentByName("enc-part")
    _fill_encrypted_data(enc_part, message["encrypted_data"])
    rep.setComponentByName("enc-part", enc_part)
    return rep


def _build_ap_req(message: dict) -> APReq:
    req = APReq()
    service = message.get("service_principal") or service_principal("fileserver")
    _fill_ap_req(req, message["service_ticket"], service, message["authenticator"])
    return req


def _build_ap_rep(message: dict) -> APRep:
    rep = APRep()
    rep.setComponentByName("pvno", PVNO)
    rep.setComponentByName("msg-type", MSG_TYPE_NUMBERS[AP_REP])
    enc_part = rep.getComponentByName("enc-part")
    _fill_encrypted_data(enc_part, message["encrypted_data"])
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
                       cname: str | None = None, sname: str | None = None) -> None:
    body.setComponentByName("kdc-options", _flags_to_bitstring([]))
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


def _fill_ap_req(req: APReq, ticket_cipher: str, ticket_principal: str,
                 authenticator_cipher: str) -> None:
    req.setComponentByName("pvno", PVNO)
    req.setComponentByName("msg-type", MSG_TYPE_NUMBERS[AP_REQ])
    req.setComponentByName("ap-options", _flags_to_bitstring([]))
    ticket = req.getComponentByName("ticket")
    _fill_ticket(ticket, ticket_cipher, ticket_principal)
    req.setComponentByName("ticket", ticket)
    authenticator = req.getComponentByName("authenticator")
    _fill_encrypted_data(authenticator, authenticator_cipher)
    req.setComponentByName("authenticator", authenticator)


def _fill_ticket(ticket: Ticket, encrypted_ticket: str, server_princ: str) -> None:
    ticket.setComponentByName("tkt-vno", PVNO)
    ticket.setComponentByName("realm", principal_realm(server_princ, REALM))
    sname = ticket.getComponentByName("sname")
    _fill_principal(sname, server_princ)
    ticket.setComponentByName("sname", sname)
    enc_part = ticket.getComponentByName("enc-part")
    _fill_encrypted_data(enc_part, encrypted_ticket, kvno=1)
    ticket.setComponentByName("enc-part", enc_part)


def _fill_encrypted_data(target: EncryptedData, cipher_text: str,
                         kvno: int | None = None) -> None:
    target.setComponentByName("etype", DEMO_ENCTYPE_ID)
    if kvno is not None:
        target.setComponentByName("kvno", int(kvno))
    target.setComponentByName("cipher", cipher_text.encode("utf-8"))


def _fill_principal(target: PrincipalName, principal: str) -> None:
    components, name_type, _realm = _split_principal(principal)
    target.setComponentByName("name-type", name_type)
    strings = target.getComponentByName("name-string").clone()
    for component in components:
        strings.append(component)
    target.setComponentByName("name-string", strings)


def _parse_as_req(req: ASReq) -> dict:
    body = req.getComponentByName("req-body")
    return {
        "msg_type": AS_REQ,
        "client_principal": _principal_to_string(body.getComponentByName("cname"), _as_str(body, "realm")),
        "realm": _as_str(body, "realm"),
        "nonce": int(body.getComponentByName("nonce")),
        "preauth": _padata_cipher(req, PA_ENC_TIMESTAMP),
    }


def _parse_tgs_req(req: TGSReq) -> dict:
    body = req.getComponentByName("req-body")
    service = _principal_to_string(body.getComponentByName("sname"), _as_str(body, "realm"))
    ap_req_der = _padata_value(req, PA_TGS_REQ)
    ap_req, rest = decoder.decode(ap_req_der, asn1Spec=APReq())
    if rest:
        raise ValueError("PA-TGS-REQ AP-REQ contains trailing bytes.")
    return {
        "msg_type": TGS_REQ,
        "realm": _as_str(body, "realm"),
        "service_principal": service,
        "nonce": int(body.getComponentByName("nonce")),
        "tgt": _ticket_cipher(ap_req.getComponentByName("ticket")),
        "authenticator": _encrypted_data_cipher(ap_req.getComponentByName("authenticator")),
    }


def _parse_kdc_rep(rep: KDCRep, msg_type: str) -> dict:
    ticket = rep.getComponentByName("ticket")
    server_princ = _ticket_principal(ticket)
    result = {
        "msg_type": msg_type,
        "realm": _as_str(rep, "crealm"),
        "client_principal": _principal_to_string(rep.getComponentByName("cname"), _as_str(rep, "crealm")),
        "encrypted_data": _encrypted_data_cipher(rep.getComponentByName("enc-part")),
    }
    if msg_type == AS_REP:
        result["tgt"] = _ticket_cipher(ticket)
        result["server_principal"] = server_princ
    else:
        result["service_ticket"] = _ticket_cipher(ticket)
        result["service_principal"] = server_princ
    return result


def _parse_ap_req(req: APReq) -> dict:
    ticket = req.getComponentByName("ticket")
    return {
        "msg_type": AP_REQ,
        "service_principal": _ticket_principal(ticket),
        "service_ticket": _ticket_cipher(ticket),
        "authenticator": _encrypted_data_cipher(req.getComponentByName("authenticator")),
    }


def _parse_ap_rep(rep: APRep) -> dict:
    return {
        "msg_type": AP_REP,
        "encrypted_data": _encrypted_data_cipher(rep.getComponentByName("enc-part")),
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


def _padata_cipher(req: KDCReq, padata_type: int) -> str:
    return _encrypted_data_cipher(_decode_encrypted_data(_padata_value(req, padata_type)))


def _padata_value(req: KDCReq, padata_type: int) -> bytes:
    padata = req.getComponentByName("padata")
    if not padata.isValue:
        raise ValueError(f"Missing PA-DATA type {padata_type}.")
    for pa in padata:
        if int(pa.getComponentByName("padata-type")) == padata_type:
            return bytes(pa.getComponentByName("padata-value"))
    raise ValueError(f"Missing PA-DATA type {padata_type}.")


def _encode_encrypted_data(cipher_text: str) -> bytes:
    encrypted = EncryptedData()
    _fill_encrypted_data(encrypted, cipher_text)
    return encoder.encode(encrypted)


def _decode_encrypted_data(payload: bytes) -> EncryptedData:
    value, rest = decoder.decode(payload, asn1Spec=EncryptedData())
    if rest:
        raise ValueError("EncryptedData contains trailing bytes.")
    return value


def _encrypted_data_cipher(encrypted: EncryptedData) -> str:
    return bytes(encrypted.getComponentByName("cipher")).decode("utf-8")


def _ticket_cipher(ticket: Ticket) -> str:
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
    }
    bits = ["0"] * 32
    for flag_name in flags:
        bit = flag_bits.get(flag_name)
        if bit is not None:
            bits[bit] = "1"
    return "".join(bits)


def _kerberos_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y%m%d%H%M%SZ")
