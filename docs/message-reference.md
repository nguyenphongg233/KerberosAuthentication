# Tham Chiếu Message

Project gửi message qua TCP length-prefixed framing. Payload mặc định là ASN.1/DER theo các application tag và field chính của RFC 4120. Có thể bật JSON legacy bằng `KRB_WIRE_FORMAT=json` để debug, nhưng chế độ mặc định là `der`.

## TCP Frame

```text
[4 bytes message length, big-endian][DER payload]
```

## Application Tags

| Message | Internal constant | RFC 4120 application tag |
| --- | --- | --- |
| `Ticket` | Ticket trong TGT/ST | `[APPLICATION 1]` |
| `AS-REQ` | `AS_REQ` | `[APPLICATION 10]` |
| `AS-REP` | `AS_REP` | `[APPLICATION 11]` |
| `TGS-REQ` | `TGS_REQ` | `[APPLICATION 12]` |
| `TGS-REP` | `TGS_REP` | `[APPLICATION 13]` |
| `AP-REQ` | `AP_REQ` | `[APPLICATION 14]` |
| `AP-REP` | `AP_REP` | `[APPLICATION 15]` |
| `KRB-ERROR` | `ERROR` | `[APPLICATION 30]` |

## Codec

File chịu trách nhiệm encode/decode:

```text
core/asn1_codec.py
```

`core/network.py` gọi:

- `encode_message(dict) -> bytes` khi gửi DER.
- `decode_message(bytes) -> dict` khi nhận DER.

Các handler AS/TGS/AP vẫn làm việc với dict nội bộ để code dễ đọc. Dict này không còn là wire format mặc định.

## Kiểu ASN.1 Chính

| Kiểu | Vai trò trong project |
| --- | --- |
| `PrincipalName` | Encode/decode `alice@DEMO.LOCAL`, `krbtgt/DEMO.LOCAL@DEMO.LOCAL`, `fileserver/localhost@DEMO.LOCAL` |
| `Realm` | Realm, mặc định `DEMO.LOCAL` |
| `EncryptedData` | Chứa `etype`, `kvno` tùy chọn và `cipher` |
| `Ticket` | Wrapper ASN.1 cho TGT và service ticket |
| `PA-DATA` | Chứa pre-auth hoặc PA-TGS-REQ |

## EncryptedData

`EncryptedData` chứa thông tin mã hóa tuân thủ theo RFC 3961/3962.

| Field | Mô tả |
| --- | --- |
| `etype` | `18` (aes256-cts-hmac-sha1-96) hoặc `17` (aes128-cts-hmac-sha1-96) |
| `kvno` | Key version number (tùy chọn) |
| `cipher` | Ciphertext (gồm 16-byte random confounder + DER plaintext + 12-byte HMAC-SHA1-96 checksum) |

Tên mô tả trong payload nội bộ:

```text
aes256-cts-hmac-sha1-96 / aes128-cts-hmac-sha1-96
```

## AS-REQ

Wire format:

```text
AS-REQ ::= [APPLICATION 10] KDC-REQ
```

Các field chính:

| ASN.1 field | Giá trị demo |
| --- | --- |
| `pvno` | `5` |
| `msg-type` | `10` |
| `padata` | `PA-ENC-TIMESTAMP` type `2` |
| `req-body.cname` | Client principal |
| `req-body.realm` | Realm |
| `req-body.sname` | TGS principal |
| `req-body.nonce` | UInt32 nonce |
| `req-body.etype` | `[18, 17]` |

Internal view sau khi decode:

```json
{
  "msg_type": "AS_REQ",
  "client_principal": "alice@DEMO.LOCAL",
  "realm": "DEMO.LOCAL",
  "nonce": 123456789,
  "preauth": "bytes ciphertext",
  "preauth_enctype": 18
}
```

## AS-REP

Wire format:

```text
AS-REP ::= [APPLICATION 11] KDC-REP
```

Các field chính:

| ASN.1 field | Giá trị demo |
| --- | --- |
| `pvno` | `5` |
| `msg-type` | `11` |
| `crealm` | Realm của client |
| `cname` | Client principal |
| `ticket` | TGT |
| `enc-part` | `EncryptedData` chứa `EncKDCRepPart` mã hóa bằng `Kc` |

Phần plaintext của `enc-part` sau khi giải mã là `EncKDCRepPart` gồm:

- `key`: Khóa phiên Client-TGS `Kc_tgs`.
- `last-req`: Lịch sử request (không dùng).
- `nonce`: Khớp với nonce trong request.
- `key-expiration`: Hạn dùng khóa (không dùng).
- `flags`: Cờ của vé.
- `authtime`, `starttime`, `endtime`, `renew-till`: Các mốc thời gian của vé.
- `srealm`: Realm của TGS.
- `sname`: TGS principal name (`krbtgt/DEMO.LOCAL`).

Internal view:

```json
{
  "msg_type": "AS_REP",
  "realm": "DEMO.LOCAL",
  "client_principal": "alice@DEMO.LOCAL",
  "encrypted_data": "bytes ciphertext",
  "tgt": "bytes DER Ticket"
}
```

## TGS-REQ

Wire format:

```text
TGS-REQ ::= [APPLICATION 12] KDC-REQ
```

Các field chính:

| ASN.1 field | Giá trị demo |
| --- | --- |
| `pvno` | `5` |
| `msg-type` | `12` |
| `padata` | Chứa `PA-TGS-REQ` type `1` có giá trị là `AP-REQ` DER |
| `req-body.realm` | Realm |
| `req-body.sname` | Service principal |
| `req-body.nonce` | UInt32 nonce |
| `req-body.etype` | `[18, 17]` |

Internal view sau khi decode:

```json
{
  "msg_type": "TGS_REQ",
  "realm": "DEMO.LOCAL",
  "service_principal": "fileserver/localhost@DEMO.LOCAL",
  "tgt": "bytes ciphertext của Ticket",
  "tgt_enctype": 18,
  "authenticator": "bytes ciphertext của Authenticator",
  "authenticator_enctype": 18,
  "nonce": 987654321
}
```

## TGS-REP

Wire format:

```text
TGS-REP ::= [APPLICATION 13] KDC-REP
```

Các field chính giống `AS-REP`, ngoại trừ `ticket` là service ticket và `enc-part` là `EncKDCRepPart` mã hóa bằng `Kc_tgs`.

Internal view sau khi decode:

```json
{
  "msg_type": "TGS_REP",
  "realm": "DEMO.LOCAL",
  "client_principal": "alice@DEMO.LOCAL",
  "service_principal": "fileserver/localhost@DEMO.LOCAL",
  "encrypted_data": "bytes ciphertext",
  "service_ticket": "bytes DER Ticket"
}
```

## AP-REQ

Wire format:

```text
AP-REQ ::= [APPLICATION 14] SEQUENCE
```

Các field chính:

| ASN.1 field | Giá trị demo |
| --- | --- |
| `pvno` | `5` |
| `msg-type` | `14` |
| `ap-options` | KerberosFlags (`mutual-required` hoặc rỗng) |
| `ticket` | Service ticket nhận được từ TGS |
| `authenticator` | `EncryptedData` chứa `Authenticator` đã mã hóa |

Phần plaintext của `authenticator` sau khi giải mã là `Authenticator` gồm:

- `authenticator-vno`: `5`.
- `crealm`: Realm của client.
- `cname`: Client principal.
- `cksum`: Checksum dữ liệu (không dùng).
- `cusec`: Microseconds của client.
- `ctime`: Thời gian hiện tại của client.
- `subkey`: Subkey do client đề xuất (không dùng).
- `seq-number`: Sequence number (không dùng).

Internal view sau khi decode:

```json
{
  "msg_type": "AP_REQ",
  "mutual_auth": true,
  "ticket": "bytes ciphertext của Ticket",
  "ticket_enctype": 18,
  "authenticator": "bytes ciphertext của Authenticator",
  "authenticator_enctype": 18
}
```

## AP-REP

Wire format:

```text
AP-REP ::= [APPLICATION 15] SEQUENCE
```

Các field chính:

| ASN.1 field | Giá trị demo |
| --- | --- |
| `pvno` | `5` |
| `msg-type` | `15` |
| `enc-part` | `EncryptedData` chứa `EncAPRepPart` đã mã hóa |

Phần plaintext của `enc-part` sau khi giải mã là `EncAPRepPart` gồm:

- `ctime`: Thời gian nhận được từ authenticator.
- `cusec`: Microseconds nhận được từ authenticator.
- `subkey`: Subkey đề xuất bởi server (không dùng).
- `seq-number`: Sequence number (không dùng).

Internal view sau khi decode:

```json
{
  "msg_type": "AP_REP",
  "encrypted_data": "bytes ciphertext"
}
```

## Ticket

Wire format:

```text
Ticket ::= [APPLICATION 1] SEQUENCE
```

Các field chính:

| ASN.1 field | Giá trị demo |
| --- | --- |
| `tkt-vno` | `5` |
| `realm` | Realm của server principal |
| `sname` | TGS hoặc service principal |
| `enc-part` | `EncryptedData` chứa DER bytes của `EncTicketPart` đã mã hóa |

Phần plaintext sau khi giải mã `enc-part` là cấu trúc ASN.1 `EncTicketPart` (ví dụ đối với TGT):

- `flags`: Cờ của ticket (ví dụ: initial, pre-authent, renewable).
- `key`: Khóa phiên (gồm `keytype` = 18 và `keyvalue` = 32 bytes khóa).
- `crealm`: Realm của client (`DEMO.LOCAL`).
- `cname`: Principal của client (`alice`).
- `authtime`: Thời gian xác thực (`KerberosTime`).
- `starttime`: Thời gian bắt đầu có hiệu lực (`KerberosTime`).
- `endtime`: Thời gian hết hạn (`KerberosTime`).
- `renew-till`: Thời gian tối đa được gia hạn (`KerberosTime`).

## KRB-ERROR

Wire format:

```text
KRB-ERROR ::= [APPLICATION 30] SEQUENCE
```

Project encode error bằng numeric code gần RFC:

| Internal error | Numeric code |
| --- | --- |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | `6` |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | `7` |
| `KDC_ERR_PREAUTH_FAILED` | `24` |
| `KRB_AP_ERR_TKT_EXPIRED` | `32` |
| `KRB_AP_ERR_REPEAT` | `34` |
| `KRB_AP_ERR_SKEW` | `37` |
| `KRB_AP_ERR_MODIFIED` | `41` |
| `KRB_ERR_GENERIC` | `60` |
| `KDC_ERR_WRONG_REALM` | `68` |

`e-text` chứa thông báo lỗi đọc được. `e-data` chứa JSON nhỏ để giữ lại internal error string khi decode.
