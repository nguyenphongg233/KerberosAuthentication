# Giao Thức Mô Phỏng

Tài liệu này mô tả cách project mô phỏng Kerberos V5 theo RFC 4120 ở mức cấu trúc và hành vi. Cả message ngoài (outer wire messages) và tất cả các payload mã hóa bên trong (inner encrypted structures như `EncTicketPart`, `EncKDCRepPart`, `Authenticator`, `EncAPRepPart`, `PaEncTimestamp`) đều được tuần tự hóa bằng định dạng ASN.1/DER (sử dụng thư viện `pyasn1`). Dữ liệu được mã hóa bằng thuật toán AES-CTS kết hợp checksum HMAC-SHA1-96 (enctype `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96`) và Key Usage theo đúng RFC 3961/3962.

## Ký Hiệu

| Ký hiệu | Ý nghĩa |
| --- | --- |
| `Kc` | Long-term key của client |
| `Ktgs` | Long-term key của TGS |
| `Kservice` | Long-term key của service |
| `Kc_tgs` | Session key giữa client và TGS |
| `Kc_service` | Session key giữa client và service |
| `TGT` | Ticket Granting Ticket |
| `ST` | Service Ticket |

## Wire Format

TCP frame:

```text
[4-byte big-endian length][DER payload]
```

Các message DER được định nghĩa trong `core/asn1_codec.py` theo application tag của RFC 4120:

| Message | Application tag |
| --- | --- |
| `Ticket` | `[APPLICATION 1]` |
| `AS-REQ` | `[APPLICATION 10]` |
| `AS-REP` | `[APPLICATION 11]` |
| `TGS-REQ` | `[APPLICATION 12]` |
| `TGS-REP` | `[APPLICATION 13]` |
| `AP-REQ` | `[APPLICATION 14]` |
| `AP-REP` | `[APPLICATION 15]` |
| `KRB-ERROR` | `[APPLICATION 30]` |

`KRB_WIRE_FORMAT=der` là mặc định. `KRB_WIRE_FORMAT=json` chỉ dùng khi cần debug legacy.

## Kênh Truyền Thông

Các thành phần không dùng chung một kênh duy nhất. Project tách các kênh theo đúng vai trò Kerberos:

| Kênh | Giao thức mạng | Message | Ghi chú |
| --- | --- | --- | --- |
| Client ↔ KDC/AS | TCP tới `KDC_HOST:KDC_PORT` | `AS-REQ`, `AS-REP`, `KRB-ERROR` | Client xin TGT. Password không đi qua mạng; pre-auth được mã hóa bằng `Kc`. |
| Client ↔ KDC/TGS | TCP tới `KDC_HOST:KDC_PORT` | `TGS-REQ`, `TGS-REP`, `KRB-ERROR` | Client dùng TGT để xin service ticket. TGT và authenticator nằm trong `PA-TGS-REQ`. |
| Client ↔ Application Server | TCP tới `APP_SERVER_HOST:APP_SERVER_PORT` | `AP-REQ`, `AP-REP`, `KRB-ERROR` | Client dùng service ticket để truy cập service và nhận mutual authentication. |
| AS ↔ TGS | Nội bộ cùng process KDC | Dispatch theo `msg_type` | AS và TGS là hai handler logic trong `kdc.kdc_server`, không mở socket riêng cho nhau. |
| KDC ↔ Application Server | Không có TCP runtime trực tiếp | Không có bản tin runtime giữa hai server | KDC và Application Server chia sẻ trust qua service key: KDC lưu trong DB và export keytab, Application Server đọc keytab. |

Do đó, nếu hỏi riêng “giao thức giữa các server”, câu trả lời chính xác là: AS và TGS giao tiếp nội bộ trong process KDC; KDC và Application Server không truyền ticket trực tiếp cho nhau qua network. Client là bên chuyển TGT/service ticket giữa các pha.

## Bảo Vệ Thông Tin Khi Truyền

Project bảo vệ dữ liệu Kerberos ở tầng payload, không bảo vệ toàn bộ TCP channel. TCP chỉ cung cấp kênh byte stream; ASN.1/DER chỉ là định dạng tuần tự hóa. Các phần quan trọng được mã hóa trước khi đặt vào message:

| Pha | Dữ liệu nhạy cảm trên wire | Khóa bảo vệ | Bên giải mã được |
| --- | --- | --- | --- |
| AS-REQ | Pre-authentication timestamp/principal | `Kc` | AS/KDC |
| AS-REP | Client part chứa `Kc_tgs`, nonce và lifetime | `Kc` | Client biết password đúng |
| AS-REP | TGT chứa `Kc_tgs` và thông tin client | `Ktgs` | TGS/KDC |
| TGS-REQ | Authenticator của client | `Kc_tgs` | TGS/KDC |
| TGS-REP | Client part chứa `Kc_service`, nonce và lifetime | `Kc_tgs` | Client đang giữ TGT/session key hợp lệ |
| TGS-REP | Service ticket chứa `Kc_service` và thông tin client | `Kservice` | Application Server có keytab đúng |
| AP-REQ | Authenticator của client | `Kc_service` | Application Server |
| AP-REP | Timestamp xác thực ngược lại server | `Kc_service` | Client |

Password plaintext không bao giờ được gửi qua network. Replay được hạn chế bằng `ctime`, `cusec`, clock skew check và SQLite replay cache. Tuy nhiên, vì chưa có TLS/mTLS nên attacker vẫn có thể quan sát metadata như địa chỉ IP, port, thời điểm gửi, số lần kết nối và độ dài frame.

## Principal

Realm mặc định:

```text
DEMO.LOCAL
```

Principal:

```text
alice@DEMO.LOCAL
```
```text
krbtgt/DEMO.LOCAL@DEMO.LOCAL
```
```text
fileserver/localhost@DEMO.LOCAL
```

## AS Exchange

### AS_REQ

Client tạo pre-authentication data:

```json
{
  "client_principal": "alice@DEMO.LOCAL",
  "realm": "DEMO.LOCAL",
  "timestamp": 1780770148.123,
  "ctime": 1780770148,
  "cusec": 123000
}
```

Pre-authentication được mã hóa bằng `Kc` với key usage `1` (PA-ENC-TIMESTAMP).

AS_REQ ở góc nhìn logic. Trên wire, dữ liệu này được encode thành `AS-REQ ::= [APPLICATION 10] KDC-REQ`; `preauth` nằm trong `padata` type `PA-ENC-TIMESTAMP` dưới dạng `EncryptedData`:

```json
{
  "msg_type": "AS_REQ",
  "client_principal": "alice@DEMO.LOCAL",
  "realm": "DEMO.LOCAL",
  "nonce": 123456789,
  "preauth": "E_Kc(preauth)",
  "preauth_enctype": 18
}
```

### AS Validation

AS kiểm tra:

- Realm trong request khớp realm KDC.
- Principal tồn tại trong DB.
- `preauth` giải mã được bằng khóa của client `Kc`.
- `ctime` trong preauth không bị lệch quá clock skew (5 phút).
- `ctime` + `cusec` chưa tồn tại trong replay cache (chống replay).

Nếu ok, AS sinh session key `Kc_tgs`.

### TGT (Ticket Granting Ticket)

TGT plaintext trước khi mã hóa bằng `Ktgs`:

```json
{
  "ticket_type": "TGT",
  "realm": "DEMO.LOCAL",
  "client_principal": "alice@DEMO.LOCAL",
  "server_principal": "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
  "client_tgs_session_key": "Kc_tgs",
  "authtime": 1780770148.123,
  "starttime": 1780770148.123,
  "endtime": 1780770748.123,
  "renew_till": 1780773748.123,
  "flags": ["initial", "pre_authent", "renewable"],
  "kvno": 1,
  "enctype": 18
}
```

### AS_REP

Trên wire, message là `AS-REP ::= [APPLICATION 11] KDC-REP`, có `ticket` là ASN.1 `Ticket` và `enc-part` là ASN.1 `EncryptedData`.

```json
{
  "msg_type": "AS_REP",
  "realm": "DEMO.LOCAL",
  "client_principal": "alice@DEMO.LOCAL",
  "encrypted_data": "E_Kc(client_part)",
  "tgt": "E_Ktgs(TGT)"
}
```

Client part chứa:

```json
{
  "client_tgs_session_key": "Kc_tgs",
  "server_principal": "krbtgt/DEMO.LOCAL@DEMO.LOCAL",
  "nonce": 123456789,
  "authtime": 1780770148.123,
  "starttime": 1780770148.123,
  "endtime": 1780770748.123,
  "renew_till": 1780773748.123,
  "flags": ["initial", "pre_authent", "renewable"]
}
```

Client kiểm nonce để phát hiện response không khớp request.

## TGS Exchange

### TGS_REQ

Authenticator:

```json
{
  "client_principal": "alice@DEMO.LOCAL",
  "realm": "DEMO.LOCAL",
  "timestamp": 1780770158.123,
  "ctime": 1780770158,
  "cusec": 123000
}
```

Authenticator được mã hóa bằng `Kc_tgs`.

TGS_REQ ở góc nhìn logic. Trên wire, dữ liệu này được encode thành `TGS-REQ ::= [APPLICATION 12] KDC-REQ`; TGT và authenticator nằm trong `PA-TGS-REQ` dưới dạng `AP-REQ` DER:

```json
{
  "msg_type": "TGS_REQ",
  "realm": "DEMO.LOCAL",
  "service_principal": "fileserver/localhost@DEMO.LOCAL",
  "tgt": "E_Ktgs(TGT)",
  "authenticator": "E_Kc_tgs(authenticator)",
  "nonce": 987654321
}
```

### TGS Validation

TGS kiểm tra:

- TGT giải mã được bằng `Ktgs`.
- Realm trong request khớp realm KDC.
- `server_principal` trong TGT là `krbtgt/DEMO.LOCAL@DEMO.LOCAL`.
- Realm trong TGT khớp realm KDC.
- TGT chưa hết hạn.
- Authenticator giải mã được bằng `Kc_tgs`.
- Principal trong authenticator khớp principal trong TGT.
- Timestamp nằm trong clock skew.
- Replay cache chưa có cùng `(client, service, ctime, cusec)`.
- Service principal tồn tại và có type `service`.

### Service Ticket

Service ticket plaintext trước khi mã hóa bằng `Kservice`:

```json
{
  "ticket_type": "SERVICE",
  "realm": "DEMO.LOCAL",
  "client_principal": "alice@DEMO.LOCAL",
  "server_principal": "fileserver/localhost@DEMO.LOCAL",
  "client_service_session_key": "Kc_service",
  "authtime": 1780770148.123,
  "starttime": 1780770158.123,
  "endtime": 1780770748.123,
  "flags": ["pre_authent", "renewable"],
  "kvno": 1,
  "enctype": 18
}
```

### TGS_REP

Trên wire, message là `TGS-REP ::= [APPLICATION 13] KDC-REP`.

```json
{
  "msg_type": "TGS_REP",
  "realm": "DEMO.LOCAL",
  "client_principal": "alice@DEMO.LOCAL",
  "service_principal": "fileserver/localhost@DEMO.LOCAL",
  "encrypted_data": "E_Kc_tgs(client_part)",
  "service_ticket": "E_Kservice(ST)"
}
```

Client part chứa `Kc_service`, nonce, service principal, flags và thời gian hiệu lực. Service ticket luôn có `pre_authent`; nếu TGT có `renewable` hoặc `forwardable`, TGS giữ lại các flag tương ứng.

## AP Exchange (Mô phỏng HTTP SPNEGO - RFC 4559)

Pha AP Exchange không còn truyền nhận gói tin nhị phân qua TCP Socket thô. Thay vào đó, nó mô phỏng cơ chế GSS-API / SPNEGO qua HTTP.

### Bắt tay HTTP SPNEGO (Negotiate)

1. **GET không xác thực**: Client gửi HTTP GET request ban đầu.
2. **HTTP 401 Challenge**: Server phản hồi `401 Unauthorized` kèm header:
   ```http
   WWW-Authenticate: Negotiate
   ```
3. **GET có xác thực**: Client chuẩn bị gói tin `AP-REQ` dưới dạng DER, mã hóa Base64 và gửi lại request GET kèm header:
   ```http
   Authorization: Negotiate <Base64(AP-REQ DER)>
   ```
4. **HTTP 200 OK**: Server xác thực thành công, phản hồi `200 OK` kèm header:
   ```http
   WWW-Authenticate: Negotiate <Base64(AP-REP DER)>
   ```

### AP_REQ

Cấu trúc logic của `AP-REQ` nhị phân (sau khi giải mã Base64 từ Negotiate token) tuân theo `AP-REQ ::= [APPLICATION 14]`:

```json
{
  "msg_type": "AP_REQ",
  "service_principal": "fileserver/localhost@DEMO.LOCAL",
  "service_ticket": "E_Kservice(ST)",
  "authenticator": "E_Kc_service(authenticator)"
}
```

Authenticator tương tự TGS authenticator nhưng được mã hóa bằng `Kc_service`.

### AP Validation

Application Server giải mã Base64 token từ header `Authorization: Negotiate <token>`, chuyển thành gói tin DER và kiểm tra:

- Service ticket giải mã được bằng key từ keytab.
- `server_principal` trong ticket khớp principal của service.
- Realm trong ticket khớp realm của service.
- Ticket chưa hết hạn.
- Authenticator giải mã được bằng `Kc_service`.
- Principal trong authenticator khớp ticket.
- Timestamp nằm trong clock skew.
- Replay cache chưa có cùng `(client, server, ctime, cusec)`.

### AP_REP

Server trả phản hồi `AP-REP` được mã hóa Base64 và đặt trong header `WWW-Authenticate: Negotiate <ap_rep_token>`. Cấu trúc nhị phân của `AP-REP` là `AP-REP ::= [APPLICATION 15]`:

```json
{
  "msg_type": "AP_REP",
  "service_principal": "fileserver/localhost@DEMO.LOCAL",
  "encrypted_data": "E_subkey(ctime, cusec, subkey, seq_number)"
}
```

Client giải mã AP_REP sử dụng `client_subkey` đã gửi (nếu có, hoặc khóa phiên `Kc_service`) và kiểm `ctime`/`cusec` từ authenticator gốc để xác minh mutual authentication. Đồng thời, hai bên thương lượng khóa con (subkey) và số thứ tự (sequence number) cho các thông điệp tiếp theo.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant C as Client
    participant AS as KDC AS
    participant TGS as KDC TGS
    participant S as fileserver

    C->>AS: AS_REQ(cname, realm, nonce, preauth, kdc_options=['renewable'])
    AS->>AS: Validate preauth with Kc
    AS-->>C: AS_REP(E_Kc(Kc_tgs, nonce, times, flags), TGT)
    C->>C: Cache TGT

    Note over C,AS: [TGT Renewal (Nếu hết hạn endtime)]
    C->>TGS: TGS_REQ(TGT, krbtgt, nonce, authenticator, kdc_options=['renew'])
    TGS->>TGS: Decrypt TGT, verify renew_till, reissue TGT
    TGS-->>C: TGS_REP(E_old_Kc_tgs(new_Kc_tgs), renewed_TGT)
    C->>C: Update Cache with renewed TGT

    C->>TGS: TGS_REQ(TGT, sname, nonce, authenticator)
    TGS->>TGS: Validate TGT & authenticator; copy authorization-data (groups)
    TGS-->>C: TGS_REP(E_Kc_tgs(Kc_service, nonce, times), ST)
    C->>C: Cache service ticket (ST)

    Note over C,S: [AP Exchange via HTTP SPNEGO (RFC 4559)]
    C->>S: HTTP GET /
    S-->>C: HTTP 401 Unauthorized (WWW-Authenticate: Negotiate)
    C->>S: HTTP GET / (Authorization: Negotiate Base64(AP_REQ))
    S->>S: Validate ST, extract groups, enforce RBAC, extract client subkey
    S-->>C: HTTP 200 OK (WWW-Authenticate: Negotiate Base64(AP_REP))
```

## Các Tính Năng Nâng Cao (Advanced Features)

### 1. Subkey & Sequence Number Handshake
Trong quá trình xác thực dịch vụ (AP Exchange):
- **Client** tạo ngẫu nhiên một khóa con dùng riêng (`client_subkey`) và số thứ tự bắt đầu (`seq-number`), đặt chúng vào cấu trúc `Authenticator` gửi đi trong `AP-REQ`.
- **Server (Application Server)** trích xuất `client_subkey` này để mã hóa gói tin phản hồi `AP-REP`. Đồng thời, Server sinh thêm khóa con (`server_subkey`) và số thứ tự của Server (`seq-number`) gửi lại cho Client trong `EncAPRepPart`.
- Việc thương lượng này giúp phân tách và bảo mật các thông tin trao đổi dữ liệu sau đó (không dùng trực tiếp khóa phiên gốc `Kc_service`).

### 2. Gia hạn vé (TGT Renewal)
- Khi yêu cầu vé TGT lần đầu ở AS Exchange, Client có thể yêu cầu cờ gia hạn bằng việc chỉ định cờ `renewable` trong `kdc-options` của `AS-REQ`.
- Vé TGT sẽ được cấp với cờ `renewable` và hạn gia hạn tối đa `renew-till` (ví dụ: 1 giờ hoặc 7 ngày).
- Khi vé TGT gần hết hạn hoặc đã hết hạn `endtime` (nhưng chưa quá hạn `renew-till`), Client gửi một yêu cầu `TGS-REQ` lên KDC với cờ `renew` trong `kdc-options` và đính kèm vé TGT cũ.
- KDC kiểm tra tính hợp lệ của TGT (đặc biệt là `renew-till`), cấp lại một TGT mới có thời gian hiệu lực `endtime` được gia hạn thành công (cực trị là `renew-till`).

### 3. Dữ liệu ủy quyền (Authorization Data - PAC / RBAC)
- KDC lưu trữ thông tin nhóm/vai trò của người dùng trong cơ sở dữ liệu (cột `groups` của bảng `principals` dạng mảng JSON).
- Khi cấp TGT hoặc Service Ticket, KDC trích xuất thông tin này và mã hóa nó vào trường `authorization-data` (tag 10) của vé dưới dạng cấu trúc ASN.1 `AuthorizationData`.
- Tại **Application Server**, khi giải mã Service Ticket, Server trích xuất `authorization-data` và phân quyền dựa trên vai trò (RBAC).
  - Ví dụ: Tài khoản `alice@DEMO.LOCAL` thuộc nhóm `["users", "admins"]` được cấp quyền **Admin Access** để truy cập tài nguyên quản trị.
  - Tài khoản `bob@DEMO.LOCAL` chỉ thuộc nhóm `["users"]` chỉ được truy cập tài nguyên thường (**User Access**).
