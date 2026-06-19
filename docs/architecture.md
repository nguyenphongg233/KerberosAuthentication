# Kiến Trúc Hệ Thống

Tài liệu này mô tả kiến trúc hiện tại của KerberosAuthentication sau khi nâng cấp theo hướng mô phỏng sát RFC 4120 ở mức cấu trúc và hành vi.

## Phạm Vi Chuẩn Hóa

Project mô phỏng các khái niệm Kerberos V5 chính:

- Realm.
- Principal chuẩn kiểu `name@REALM` và `service/host@REALM`.
- AS, TGS và AP Exchange.
- TGT và service ticket.
- Session key riêng cho từng quan hệ.
- Ticket flags, authtime, starttime, endtime, renew_till.
- Key version number (`kvno`) và encryption type mô tả.
- Keytab cho service.
- Credential cache cho client.
- Replay cache và audit log.
- ASN.1/DER outer wire format cho các message chính trong AS/TGS/AP.

Project đã mô phỏng các Kerberos encryption types chuẩn bao gồm `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96` bằng thuật toán AES-CTS (Cipher Text Stealing) và mã xác thực HMAC-SHA1-96, áp dụng cơ chế Key Usage và dẫn xuất khóa (DK/DR) theo đúng RFC 3961/3962.

## Sơ Đồ Tổng Quan

```text
Client CLI
  | AS_REQ / AS_REP
  v
  KDC Server (Ports 8888, 8088 KAdmin Web Console)
  |-- Authentication Server Handler
  |-- Ticket Granting Server Handler
  |-- Principal DB (with Cross-Realm principals) / Audit Log / Replay Cache
  |
  | TGS_REQ / TGS_REP
  v
  Client Credential Cache (MIT ccache v4 subset)
  |
  | AP_REQ / AP_REP (HTTP Negotiate-style headers)
  v
  Application Server
  |-- MIT Keytab binary v2
  |-- Replay Cache
```

## Thành Phần

| Thành phần | File | Trách nhiệm |
| --- | --- | --- |
| Client CLI | `client/client_app.py` | Thực hiện AS/TGS/AP Exchange |
| Credential Cache | `client/credential_cache.py` | Lưu TGT, service ticket và session key trong file nhị phân **MIT ccache v4 subset** |
| KDC Server | `kdc/kdc_server.py` | TCP server, dispatch request đến AS/TGS |
| KDC Database | `kdc/database.py` | Schema, migration, principal store, alias, audit log, keytab export |
| AS Handler | `kdc/as_handler.py` | Pre-authentication, cấp TGT |
| TGS Handler | `kdc/tgs_handler.py` | Kiểm TGT/authenticator, cấp service ticket (hỗ trợ Cross-Realm) |
| Application Server | `app_server/service_server.py` | Đọc keytab nhị phân, xử lý AP_REQ, trả AP_REP qua HTTP Negotiate-style headers |
| Crypto | `core/crypto.py` | nfold, derive-random, AES-CBC-CTS, HMAC-SHA1-96, PBKDF2-HMAC-SHA1 |
| Principal | `core/principal.py` | Chuẩn hóa realm/principal |
| Keytab | `core/keytab.py` | Đọc/ghi keytab nhị phân chuẩn **MIT Keytab v2** |
| Replay Cache | `core/replay_cache.py` | Replay cache SQLite |
| ASN.1/DER Codec | `core/asn1_codec.py` | Encode/decode message Kerberos theo subset RFC 4120 |
| Network | `core/network.py` | TCP length-prefixed DER mặc định, JSON fallback khi debug |
| Constants | `core/messages.py` | Message type, error code, config |
| KAdmin Web | `kdc/kadmin_web.py` | Web Dashboard Glassmorphism (cổng 8088) quản trị principal và Audit Log thời gian thực |

## Principal Model

Realm mặc định:

```text
DEMO.LOCAL
```

Principal mặc định:

```text
alice@DEMO.LOCAL
bob@DEMO.LOCAL
krbtgt/DEMO.LOCAL@DEMO.LOCAL
fileserver/localhost@DEMO.LOCAL
```

Client có thể nhập alias `alice`; `core.principal.user_principal` sẽ chuẩn hóa thành `alice@DEMO.LOCAL`.

Service alias `fileserver` sẽ được chuẩn hóa thành `fileserver/localhost@DEMO.LOCAL`.

## Database Model

Database chính mặc định:

```text
kdc/database.db
```

Các bảng chính:

| Bảng | Vai trò |
| --- | --- |
| `principals` | Lưu principal, salt, key, kvno, enctype, kdf, trạng thái |
| `principal_aliases` | Map alias ngắn sang principal chuẩn |
| `principal_keys` | Lưu lịch sử long-term key theo `principal`/`kvno`/`enctype` |
| `audit_log` | Ghi sự kiện AS/TGS/KDC |
| `replay_cache` | Lưu authenticator fingerprint đã sử dụng |

Schema `principals` lưu:

- `principal_name`
- `principal_type`
- `realm`
- `salt`
- `key`
- `kvno`
- `enctype`
- `kdf`
- `iterations`
- `created_at`
- `updated_at`
- `disabled`

Schema `principal_keys` lưu nhiều phiên bản key của cùng một principal. Bảng `principals` vẫn giữ current key để AS/TGS tra cứu nhanh; khi `kadmin cpw` đổi password/key, `kvno` tăng lên và key cũ được giữ trong `principal_keys` để KDC vẫn giải mã được TGT cũ cho đến khi ticket hết hạn.

## Key Model

Long-term key được dẫn xuất bằng:

```text
PBKDF2-HMAC-SHA1(password, principal_salt, 4096 iterations) -> rồi dẫn xuất thông qua derive-random (DK) với hằng "kerberos" theo chuẩn RFC 3962
```

Salt chuẩn Kerberos V5:

```text
REALMusername
```

Ví dụ:

```text
DEMO.LOCALalice
```

Session key được sinh ngẫu nhiên bằng `os.urandom(16)` (đối với AES-128) hoặc `os.urandom(32)` (đối với AES-256) làm session key chuẩn Kerberos.

## Nơi Lưu Trữ Khóa

Các khóa trong project được lưu và sử dụng như sau:

| Loại khóa / secret | Nơi lưu | Bên sử dụng | Ghi chú |
| --- | --- | --- | --- |
| Password demo của user | Hằng bootstrap trong `kdc/database.py` | KDC khi khởi tạo principal; client nhập lại khi chạy | Password không được gửi qua network. Trong demo password mặc định là dữ liệu bootstrap, chưa phải secret manager. |
| Long-term client key `Kc` | SQLite `kdc/database.db`, bảng `principals`, cột `key` | AS dùng để kiểm pre-authentication | Client tự derive `Kc` từ password và salt khi chạy, không lưu `Kc` lâu dài. |
| Long-term TGS key `Ktgs` | SQLite `kdc/database.db`, bảng `principals`, principal `krbtgt/DEMO.LOCAL@DEMO.LOCAL` | AS mã hóa TGT; TGS giải mã TGT | Key này chỉ nằm trong KDC DB, không export ra keytab service. |
| Long-term service key `Kservice` | SQLite `kdc/database.db` và keytab nhị phân `app_server/<APP_SERVICE_NAME>.keytab` | TGS mã hóa service ticket; Application Server giải mã service ticket | KDC export keytab khi start; Application Server đọc keytab khi xử lý AP_REQ. |
| Client-TGS session key `Kc_tgs` | Trong TGT đã mã hóa bằng `Ktgs`; trong AS-REP client part đã mã hóa bằng `Kc`; sau đó nằm trong `client/krb5cc_demo` | Client và TGS | Do AS sinh ngẫu nhiên cho từng phiên TGT. |
| Client-Service session key `Kc_service` | Trong service ticket đã mã hóa bằng `Kservice`; trong TGS-REP client part đã mã hóa bằng `Kc_tgs`; sau đó nằm trong `client/krb5cc_demo` | Client và Application Server | Do TGS sinh ngẫu nhiên cho từng service ticket. |
| Ticket ciphertext | Credential cache client `client/krb5cc_demo` | Client lưu và gửi lại; TGS/Application Server giải mã phần ticket tương ứng | Client không cần đọc plaintext của TGT hoặc service ticket. |

Replay cache và audit log không lưu khóa. Replay cache chỉ lưu fingerprint của authenticator đã dùng; audit log chỉ ghi sự kiện vận hành.

Khi KDC khởi động, default principals chỉ được tạo nếu chưa tồn tại. Điều này tránh việc restart KDC ghi đè password/kvno đã đổi bằng `kadmin`.

## Keytab Model

KDC tự xuất keytab nhị phân **MIT Keytab v2** cho Application Server:

```text
app_server/<APP_SERVICE_NAME>.keytab
```

Keytab chứa:

- `principal`
- `realm`
- `kvno`
- `enctype`
- `key`

Khi KDC export lại cùng principal/kvno/enctype, entry cũ cùng slot được thay thế để tránh keytab phình do duplicate. Khi có nhiều kvno, Application Server dùng `kvno` và `enctype` trong outer `Ticket.enc-part` để chọn đúng entry; nếu request không có `kvno`, server chọn entry có kvno cao nhất.

Lệnh `kadmin.py ktadd --all-versions` có thể export toàn bộ key versions đã lưu cho một service principal. Điều này hữu ích sau key rotation vì service ticket cũ vẫn có thể còn hiệu lực trong thời gian ngắn.

## Credential Cache Model

Client lưu cache tại:

```text
client/krb5cc_demo
```

Cache chứa:

- TGT.
- Client-TGS session key.
- Metadata của TGT.
- Service ticket theo từng service principal.
- Client-Service session key.
- Metadata của service ticket.

Cache lưu ở định dạng **MIT ccache v4 subset**. Project thêm một authdata metadata entry riêng của demo để giữ các trường như `ticket_kvno` và `ticket_enctype` sau khi reload cache từ file. Đây không phải full outer `Ticket` DER như MIT Kerberos production, nhưng đủ để client dựng lại outer ticket fields khi gửi TGS/AP request trong demo.

Cache sẽ tự bỏ ticket nếu `endtime` đã hết hạn.

## Replay Cache Model

Replay cache nằm trong SQLite table `replay_cache`.

TGS replay key:

```text
client_principal | service_principal | ctime | cusec
```

AP replay key:

```text
client_principal | server_principal | ctime | cusec
```

Entry cũ hơn `MAX_CLOCK_SKEW` sẽ bị xóa khi có request mới.

## Threading

KDC và Application Server đều tạo thread riêng cho mỗi TCP connection:

```text
accept()
Thread(target=handle_client, daemon=True)
```

SQLite connection được mở riêng trong mỗi request KDC. Replay cache cũng mở connection ngắn hạn khi check-and-store.

## Giao Thức Truyền Thông Giữa Các Thành Phần

Project dùng TCP socket cho các kênh client-server. Mỗi message có frame:

```text
[4-byte big-endian length][DER payload]
```

`DER payload` là outer Kerberos message do `core/asn1_codec.py` encode/decode. `KRB_WIRE_FORMAT=der` là mặc định; `json` chỉ dùng khi debug legacy và mã hóa các field `bytes` dưới dạng Base64 trong JSON.

| Kênh | Endpoint | Message | Cách bảo vệ dữ liệu |
| --- | --- | --- | --- |
| Client ↔ KDC/AS | `KDC_HOST:KDC_PORT` | `AS-REQ`, `AS-REP`, `KRB-ERROR` | Pre-auth mã hóa bằng `Kc`; TGT mã hóa bằng `Ktgs`; client part mã hóa bằng `Kc`. |
| Client ↔ KDC/TGS | `KDC_HOST:KDC_PORT` | `TGS-REQ`, `TGS-REP`, `KRB-ERROR` | TGT mã hóa bằng `Ktgs`; authenticator mã hóa bằng `Kc_tgs`; service ticket mã hóa bằng `Kservice`; client part mã hóa bằng `Kc_tgs`. |
| Client ↔ Application Server | `APP_SERVER_HOST:APP_SERVER_PORT` | `AP-REQ`, `AP-REP`, `KRB-ERROR` | Service ticket mã hóa bằng `Kservice`; authenticator và AP-REP mã hóa bằng `Kc_service`. |
| AS ↔ TGS | Nội bộ trong cùng process `kdc.kdc_server` | Dispatch theo `msg_type` | Không có network riêng giữa AS và TGS trong demo; cả hai dùng chung KDC DB. |
| KDC ↔ Application Server | Không có kênh TCP runtime trực tiếp | Không trao đổi request/response runtime | Quan hệ tin cậy được thiết lập bằng `Kservice`: KDC lưu trong DB và export keytab; Application Server đọc keytab. |

Vì chưa có TLS/mTLS, DER chỉ là định dạng tuần tự hóa chứ không phải mã hóa kênh truyền. Tính bí mật của dữ liệu Kerberos nằm ở các payload được mã hóa bằng thuật toán đối xứng chuẩn Kerberos (AES-CTS + HMAC-SHA1-96) trong `EncryptedData.cipher`; các metadata như IP, port, thời điểm gửi và độ dài message vẫn có thể bị quan sát từ bên ngoài.

## Data Flow

### AS Exchange

1. Client chuẩn hóa principal.
2. Client derive `Kc` bằng PBKDF2 với salt theo principal.
3. Client gửi `AS-REQ` dạng DER, chứa `PA-ENC-TIMESTAMP` mã hóa chuẩn trong `padata`.
4. AS kiểm tra principal, pre-auth, timestamp.
5. AS cấp TGT mã hóa bằng `Ktgs`.
6. AS trả client portion mã hóa bằng `Kc`.

### TGS Exchange

1. Client gửi `TGS-REQ` dạng DER, trong đó `PA-TGS-REQ` chứa `AP-REQ` với TGT và authenticator.
2. TGS giải mã TGT bằng `Ktgs`.
3. TGS kiểm `starttime`, `endtime`, realm/service trong request, authenticator và replay cache.
4. TGS cấp service ticket mã hóa bằng service key.
5. TGS trả client portion mã hóa bằng `Kc_tgs`.

### AP Exchange (HTTP Negotiate-Style Demo)

1. Client gửi yêu cầu HTTP GET không có xác thực lên Application Server.
2. Server phản hồi `401 Unauthorized` kèm tiêu đề `WWW-Authenticate: Negotiate`.
3. Client sinh subkey/seq-number, mã hóa authenticator bằng khóa phiên, và gửi HTTP GET kèm tiêu đề `Authorization: Negotiate <Base64(AP-REQ DER)>`.
4. Server giải mã và xác minh `AP-REQ` (chọn keytab theo `kvno`/enctype, kiểm tra ticket, principal, `starttime`, `endtime`, authenticator, replay cache, và phân quyền group RBAC).
5. Nếu xác thực thành công, Server trả về phản hồi `200 OK` kèm tiêu đề `WWW-Authenticate: Negotiate <Base64(AP-REP DER)>`.
6. Client giải mã `AP-REP`, xác minh `ctime/cusec` trùng Authenticator ban đầu để hoàn tất mutual authentication (xác thực hai chiều).

## Ranh Giới Lỗi

| Lỗi | Nơi phát hiện | Error |
| --- | --- | --- |
| Client không tồn tại | AS | `KDC_ERR_C_PRINCIPAL_UNKNOWN` |
| Sai password/pre-auth | AS | `KDC_ERR_PREAUTH_FAILED` |
| Request sai realm | AS/TGS | `KDC_ERR_WRONG_REALM` |
| TGT sai key/bị sửa | TGS | `KRB_AP_ERR_MODIFIED` |
| Ticket hết hạn | TGS/AP | `KRB_AP_ERR_TKT_EXPIRED` |
| Ticket chưa tới thời gian hiệu lực | TGS/AP | `KRB_AP_ERR_TKT_NYV` |
| Clock skew quá lớn | AS/TGS/AP | `KRB_AP_ERR_SKEW` |
| Authenticator replay | TGS/AP | `KRB_AP_ERR_REPEAT` |
| Service không tồn tại | TGS | `KDC_ERR_S_PRINCIPAL_UNKNOWN` |
| Ticket không dành cho service hiện tại | AP | `KRB_AP_ERR_MODIFIED` |
