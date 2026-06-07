# Ghi Chú Bảo Mật

Tài liệu này mô tả mô hình bảo mật của project KerberosAuthentication, các cơ chế đã triển khai, phạm vi mô phỏng so với Kerberos V5 và các rủi ro còn lại. Project dùng RFC 4120 làm cơ sở khái niệm và đã dùng ASN.1/DER cho outer wire message, nhưng chưa tương thích Kerberos production vì `EncryptedData.cipher` vẫn chứa Fernet token demo thay vì Kerberos enctype/checksum/key usage chuẩn.

## Mục Tiêu Bảo Mật

Project hướng tới các mục tiêu sau:

- Không gửi password plaintext qua network.
- Client phải chứng minh biết long-term key ở pha AS bằng pre-authentication.
- KDC phân phối session key thông qua ticket đã mã hóa.
- Client không cần đọc plaintext ticket dành cho TGS hoặc service.
- Service chỉ chấp nhận ticket decrypt được bằng service key trong keytab.
- Ticket có thời hạn sử dụng rõ ràng: `authtime`, `starttime`, `endtime`, `renew_till`.
- Authenticator có `ctime/cusec` để giới hạn replay window.
- Replay cache chặn việc gửi lại cùng authenticator.
- AP_REP cho phép client xác thực ngược lại server.

## Tài Sản Được Bảo Vệ

| Tài sản | Cơ chế bảo vệ |
| --- | --- |
| User password | Không truyền qua network; chỉ dùng local để dẫn xuất long-term key |
| Long-term client key | Dẫn xuất bằng PBKDF2-HMAC-SHA256 với salt theo principal |
| TGS key | Lưu trong KDC DB, dùng để mã hóa TGT |
| Service key | Lưu trong KDC DB và export ra keytab JSON cho Application Server |
| Client-TGS session key | Mã hóa trong AS_REP bằng client key; nằm trong TGT mã hóa bằng TGS key |
| Client-Service session key | Mã hóa trong TGS_REP bằng client-TGS key; nằm trong service ticket mã hóa bằng service key |
| TGT | Mã hóa bằng TGS key |
| Service ticket | Mã hóa bằng service key |
| Authenticator | Mã hóa bằng session key tương ứng |
| Outer wire message | ASN.1/DER theo application tag RFC 4120 cho AS/TGS/AP/KRB-ERROR/Ticket |
| Replay state | SQLite replay cache |
| Sự kiện KDC | SQLite audit log |

## Vị Trí Lưu Khóa Và Secret

Bảng dưới đây là bản đồ lưu trữ khóa của project:

| Loại khóa / secret | Vị trí lưu | Rủi ro chính | Cách xử lý hiện tại |
| --- | --- | --- | --- |
| Password demo của `alice`, `bob`, TGS và service | Hằng bootstrap trong `kdc/database.py` | Lộ secret nếu dùng nguyên mẫu này cho môi trường thật | Chỉ dùng cho demo; password không gửi qua network. |
| Long-term client key `Kc` | SQLite `kdc/database.db`, bảng `principals`, cột `key`; client chỉ derive tạm thời từ password khi chạy | Nếu KDC DB bị lộ, attacker có thể thử giả mạo principal hoặc brute force password yếu | PBKDF2-HMAC-SHA256 với salt theo principal và 200.000 iterations. |
| Long-term TGS key `Ktgs` | SQLite `kdc/database.db`, principal `krbtgt/DEMO.LOCAL@DEMO.LOCAL` | Nếu lộ `Ktgs`, attacker có thể forge hoặc decrypt TGT trong demo | Không export ra keytab; chỉ KDC dùng. |
| Long-term service key `Kservice` | SQLite `kdc/database.db` và keytab JSON `app_server/<APP_SERVICE_NAME>.keytab.json` | Nếu keytab bị lộ, attacker có thể decrypt service ticket hoặc giả lập service | Application Server đọc keytab thay vì hard-code key trong code. |
| Session key `Kc_tgs` | Trong TGT, trong encrypted client part của AS-REP, và trong credential cache `client/krb5cc_demo.json` | Nếu credential cache bị lộ, attacker có thể dùng TGT còn hạn | Ticket có lifetime; cache bỏ entry hết hạn. |
| Session key `Kc_service` | Trong service ticket, trong encrypted client part của TGS-REP, và trong credential cache `client/krb5cc_demo.json` | Nếu credential cache bị lộ, attacker có thể truy cập service trong thời hạn ticket | Ticket có lifetime; Application Server kiểm replay và endtime. |
| Replay state | SQLite table `replay_cache` | Không phải secret, nhưng mất cache có thể giảm khả năng phát hiện replay sau restart | Dùng SQLite persistent cache thay vì memory-only cache. |

Các file quan trọng cần bảo vệ khi chạy demo là `kdc/database.db`, `app_server/<APP_SERVICE_NAME>.keytab.json` và `client/krb5cc_demo.json`. Đây là các runtime artifact, không nên commit lên repository và nên đặt quyền file chặt nếu chạy ngoài môi trường học tập.

## Pre-Authentication

Client gửi pre-authentication data trong AS_REQ:

```text
preauth = E_Kc({
  client_principal,
  realm,
  timestamp,
  ctime,
  cusec
})
```

AS chỉ cấp TGT nếu:

- Principal tồn tại trong database.
- Realm trong request là realm KDC đang phục vụ.
- Pre-authentication data decrypt được bằng key của principal.
- Principal và realm trong pre-authentication data khớp request.
- Timestamp nằm trong `MAX_CLOCK_SKEW`.

Cơ chế này giúp sai password bị từ chối ngay ở AS và tránh việc KDC cấp AS_REP hữu ích cho client không biết password.

## Key Derivation

Long-term key được dẫn xuất trong `core/crypto.py`:

```text
PBKDF2-HMAC-SHA256(password, salt, 200000 iterations, dklen=32)
```

Salt demo được tạo theo principal:

```text
REALM:principal
```

Ví dụ:

```text
DEMO.LOCAL:alice@DEMO.LOCAL
```

Điểm đã cải thiện:

- Không còn SHA-256 trực tiếp trên password.
- Mỗi principal có salt riêng.
- Database lưu metadata `kdf`, `iterations`, `salt`, `kvno`, `enctype`.

Giới hạn:

- Đây vẫn chưa phải Kerberos string-to-key chuẩn theo từng enctype.
- Không có password policy, account lockout hoặc rate limiting.
- Salt deterministic để client tự derive key trước AS_REQ; môi trường production cần chính sách mạnh hơn.

## Ticket Và Session Key

TGT chứa:

- `client_principal`.
- `server_principal = krbtgt/REALM@REALM`.
- `client_tgs_session_key`.
- `authtime`, `starttime`, `endtime`, `renew_till`.
- `flags`, `kvno`, `enctype`.

Service ticket chứa:

- `client_principal`.
- `server_principal = service/host@REALM`.
- `client_service_session_key`.
- `authtime`, `starttime`, `endtime`.
- `flags`, `kvno`, `enctype`.

KDC sinh session key bằng `os.urandom(32)` và encode thành Fernet-compatible key. Session key có phạm vi ngắn hạn và được lưu trong credential cache của client cho tới khi ticket hết hạn.

## Replay Protection

Replay cache được triển khai trong `core/replay_cache.py` và lưu ở SQLite table `replay_cache`.

TGS kiểm tra replay cho authenticator trong TGS_REQ:

```text
client_principal | service_principal | ctime | cusec
```

Application Server kiểm tra replay cho authenticator trong AP_REQ:

```text
client_principal | server_principal | ctime | cusec
```

Nếu fingerprint đã tồn tại trong cửa sổ `MAX_CLOCK_SKEW`, hệ thống trả:

```text
KRB_AP_ERR_REPEAT
```

Điểm đã cải thiện:

- Replay cache không còn chỉ nằm trong memory process.
- Restart process không xóa ngay replay state nếu vẫn dùng cùng SQLite file.

Giới hạn:

- Cache chưa phải distributed cache cho nhiều node.
- Không có cleanup job độc lập; entry cũ được xóa khi có request mới.
- Nếu dùng nhiều SQLite file khác nhau giữa các instance, replay state không được chia sẻ.

## Mutual Authentication

Application Server trả AP_REP:

```text
AP_REP = E_Kc_service({
  timestamp: client_timestamp + 1,
  ctime,
  service_principal,
  service_data
})
```

Client chỉ chấp nhận server nếu:

- AP_REP decrypt được bằng `Kc_service`.
- Timestamp trong AP_REP bằng timestamp client gửi cộng 1.

Cơ chế này chứng minh server đã decrypt được service ticket, lấy được `Kc_service` và đọc được authenticator hợp lệ.

## Keytab Và Credential Cache

### Keytab

KDC export keytab JSON:

```text
app_server/<APP_SERVICE_NAME>.keytab.json
```

Application Server đọc keytab khi start để lấy service key. Code không còn hard-code `SERVICE_PASSWORD` trong `service_server.py`.

Giới hạn:

- Keytab là JSON demo, không phải keytab binary chuẩn.
- Key trong keytab chưa được bảo vệ bằng OS key store hoặc secret manager.
- Code chưa tự set file permission chặt cho keytab.

### Credential Cache

Client lưu credential cache JSON:

```text
client/krb5cc_demo.json
```

Cache chứa TGT, service ticket, session key và metadata. Ticket hết hạn sẽ bị bỏ khi client đọc cache.

Giới hạn:

- Cache là JSON demo, không phải ccache chuẩn của MIT Kerberos.
- Session key lưu trong file cache ở dạng có thể đọc được bởi user/process có quyền đọc file.
- Chưa có cache isolation theo OS session.

## Crypto Model

Project dùng ASN.1/DER cho outer message và `cryptography.fernet.Fernet` để mã hóa plaintext dict bên trong `EncryptedData.cipher`. Fernet cung cấp encryption và integrity check ở mức library, phù hợp cho demo dễ đọc.

Trong project:

- `derive_key()` dùng PBKDF2-HMAC-SHA256.
- `generate_session_key()` dùng `os.urandom(32)`.
- `core/asn1_codec.py` encode/decode outer message DER.
- `encrypt()` serialize dict thành JSON rồi Fernet encrypt trước khi đặt token vào `EncryptedData.cipher`.
- `decrypt()` Fernet decrypt rồi parse JSON.

Giới hạn quan trọng:

- Không dùng Kerberos encryption types thật như AES CTS HMAC SHA1/SHA2.
- Không có key usage number theo Kerberos.
- Không có checksum theo RFC 3961.
- ASN.1/DER hiện mới bao phủ outer message; encrypted payload bên trong vẫn là demo.

## Bảo Mật Kênh Truyền Thông

Các kênh truyền trong project:

| Kênh | Message | Bảo vệ ở mức payload |
| --- | --- | --- |
| Client ↔ KDC/AS | `AS-REQ`, `AS-REP` | Pre-auth mã hóa bằng `Kc`; TGT mã hóa bằng `Ktgs`; client part mã hóa bằng `Kc`. |
| Client ↔ KDC/TGS | `TGS-REQ`, `TGS-REP` | Authenticator mã hóa bằng `Kc_tgs`; service ticket mã hóa bằng `Kservice`; client part mã hóa bằng `Kc_tgs`. |
| Client ↔ Application Server | `AP-REQ`, `AP-REP` | Service ticket mã hóa bằng `Kservice`; authenticator và AP-REP mã hóa bằng `Kc_service`. |
| AS ↔ TGS | Nội bộ trong cùng KDC process | Không có kênh mạng riêng; hai handler dùng chung KDC DB. |
| KDC ↔ Application Server | Không có kênh TCP runtime trực tiếp | Trust dựa trên service key trong KDC DB và keytab của Application Server. |

TCP channel hiện chưa có TLS/mTLS. ASN.1/DER chỉ là định dạng wire, không cung cấp mã hóa. Payload quan trọng được mã hóa ở tầng Kerberos demo, nhưng metadata như IP, port, timing, kích thước message và số lần kết nối vẫn có thể bị quan sát.

## Audit Log

KDC ghi audit log vào bảng `audit_log` cho các sự kiện chính:

- Khởi tạo database.
- Upsert principal.
- AS pre-authentication failure/success.
- TGT issuance.
- TGS TGT validation.
- TGS authenticator validation/replay.
- Service ticket issuance.

Giới hạn:

- Audit log mới tập trung ở KDC.
- Application Server chưa ghi audit log riêng.
- Chưa có log retention, export, correlation ID hoặc cảnh báo.

## Hạn Chế So Với Kerberos Production

Project chưa implement:

- Kerberos encryption types, checksum và key usage chuẩn.
- Cross-realm trust.
- Principal canonicalization đầy đủ theo policy KDC/DNS.
- Renew, forward, delegate flow đầy đủ.
- Subkey và sequence number.
- Authorization data/PAC như Active Directory.
- Keytab và ccache binary chuẩn.
- Secret manager, key rotation hoàn chỉnh và permission hardening.
- TLS/mTLS cho TCP channel.
- Principal management CLI/API.
- Rate limiting và account lockout.

## Threat Model

### Attacker nghe lén network

Password không đi qua network. Ticket, pre-authentication data và authenticator đều được mã hóa. Tuy vậy attacker vẫn quan sát được metadata như IP, port, timing, message length và connection pattern.

### Attacker replay packet

Replay authenticator trong TGS/AP bị chặn bằng SQLite replay cache nếu replay xảy ra trong `MAX_CLOCK_SKEW`. Replay ngoài cửa sổ thời gian sẽ phụ thuộc vào ticket lifetime và timestamp validation.

### Attacker sửa packet

Payload bị sửa thường làm Fernet decrypt fail. Server trả lỗi tương ứng như `KRB_AP_ERR_MODIFIED` hoặc `KDC_ERR_PREAUTH_FAILED`.

### Attacker lấy được credential cache client

Nếu attacker đọc được `client/krb5cc_demo.json`, họ có thể lấy ticket và session key còn hiệu lực. Đây tương đương rủi ro pass-the-ticket trong thời gian ticket chưa hết hạn.

### Attacker lấy được keytab

Nếu attacker đọc được keytab service, họ có thể decrypt service ticket dành cho service đó và giả lập service trong phạm vi demo.

### Attacker lấy được KDC DB

Nếu attacker lấy được SQLite database của KDC, mặc định là `kdc/database.db`, rủi ro rất nghiêm trọng:

- Có thể lấy long-term key đã dẫn xuất.
- Có thể forge TGT nếu lấy được key của `krbtgt`.
- Có thể forge service ticket nếu lấy được service key.
- Có thể brute force password yếu, dù PBKDF2 làm chậm hơn SHA-256 trực tiếp.

### Attacker điều khiển đồng hồ

Nếu làm đồng hồ lệch quá `MAX_CLOCK_SKEW`, attacker có thể gây lỗi xác thực. Project chưa có cơ chế đồng bộ thời gian hoặc kiểm soát NTP.

## Khuyến Nghị Nâng Cấp Tiếp

1. Thêm admin CLI cho tạo principal, disable principal và rotate key.
2. Thêm key version rotation thực sự cho TGS và service.
3. Thêm permission hardening cho keytab và credential cache.
4. Thêm rate limiting cho AS pre-authentication failure.
5. Thêm test tự động cho replay, tampering, expiration, wrong realm và wrong service.
6. Thêm audit log cho Application Server.
7. Tách replay cache sang backend dùng chung nếu mô phỏng nhiều instance.
8. Nếu mục tiêu là tương thích Kerberos thật, cần thay Fernet bằng enctype/checksum/key usage chuẩn và keytab/ccache chuẩn.

## Security Checklist

| Hạng mục | Trạng thái |
| --- | --- |
| Password không gửi plaintext qua network | Có |
| AS pre-authentication | Có |
| Nonce trong AS/TGS response | Có |
| ASN.1/DER outer wire format RFC 4120 | Có |
| Principal dạng `name@REALM` và `service/host@REALM` | Có |
| Realm mặc định | Có |
| Wrong realm rejection | Có |
| PBKDF2 với salt theo principal | Có |
| Ticket có flags và lifetime | Có |
| Keytab cho Application Server | Có, JSON demo |
| Credential cache bền vững | Có, JSON demo |
| Replay cache bền vững | Có, SQLite |
| Mutual authentication | Có |
| Audit log KDC | Có |
| Secret manager | Chưa |
| Authorization/PAC | Chưa |
| TLS/mTLS cho TCP channel | Chưa |
| Kerberos enctype/checksum/key usage chuẩn | Chưa |
| Tương thích MIT Kerberos/Active Directory | Chưa |
