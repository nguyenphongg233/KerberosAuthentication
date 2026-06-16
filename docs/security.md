# Ghi Chú Bảo Mật

Tài liệu này mô tả mô hình bảo mật của project KerberosAuthentication, các cơ chế đã triển khai, phạm vi mô phỏng so với Kerberos V5 và các rủi ro còn lại. Project sử dụng RFC 4120, RFC 3961, và RFC 3962 làm cơ sở thiết kế. Cả message ngoài (outer wire messages) và các cấu trúc mã hóa bên trong (inner encrypted payloads) đều tuân theo chuẩn ASN.1/DER (sử dụng `pyasn1`). Dữ liệu được mã hóa bằng thuật toán đối xứng AES-CTS kết hợp mã xác thực HMAC-SHA1-96 (enctype `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96`) cùng với cơ chế Key Usage dẫn xuất khóa chuẩn.

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
| Long-term client key | Dẫn xuất bằng PBKDF2-HMAC-SHA1 với salt `REALMusername` và derive-random (DK) theo chuẩn RFC 3962 |
| TGS key | Lưu trong KDC DB, dùng để mã hóa TGT |
| Service key | Lưu trong KDC DB và export ra keytab nhị phân chuẩn MIT Keytab v2 cho Application Server |
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
| Long-term client key `Kc` | SQLite `kdc/database.db`, bảng `principals`, cột `key`; client chỉ derive tạm thời từ password khi chạy | Nếu KDC DB bị lộ, attacker có thể thử giả mạo principal hoặc brute force password yếu | PBKDF2-HMAC-SHA1 với salt `REALMusername` (ví dụ `DEMO.LOCALalice`) và hằng "kerberos" để derive-random chuẩn RFC 3962. |
| Long-term TGS key `Ktgs` | SQLite `kdc/database.db`, principal `krbtgt/DEMO.LOCAL@DEMO.LOCAL` | Nếu lộ `Ktgs`, attacker có thể forge hoặc decrypt TGT trong demo | Không export ra keytab; chỉ KDC dùng. |
| Long-term service key `Kservice` | SQLite `kdc/database.db` và keytab nhị phân `app_server/<APP_SERVICE_NAME>.keytab` | Nếu keytab bị lộ, attacker có thể decrypt service ticket hoặc giả lập service | Application Server đọc keytab nhị phân thay vì hard-code key trong code. |
| Session key `Kc_tgs` | Trong TGT, trong encrypted client part của AS-REP, và trong credential cache nhị phân `client/krb5cc_demo` | Nếu credential cache bị lộ, attacker có thể dùng TGT còn hạn | Ticket có lifetime; cache bỏ entry hết hạn. |
| Session key `Kc_service` | Trong service ticket, trong encrypted client part của TGS-REP, và trong credential cache nhị phân `client/krb5cc_demo` | Nếu credential cache bị lộ, attacker có thể truy cập service trong thời hạn ticket | Ticket có lifetime; Application Server kiểm replay và endtime. |
| Replay state | SQLite table `replay_cache` | Không phải secret, nhưng mất cache có thể giảm khả năng phát hiện replay sau restart | Dùng SQLite persistent cache thay vì memory-only cache. |

Các file quan trọng cần bảo vệ khi chạy demo là `kdc/database.db`, `app_server/<APP_SERVICE_NAME>.keytab` và `client/krb5cc_demo`. Đây là các runtime artifact, không nên commit lên repository và nên đặt quyền file chặt nếu chạy ngoài môi trường học tập.

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
PBKDF2-HMAC-SHA1(password, salt, 1000 iterations) -> rồi dẫn xuất thông qua derive-random (DK) với hằng "kerberos" theo chuẩn RFC 3962.

Salt chuẩn Kerberos V5 được tạo theo principal dạng:

```text
REALMusername
```

Ví dụ:

```text
DEMO.LOCALalice
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

KDC sinh session key bằng `os.urandom(16)` (AES-128) hoặc `os.urandom(32)` (AES-256) theo enctype chuẩn. Session key có phạm vi ngắn hạn và được lưu trong credential cache của client cho tới khi ticket hết hạn.

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

KDC xuất file keytab nhị phân theo chuẩn **MIT Keytab v2**:

```text
app_server/<APP_SERVICE_NAME>.keytab (mặc định: app_server/fileserver.keytab)
```

Application Server tự động đọc keytab nhị phân này khi khởi chạy để nạp động các service key. Dự án không lưu password hay key cứng trong mã nguồn.

Giới hạn:
- Key trong keytab chưa được bảo vệ bằng OS key store hoặc secret manager bảo mật mức hệ thống.
- Code chưa tự set file permission chặt cho keytab (cần thực hiện thủ công bằng OS permission).

### Credential Cache

Client lưu trữ vé và session key trong credential cache nhị phân theo chuẩn **MIT ccache v4**:

```text
client/krb5cc_demo (hoặc client/krb5cc_partner tùy thuộc realm)
```

Cache chứa thông tin default principal, danh sách các credential (TGT, Service Ticket, session keys, flags và timestamps). Vé hết hạn sẽ tự động bị loại bỏ hoặc làm mới khi client đọc cache.

Giới hạn:
- Session key lưu dưới dạng nhị phân thô trong file ccache, có thể bị đánh cắp bởi user hoặc process có quyền đọc file trên máy cục bộ.
- Chưa có cơ chế cache isolation theo OS session.

## Crypto Model

Project sử dụng định dạng ASN.1/DER cho cả message ngoài và các cấu trúc mã hóa bên trong. Việc mã hóa sử dụng các thuật toán đối xứng chuẩn Kerberos V5 (AES-CTS kết hợp HMAC-SHA1-96 checksum) và dẫn xuất khóa (nfold + PBKDF2-HMAC-SHA1 + derive-random DK) tuân thủ RFC 3961/3962.

Trong project:

- `derive_key()` dùng PBKDF2-HMAC-SHA1 kết hợp `nfold` và `derive_random` với hằng "kerberos" theo chuẩn RFC 3962.
- `generate_session_key()` tạo khóa ngẫu nhiên 16 bytes hoặc 32 bytes tương ứng với các enctype AES-128 và AES-256.
- `core/asn1_codec.py` định nghĩa và encode/decode toàn bộ các cấu trúc ASN.1 DER (bao gồm cả outer message và inner encrypted parts như `EncTicketPart`, `EncKDCRepPart`, `Authenticator`, `EncAPRepPart`, `PaEncTimestamp`).
- `encrypt()` mã hóa dữ liệu sử dụng chế độ AES-CTS tự triển khai cùng checksum HMAC-SHA1-96, áp dụng Key Usage thích hợp.
- `decrypt()` giải mã và xác minh tính toàn vẹn của dữ liệu thông qua so sánh checksum HMAC-SHA1-96, áp dụng Key Usage tương ứng.

Ưu điểm nổi bật:
- Triển khai chuẩn các enctype `aes256-cts-hmac-sha1-96` (18) và `aes128-cts-hmac-sha1-96` (17).
- Hỗ trợ đầy đủ Key Usage theo đặc tả của RFC 4120.
- Checksum HMAC-SHA1-96 được tính toán trên ciphertext để bảo vệ tính toàn vẹn.
- Toàn bộ dữ liệu trao đổi (cả phần header và phần payload mã hóa) đều được đóng gói và serialize dưới dạng ASN.1 DER nhị phân chuẩn.

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

Dù dự án đã tích hợp nhiều tính năng nâng cao (như mã hóa chuẩn AES-CTS với HMAC-SHA1-96, xác thực chéo Realm, subkey/seq-number, authorization data/PAC, ccache/keytab nhị phân chuẩn MIT và KAdmin Web Console/REST API), hệ thống vẫn chưa phải là một Kerberos production hoàn chỉnh do:

- Chưa hỗ trợ đầy đủ các tính năng principal canonicalization theo policy KDC/DNS.
- Chưa hỗ trợ luồng ủy quyền chuyển tiếp vé phức tạp (forward/delegate) đầy đủ.
- Chưa tích hợp mã hóa kênh truyền TLS/mTLS cho các socket TCP (metadata như IP, port và timing của bản tin wire ASN.1 vẫn có thể bị quan sát).
- Chưa tích hợp với Secret Manager chuyên dụng, cơ chế tự động key rotation định kỳ và tự động hard-lock file permission.
- Chưa triển khai rate limiting và account lockout để chống brute-force tấn công pre-authentication trực tiếp ở KDC.

## Threat Model

### Attacker nghe lén network

Password không đi qua network. Ticket, pre-authentication data và authenticator đều được mã hóa. Tuy vậy attacker vẫn quan sát được metadata như IP, port, timing, message length và connection pattern.

### Attacker replay packet

Replay authenticator trong TGS/AP bị chặn bằng SQLite replay cache nếu replay xảy ra trong `MAX_CLOCK_SKEW`. Replay ngoài cửa sổ thời gian sẽ phụ thuộc vào ticket lifetime và timestamp validation.

### Attacker sửa packet

Payload bị sửa đổi thường dẫn tới việc xác minh checksum HMAC-SHA1-96 thất bại. Server sẽ ném ngoại lệ `InvalidToken` và trả về mã lỗi tương ứng như `KRB_AP_ERR_MODIFIED` hoặc `KDC_ERR_PREAUTH_FAILED`.

### Attacker lấy được credential cache client

Nếu attacker đọc được `client/krb5cc_demo`, họ có thể lấy ticket và session key còn hiệu lực. Đây tương đương rủi ro pass-the-ticket trong thời gian ticket chưa hết hạn.

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

1. Thêm permission hardening cho keytab và credential cache ở cấp hệ điều hành (đọc/ghi giới hạn cho process chạy dịch vụ/client).
2. Thêm rate limiting cho AS pre-authentication failure tại KDC để hạn chế brute force password.
3. Thêm test tự động kiểm tra replay, tampering, expiration, wrong realm và wrong service.
4. Thêm audit log chi tiết cho Application Server.
5. Tách replay cache sang các hệ quản trị database phân tán hoặc Redis dùng chung hiệu năng cao hơn nếu mở rộng nhiều instance KDC.

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
| Keytab cho Application Server | Có, MIT Keytab v2 nhị phân |
| Credential cache bền vững | Có, MIT ccache v4 nhị phân |
| Replay cache bền vững | Có, SQLite |
| Mutual authentication | Có |
| Audit log KDC | Có |
| Xác thực chéo Realm (Cross-Realm Trust) | Có (2-hop TGS exchange) |
| Giao diện quản trị KAdmin / REST API | Có (Cổng 8088 với audit logs thực tế) |
| Secret manager | Chưa |
| Authorization/PAC | Có (RBAC nhóm admin/user nhúng trong ticket) |
| TLS/mTLS cho TCP channel | Chưa |
| Kerberos enctype/checksum/key usage chuẩn | Có (aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96) |
| Tương thích cấu trúc MIT Kerberos/Active Directory | Mô phỏng sát chuẩn ở mức cấu trúc lưu trữ và wire format |
