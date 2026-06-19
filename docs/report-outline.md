# Dàn Ý Báo Cáo - KerberosAuthentication

Tài liệu này là dàn ý báo cáo chi tiết cho project KerberosAuthentication. Báo cáo nên trình bày rõ: dự án mô phỏng Kerberos V5 dựa trên RFC 4120 ở mức cấu trúc và hành vi, cả message ngoài và các payload mã hóa bên trong đều đã được đóng gói nhị phân bằng cấu trúc ASN.1/DER chuẩn hóa. Hệ thống hỗ trợ các enctype chuẩn `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96` thông qua mã hóa AES-CTS, checksum HMAC-SHA1-96, Key Usage và dẫn xuất khóa theo đúng RFC 3961/3962.

## 1. Giới Thiệu

- Lý do cần giao thức xác thực trong môi trường mạng không an toàn.
- Vấn đề của việc gửi mật khẩu trực tiếp qua network.
- Vai trò của Kerberos trong hệ thống phân tán và môi trường doanh nghiệp.
- Mục tiêu của project:
  - Mô phỏng luồng AS/TGS/AP.
  - Minh họa ticket, session key và authenticator.
  - Minh họa pre-authentication, replay protection và mutual authentication.
- Phạm vi của project:
  - Dùng Python, TCP socket, ASN.1/DER (thư viện `pyasn1`), SQLite và PyCryptodome.
  - Đã triển khai thuật toán mật mã Kerberos chuẩn (AES-CTS, HMAC-SHA1-96, Key Usage, nfold + PBKDF2-HMAC-SHA1 + DK/DR).

## 2. Cơ Sở Lý Thuyết Kerberos V5

- Tổng quan Kerberos V5 theo RFC 4120.
- Khái niệm Key Distribution Center.
- Vai trò của Authentication Server.
- Vai trò của Ticket Granting Server.
- Principal và realm:
  - User principal: `alice@DEMO.LOCAL`.
  - TGS principal: `krbtgt/DEMO.LOCAL@DEMO.LOCAL`.
  - Service principal: `fileserver/localhost@DEMO.LOCAL`.
- Ticket Granting Ticket.
- Service ticket.
- Long-term key và session key.
- Authenticator.
- Clock skew và replay attack.
- Mutual authentication.

## 3. Mục Tiêu Thiết Kế

- Không truyền password plaintext.
- Tách rõ ba pha AS, TGS và AP.
- Dùng KDC làm trusted third party.
- Ticket chỉ đọc được bởi server đích.
- Client nhận session key qua encrypted client part.
- Service xác thực client thông qua service ticket và authenticator.
- Client xác thực ngược lại service bằng AP_REP.
- Có database principal, keytab, credential cache, replay cache và audit log.

## 4. Kiến Trúc Hệ Thống

- Thành phần chính:
  - Client CLI.
  - Credential Cache.
  - KDC Server.
  - AS Handler.
  - TGS Handler.
  - KDC Database.
  - Application Server.
  - Keytab.
  - Crypto utilities.
  - Network utilities.
  - ASN.1/DER codec.
  - Principal utilities.
  - Replay cache.
- Sơ đồ tổng quan:

```text
Client -> KDC AS -> Client -> KDC TGS -> Client -> Application Server
```

- Mô hình giao tiếp:
  - TCP socket.
  - 4-byte big-endian length prefix.
  - ASN.1/DER payload mặc định.
  - JSON fallback chỉ để debug.
- Mô hình concurrency:
  - Mỗi connection được xử lý bằng một thread.

## 5. Mô Hình Dữ Liệu

- SQLite database `kdc/database.db`.
- Bảng `principals`:
  - `principal_name`.
  - `principal_type`.
  - `realm`.
  - `salt`.
  - `key`.
  - `kvno`.
  - `enctype`.
  - `kdf`.
  - `iterations`.
  - `disabled`.
- Bảng `principal_aliases`.
- Bảng `audit_log`.
- Bảng `replay_cache`.
- Keytab (định dạng nhị phân MIT Keytab v2):
  - Principal.
  - Realm.
  - KVNO.
  - Enctype.
  - Key.
- Credential cache (định dạng nhị phân MIT ccache v4 subset):
  - TGT.
  - Service ticket.
  - Session key.
  - Metadata thời hạn.

## 6. Chi Tiết Hiện Thực Giao Thức

### 6.1 AS Exchange

- Client chuẩn hóa username thành principal.
- Client dẫn xuất `Kc` bằng PBKDF2-HMAC-SHA1 + DK với salt theo principal.
- Client tạo pre-authentication data gồm principal, realm, timestamp, `ctime`, `cusec`.
- Client encode outer `AS-REQ` bằng ASN.1/DER.
- AS kiểm tra principal, decrypt pre-authentication data và kiểm clock skew.
- AS sinh `Kc_tgs`.
- AS cấp TGT mã hóa bằng `Ktgs`.
- AS trả encrypted client part mã hóa bằng `Kc`.
- Client kiểm nonce và lưu TGT vào credential cache.

### 6.2 TGS Exchange

- Client lấy TGT và `Kc_tgs` từ cache.
- Client tạo authenticator mã hóa bằng `Kc_tgs`.
- Client encode outer `TGS-REQ` bằng ASN.1/DER; `PA-TGS-REQ` chứa `AP-REQ` DER.
- TGS decrypt TGT bằng `Ktgs`.
- TGS kiểm `server_principal`, `endtime`, authenticator, principal match và replay cache.
- TGS kiểm service principal tồn tại.
- TGS sinh `Kc_service`.
- TGS cấp service ticket mã hóa bằng service key.
- Client decrypt TGS_REP, kiểm nonce và lưu service ticket.

### 6.3 AP Exchange

- Client lấy service ticket và `Kc_service` từ cache.
- Client tạo authenticator mã hóa bằng `Kc_service`.
- Client encode outer `AP-REQ` bằng ASN.1/DER.
- Application Server decrypt service ticket bằng keytab key.
- Server kiểm service principal, ticket lifetime, authenticator và replay cache.
- Server trả AP_REP mã hóa bằng `Kc_service`.
- Client kiểm `ctime/cusec` trong AP_REP trùng Authenticator ban đầu để xác nhận mutual authentication.

## 7. Cơ Chế Mật Mã Và Bảo Vệ

- PBKDF2-HMAC-SHA1 dẫn xuất khóa với 4096 iterations mặc định và derive-random DK theo RFC 3962.
- Salt theo chuẩn `REALMusername`.
- Session key ngẫu nhiên bằng `os.urandom(16)` hoặc `os.urandom(32)`.
- Mã hóa đối xứng AES-CTS kết hợp checksum HMAC-SHA1-96 bảo vệ tính bảo mật và toàn vẹn của payload.
- ASN.1/DER cho outer message AS/TGS/AP/KRB-ERROR/Ticket.
- Ticket lifetime và renewable lifetime.
- `ctime/cusec` trong authenticator.
- Persistent replay cache bằng SQLite.
- Keytab nhị phân MIT Keytab v2 cho service key.
- Credential cache nhị phân MIT ccache v4 subset cho client.
- Audit log trong KDC.

## 8. Đối Chiếu Với RFC 4120

Đã mô phỏng:

- Realm và principal.
- AS_REQ/AS_REP.
- TGS_REQ/TGS_REP.
- AP_REQ/AP_REP.
- ASN.1/DER application tag và field chính cho AS/TGS/AP/KRB-ERROR/Ticket.
- TGT và service ticket.
- Session key.
- Authenticator.
- Ticket flags và lifetime.
- Cấu trúc ASN.1/DER cho cả outer message và các inner encrypted parts.
- Kerberos enctype (aes256-cts-hmac-sha1-96/aes128-cts-hmac-sha1-96), checksum (HMAC-SHA1-96), key usage chuẩn (RFC 3961/3962/4120).
- Tiện ích CLI `kadmin.py` quản trị DB của KDC.

Chưa triển khai:

- Tương thích trực tiếp 100% với OS APIs (GSSAPI/SSPI).
- Kênh truyền bảo mật TLS/mTLS cho các socket TCP.

## 9. Thử Nghiệm Và Kết Quả

- Kiểm tra cú pháp bằng `py_compile`.
- Happy path:
  - `alice/alice_password`.
  - AS thành công.
  - TGS thành công.
  - AP thành công.
- Sai password:
  - `alice/wrong_password`.
  - AS trả `KDC_ERR_PREAUTH_FAILED`.
- Unknown principal:
  - AS trả `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
- Unknown service:
  - TGS trả `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
- Wrong realm:
  - AS/TGS trả `KDC_ERR_WRONG_REALM`.
- Replay authenticator:
  - TGS/AP trả `KRB_AP_ERR_REPEAT`.
- Ticket hết hạn:
  - TGS/AP trả `KRB_AP_ERR_TKT_EXPIRED`.
- Ticket chưa tới thời gian hiệu lực:
  - TGS/AP trả `KRB_AP_ERR_TKT_NYV`.
- Ticket sai service:
  - AP trả `KRB_AP_ERR_MODIFIED`.

## 10. Phân Tích Bảo Mật

- Password không đi qua network.
- KDC là trusted third party.
- TGT chỉ TGS đọc được.
- Service ticket chỉ service đọc được.
- Authenticator giới hạn replay trong clock skew.
- Replay cache giảm rủi ro gửi lại authenticator.
- AP_REP cung cấp xác thực hai chiều.
- Rủi ro nếu lộ credential cache.
- Rủi ro nếu lộ keytab.
- Rủi ro nếu lộ KDC DB hoặc key `krbtgt`.
- Hạn chế do chưa có secret manager, TLS, authorization và rate limiting.

- Thêm kênh bảo mật TLS/mTLS bảo vệ các socket TCP.
- Thêm key rotation và KVNO history.
- Thêm permission hardening cho các file keytab và credential cache nhị phân.
- Thêm rate limiting và account lockout.
- Thêm audit log phía Application Server.
- Tách config thành các file cấu hình ngoài (YAML/INI).

## 12. Kết Luận

- Tổng kết các thành phần đã xây dựng.
- Nêu rõ project đã mô phỏng đúng luồng Kerberos V5 cốt lõi.
- Khẳng định giá trị học thuật của việc tự xây dựng AS/TGS/AP.
- Nêu giới hạn production để tránh hiểu nhầm.
- Đề xuất hướng nâng cấp tiếp theo.
