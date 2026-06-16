# KerberosAuthentication

KerberosAuthentication là dự án Python mô phỏng giao thức xác thực Kerberos V5 dựa trên các khái niệm trong [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120). Dự án tự xây dựng các thành phần cốt lõi gồm Client, Key Distribution Center, Authentication Server, Ticket Granting Server và Application Server để minh họa rõ quy trình cấp vé, phân phốiDự án đã được nâng cấp đầy đủ để đáp ứng các tiêu chuẩn mã hóa và định dạng của Kerberos V5. Cả message ngoài (outer wire messages) và tất cả các payload mã hóa bên trong (inner encrypted structures như `EncTicketPart`, `EncKDCRepPart`, `Authenticator`, `EncAPRepPart`, `PaEncTimestamp`) đều được định nghĩa và tuần tự hóa bằng ASN.1/DER (sử dụng thư viện `pyasn1`). Việc mã hóa sử dụng các enctype chuẩn `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96` với chế độ AES-CTS (Cipher Text Stealing) tự triển khai kết hợp checksum HMAC-SHA1-96, Key Usage và dẫn xuất khóa ($K_{enc}, K_{mac}$) theo RFC 3961/3962.

## Mục Lục

- [Tài Liệu Chi Tiết](#tài-liệu-chi-tiết)
- [Mức Độ Tuân Theo RFC 4120](#mức-độ-tuân-theo-rfc-4120)
- [Tính Năng Chính](#tính-năng-chính)
- [Công Nghệ Sử Dụng](#công-nghệ-sử-dụng)
- [Kiến Trúc Tổng Quan](#kiến-trúc-tổng-quan)
- [Cài Đặt](#cài-đặt)
- [Chạy Hệ Thống](#chạy-hệ-thống)
- [Principal Mặc Định](#principal-mặc-định)
- [Cấu Hình](#cấu-hình)
- [Luồng Giao Thức](#luồng-giao-thức)
- [Kiểm Tra Nhanh](#kiểm-tra-nhanh)
- [Giới Hạn Còn Lại](#giới-hạn-còn-lại)

## Tài Liệu Chi Tiết

| Tài liệu | Nội dung |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Kiến trúc tổng thể, module, database, keytab, replay cache và credential cache |
| [docs/protocol.md](docs/protocol.md) | Phân tích chi tiết AS Exchange, TGS Exchange và AP Exchange theo code hiện tại |
| [docs/message-reference.md](docs/message-reference.md) | Định dạng message ASN.1/DER, ticket, authenticator, error code và TCP framing |
| [docs/operations.md](docs/operations.md) | Cài đặt, chạy local, cấu hình, keytab, cache, troubleshooting và runbook |
| [docs/security.md](docs/security.md) | Mô hình bảo mật, threat model, điểm đạt được và hạn chế còn lại |
| [docs/development.md](docs/development.md) | Quy ước phát triển, test strategy và hướng mở rộng |

## Mức Độ Tuân Theo RFC 4120 / RFC 3961 / RFC 3962

Đã mô phỏng:

- Realm mặc định `DEMO.LOCAL`.
- Principal dạng Kerberos:
  - User: `alice@DEMO.LOCAL`.
  - TGS: `krbtgt/DEMO.LOCAL@DEMO.LOCAL`.
  - Service: `fileserver/localhost@DEMO.LOCAL`.
- AS Exchange với pre-authentication, nonce và AS_REP encrypted part.
- TGS Exchange với TGT, authenticator, nonce và service ticket.
- AP Exchange với service ticket, authenticator và AP_REP `timestamp + 1`.
- Tuần tự hóa toàn bộ: Cả outer message và các payload mã hóa bên trong (`EncTicketPart`, `EncKDCRepPart`, `Authenticator`, `EncAPRepPart`, `PaEncTimestamp`) đều được định nghĩa và mã hóa dưới dạng cấu trúc ASN.1/DER.
- Dẫn xuất khóa và mã hóa chuẩn Kerberos: Enctype `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96`, mã hóa AES-CTS (Cipher Text Stealing), mã xác thực HMAC-SHA1-96, và Key Usage dẫn xuất khóa ($K_{enc}, K_{mac}$) theo RFC 3961/3962.
- Ticket có `realm`, `client_principal`, `server_principal`, `authtime`, `starttime`, `endtime`, `renew_till`, `flags`, `kvno`, `enctype` và `authorization-data`.
- Hỗ trợ cờ gia hạn vé (`renewable` flag) và quy trình **Gia hạn vé TGT (TGT Renewal)** bằng cách gửi `TGS-REQ` có cờ `renew` trong `kdc-options` với TGT đã hết hạn lên KDC.
- Nhúng **Dữ liệu ủy quyền nhóm/vai trò (Authorization Data / PAC)** trong `EncTicketPart` để phân quyền dựa trên vai trò (RBAC) tại Application Server (File Server phân cấp quyền hiển thị cho `alice` [Admin] và `bob` [User]).
- **Subkey & Sequence Number Handshake** trong AP Exchange: Client sinh khóa con `client_subkey` và số thứ tự khởi đầu `seq-number` gửi trong Authenticator, Server trả về khóa con và số thứ tự của mình trong `EncAPRepPart` để hoàn tất bắt tay.
- Principal database có salt (`REALMusername`), PBKDF2 parameters, key version number (kvno) và principal aliases.
- Công cụ quản trị KDC database: Tiện ích CLI `kadmin.py` hỗ trợ các lệnh `add`, `delete`, `cpw`, `list`, `ktadd` trực tiếp trên database.
- Định dạng nhị phân **MIT Keytab v2** lưu trữ thông tin các service principal và khóa của chúng.
- Định dạng nhị phân **MIT ccache v4** lưu trữ thông tin credential cache an toàn cho client.
- Persistent replay cache trong SQLite.
- Audit log trong SQLite.

Chưa mô phỏng đầy đủ:

- Principal canonicalization đầy đủ theo DNS/KDC policy.
- Luồng ủy quyền chuyển tiếp vé (forward/delegate) đầy đủ.

## Tính Năng Chính

- Không truyền password plaintext qua network.
- Dùng PBKDF2-HMAC-SHA1 với salt theo principal dạng `REALMusername` để dẫn xuất long-term key chuẩn RFC 3962.
- Dùng KDC làm trusted third party.
- Tách logic AS và TGS thành hai handler riêng.
- Dùng TGT để xin service ticket.
- Dùng session key riêng cho Client-TGS và Client-Service.
- Dùng authenticator có `ctime/cusec` và timestamp để chống replay.
- Dùng SQLite replay cache để phát hiện authenticator bị gửi lại.
- Dùng keytab nhị phân **MIT Keytab v2** để Application Server lấy service key động.
- Dùng credential cache nhị phân **MIT ccache v4** để lưu trữ vé và session key giữa các phiên chạy của client.
- Dùng audit log để ghi các sự kiện chính của KDC.

## Công Nghệ Sử Dụng

| Thành phần | Công nghệ |
| --- | --- |
| Ngôn ngữ | Python 3.10+ |
| Giao tiếp mạng | TCP socket |
| Message format | ASN.1/DER mặc định, JSON tùy chọn để debug |
| TCP framing | 4-byte big-endian length prefix + DER payload |
| Database | SQLite |
| Mã hóa / Giải mã | AES-CTS (Cipher Text Stealing) + HMAC-SHA1-96 (`pycryptodome`) |
| KDF | PBKDF2-HMAC-SHA1, 1000 iterations (chuẩn RFC 3962) |
| Keytab | Định dạng nhị phân MIT Keytab v2 |
| Credential cache | Định dạng nhị phân MIT ccache v4 |
| Replay cache | SQLite table |
| ASN.1/DER | `pyasn1` |
| Concurrency | Thread cho từng connection |

## Kiến Trúc Tổng Quan

```text
Client
  | 1. AS_REQ / AS_REP
  v
KDC: Authentication Server (AS)
  |
  | 2. TGS_REQ / TGS_REP
  v
KDC: Ticket Granting Server (TGS)
  |
  | 3. AP_REQ / AP_REP
  v
Application Server: fileserver/localhost@DEMO.LOCAL
```

Các module chính:

- `client/client_app.py`: CLI client, thực hiện đủ ba pha Kerberos.
- `client/credential_cache.py`: credential cache nhị phân chuẩn MIT ccache v4.
- `kdc/kdc_server.py`: TCP server của KDC.
- `kdc/database.py`: schema/migration, principal store, aliases, audit log, keytab export.
- `kdc/as_handler.py`: AS Exchange.
- `kdc/tgs_handler.py`: TGS Exchange.
- `app_server/service_server.py`: AP Exchange và service mock.
- `core/crypto.py`: nfold, derive-random (DK/DR), CBC-CTS mode, HMAC-SHA1-96, PBKDF2-HMAC-SHA1, key derivation.
- `core/principal.py`: chuẩn hóa realm/principal.
- `core/keytab.py`: đọc/ghi keytab nhị phân chuẩn MIT Keytab v2.
- `core/replay_cache.py`: replay cache SQLite.
- `core/asn1_codec.py`: encode/decode ASN.1/DER theo subset RFC 4120.
- `core/network.py`: TCP length-prefixed framing cho DER hoặc JSON debug.
- `core/messages.py`: constants giao thức và cấu hình.

## Cài Đặt

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Chạy Hệ Thống

Mở ba terminal tại thư mục gốc.

Terminal 1:

```powershell
python -m kdc.kdc_server
```

KDC sẽ tự:

- Migration `kdc/database.db`.
- Upsert principal mặc định.
- Sinh keytab tại `app_server/<APP_SERVICE_NAME>.keytab`, mặc định là `app_server/fileserver.keytab`.

Terminal 2:

```powershell
python -m app_server.service_server
```

Terminal 3:

```powershell
python -m client.client_app
```

Nhập:

```text
username: alice
password: alice_password
```

## Principal Mặc Định

| Principal | Password | Vai trò |
| --- | --- | --- |
| `alice@DEMO.LOCAL` | `alice_password` | Client mẫu |
| `bob@DEMO.LOCAL` | `bob_password` | Client mẫu |
| `krbtgt/DEMO.LOCAL@DEMO.LOCAL` | `tgs_secret` | TGS principal |
| `fileserver/localhost@DEMO.LOCAL` | `fileserver_secret` | Application service |

Client vẫn cho nhập alias `alice`; hệ thống sẽ chuẩn hóa thành `alice@DEMO.LOCAL`.

## Khóa Được Lưu Ở Đâu?

| Khóa / secret | Vị trí lưu chính | Ghi chú |
| --- | --- | --- |
| Password demo | Hằng bootstrap trong `kdc/database.py`; user nhập lại ở client khi chạy | Không gửi password qua network. |
| Long-term client key `Kc` | SQLite `kdc/database.db`, bảng `principals`; client derive tạm thời từ password | AS dùng để kiểm pre-authentication. |
| Long-term TGS key `Ktgs` | SQLite `kdc/database.db`, principal `krbtgt/DEMO.LOCAL@DEMO.LOCAL` | AS mã hóa TGT, TGS giải mã TGT. |
| Long-term service key `Kservice` | SQLite `kdc/database.db` và keytab `app_server/<APP_SERVICE_NAME>.keytab` | TGS mã hóa service ticket, Application Server giải mã service ticket. |
| Session key `Kc_tgs` | Trong TGT, AS-REP client part và credential cache `client/krb5cc_demo` | Dùng giữa client và TGS. |
| Session key `Kc_service` | Trong service ticket, TGS-REP client part và credential cache `client/krb5cc_demo` | Dùng giữa client và Application Server. |

Replay cache không lưu khóa; nó chỉ lưu fingerprint authenticator đã dùng.

## Kênh Truyền Thông

| Kênh | Message | Ghi chú |
| --- | --- | --- |
| Client ↔ KDC/AS | `AS-REQ`, `AS-REP`, `KRB-ERROR` qua `KDC_HOST:KDC_PORT` | Client xin TGT. |
| Client ↔ KDC/TGS | `TGS-REQ`, `TGS-REP`, `KRB-ERROR` qua `KDC_HOST:KDC_PORT` | Client dùng TGT để xin service ticket. |
| Client ↔ Application Server | `AP-REQ`, `AP-REP`, `KRB-ERROR` qua `APP_SERVER_HOST:APP_SERVER_PORT` | Client dùng service ticket để truy cập service. |
| AS ↔ TGS | Nội bộ trong process KDC | Không có socket riêng giữa AS và TGS trong demo. |
| KDC ↔ Application Server | Không có TCP runtime trực tiếp | Trust dựa trên service key: KDC export keytab, Application Server đọc keytab. |

Thông tin truyền trên mạng được bảo vệ ở tầng payload Kerberos demo, không phải nhờ TCP hoặc DER. Cụ thể:

- Password không bao giờ được gửi qua network.
- `AS-REQ` gửi pre-authentication data đã mã hóa bằng `Kc`.
- TGT được mã hóa bằng `Ktgs`, nên client không đọc được nội dung TGT.
- `TGS-REQ` gửi authenticator đã mã hóa bằng `Kc_tgs`.
- Service ticket được mã hóa bằng `Kservice`, nên chỉ Application Server có keytab đúng mới giải mã được.
- `AP-REQ` gửi authenticator đã mã hóa bằng `Kc_service`.
- `AP-REP` cũng được mã hóa bằng `Kc_service` để client xác thực ngược lại server.

Giới hạn: project chưa có TLS/mTLS cho TCP channel. ASN.1/DER chỉ là định dạng tuần tự hóa, không phải cơ chế mã hóa kênh truyền; metadata như IP, port, timing và độ dài message vẫn có thể bị quan sát.

## Cấu Hình

| Biến | Default | Ý nghĩa |
| --- | --- | --- |
| `KRB_REALM` | `DEMO.LOCAL` | Realm mặc định |
| `APP_SERVICE_NAME` | `fileserver` | Service component trong service principal |
| `APP_SERVER_NAME` | `localhost` | Host component trong service principal |
| `KDC_HOST` | `127.0.0.1` | Địa chỉ KDC |
| `KDC_PORT` | `8888` | Port KDC |
| `KDC_DB_PATH` | `kdc/database.db` | SQLite database của KDC |
| `APP_SERVER_HOST` | `127.0.0.1` | Địa chỉ Application Server |
| `APP_SERVER_PORT` | `8000` | Port Application Server |
| `KRB_WIRE_FORMAT` | `der` | `der` để dùng ASN.1/DER, `json` để debug legacy |
| `APP_SERVER_KEYTAB` | `app_server/<APP_SERVICE_NAME>.keytab` | Keytab của Application Server |
| `KRB5CCNAME` | `client/krb5cc_demo` | Credential cache file |
| `KRB_REPLAY_CACHE` | `kdc/database.db` | Replay cache SQLite |

Nếu port mặc định bị chiếm:

```powershell
$env:KDC_PORT = "8889"
python -m kdc.kdc_server
```

Client terminal phải set cùng biến:

```powershell
$env:KDC_PORT = "8889"
python -m client.client_app
```

## Luồng Giao Thức

### AS Exchange

```text
AS_REQ = {
  client_principal,
  realm,
  nonce,
  preauth = E_Kc({ client_principal, realm, ctime, cusec })
}
```

AS trả:

```text
AS_REP = {
  encrypted_data = E_Kc({ Kc_tgs, nonce, flags, authtime, starttime, endtime, renew_till }),
  tgt = E_Ktgs({ client_principal, server_principal=krbtgt/REALM@REALM, Kc_tgs, flags, times })
}
```

### TGS Exchange

```text
TGS_REQ = {
  service_principal,
  tgt,
  nonce,
  authenticator = E_Kc_tgs({ client_principal, ctime, cusec })
}
```

TGS trả:

```text
TGS_REP = {
  encrypted_data = E_Kc_tgs({ Kc_service, nonce, service_principal, flags, starttime, endtime }),
  service_ticket = E_Kservice({ client_principal, server_principal, Kc_service, flags, times })
}
```

### AP Exchange

```text
AP_REQ = {
  service_ticket,
  authenticator = E_Kc_service({ client_principal, ctime, cusec })
}
```

Service trả:

```text
AP_REP = E_Kc_service({ timestamp: client_timestamp + 1, service_data })
```

## Kiểm Tra Nhanh

```powershell
python -m py_compile core\crypto.py core\principal.py core\keytab.py core\replay_cache.py core\messages.py core\asn1_codec.py core\network.py kdc\database.py kdc\as_handler.py kdc\tgs_handler.py kdc\kdc_server.py app_server\service_server.py client\credential_cache.py client\client_app.py
```

Kịch bản đúng:

```text
username: alice
password: alice_password
```

Kịch bản sai:

```text
username: alice
password: wrong_password
```

Kỳ vọng: AS trả `KDC_ERR_PREAUTH_FAILED`.

## Giới Hạn Còn Lại

Dự án đã sát chuẩn hơn ở mức mô phỏng, nhưng vẫn chưa phải Kerberos production hoàn chỉnh do:

- Không tương thích trực tiếp ở mức giao thức truyền thông mạng socket TCP với các phần mềm chuẩn MIT Kerberos hoặc Windows Active Directory do sử dụng TCP framing tự định nghĩa đơn giản, chưa tích hợp đầy đủ các lớp API GSSAPI/SSPI.
- Chưa implement đầy đủ các cờ và luồng chuyển tiếp vé (forward/delegate) phức tạp.
- Chưa tích hợp mã hóa kênh truyền TLS/mTLS cho các socket TCP.

Các giới hạn này và mô hình an toàn được phân tích chi tiết trong [docs/security.md](docs/security.md).
