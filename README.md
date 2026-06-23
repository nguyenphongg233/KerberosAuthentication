# KerberosAuthentication

KerberosAuthentication là dự án Python mô phỏng giao thức xác thực Kerberos V5 dựa trên các khái niệm trong [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120). Dự án tự xây dựng các thành phần cốt lõi gồm Client, Key Distribution Center, Authentication Server, Ticket Granting Server và Application Server để minh họa rõ quy trình cấp vé và phân phối khóa phiên. Cả message ngoài (outer wire messages) và các payload mã hóa bên trong (inner encrypted structures như `EncTicketPart`, `EncKDCRepPart`, `Authenticator`, `EncAPRepPart`, `PaEncTimestamp`) đều được định nghĩa và tuần tự hóa bằng ASN.1/DER (sử dụng thư viện `pyasn1`). Việc mã hóa sử dụng các enctype chuẩn `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96` với chế độ AES-CTS (Cipher Text Stealing) tự triển khai kết hợp checksum HMAC-SHA1-96, Key Usage và dẫn xuất khóa (`Ke`, `Ki`) theo RFC 3961/3962.

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
- [KAdmin Web Console](#kadmin-web-console)
- [Test Và Demo](#test-và-demo)
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
| [docs/test-demo-strategy.md](docs/test-demo-strategy.md) | Chiến lược test/demo, regression cases, demo matrix và thứ tự trình bày |

## Mức Độ Tuân Theo RFC 4120 / RFC 3961 / RFC 3962

Đã mô phỏng:

- Realm mặc định `DEMO.LOCAL`.
- Principal dạng Kerberos:
  - User: `alice@DEMO.LOCAL`.
  - TGS: `krbtgt/DEMO.LOCAL@DEMO.LOCAL`.
  - Service: `fileserver/localhost@DEMO.LOCAL`.
- AS Exchange với pre-authentication, nonce và AS_REP encrypted part.
- TGS Exchange với TGT, authenticator, nonce và service ticket.
- AP Exchange với service ticket, authenticator và AP_REP chứa lại `ctime/cusec` của Authenticator theo cấu trúc `EncAPRepPart`.
- Tuần tự hóa toàn bộ: Cả outer message và các payload mã hóa bên trong (`EncTicketPart`, `EncKDCRepPart`, `Authenticator`, `EncAPRepPart`, `PaEncTimestamp`) đều được định nghĩa và mã hóa dưới dạng cấu trúc ASN.1/DER.
- Dẫn xuất khóa và mã hóa chuẩn Kerberos: Enctype `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96`, mã hóa AES-CTS (Cipher Text Stealing), mã xác thực HMAC-SHA1-96, và Key Usage dẫn xuất khóa (`Ke`, `Ki`) theo RFC 3961/3962.
- Ticket ASN.1 outer có `realm`, `sname`, `kvno`, `enctype`; `kvno` được lấy từ principal record trong KDC DB thay vì hard-code. Phần `EncTicketPart` có `client_principal`, session key, `authtime`, `starttime`, `endtime`, `renew_till`, `flags` và `authorization-data`.
- Hỗ trợ cờ gia hạn vé (`renewable` flag) và quy trình **Gia hạn vé TGT (TGT Renewal)** bằng cách gửi `TGS-REQ` có cờ `renew` trong `kdc-options` với TGT đã hết hạn lên KDC.
- Nhúng **Dữ liệu ủy quyền nhóm/vai trò (Authorization Data / RBAC)** trong `EncTicketPart` để phân quyền dựa trên vai trò tại Application Server (File Server phân cấp quyền hiển thị cho `alice` [Admin] và `bob` [User]). Đây là authorization-data demo, không phải PAC Active Directory đầy đủ.
- **Subkey & Sequence Number Handshake** trong AP Exchange: Client sinh khóa con `client_subkey` và số thứ tự khởi đầu `seq-number` gửi trong Authenticator, Server trả về khóa con và số thứ tự của mình trong `EncAPRepPart` để hoàn tất bắt tay.
- Principal database có salt (`REALMusername`), PBKDF2 parameters, key version number (kvno), principal aliases và key history theo `principal`/`kvno`/`enctype`.
- Công cụ quản trị KDC database: Tiện ích CLI `kadmin.py` hỗ trợ các lệnh `add`, `delete`, `cpw`, `list`, `ktadd`; `cpw` tăng `kvno`, còn `ktadd --all-versions` có thể export toàn bộ key versions ra keytab.
- Định dạng nhị phân **MIT Keytab v2** lưu trữ thông tin các service principal và khóa của chúng.
- Định dạng nhị phân **MIT ccache v4 subset** lưu trữ credential cache cho client, kèm metadata extension riêng để giữ `ticket_kvno`/`ticket_enctype` sau khi reload cache.
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
- Dùng keytab nhị phân **MIT Keytab v2** để Application Server lấy service key động và chọn đúng entry theo `principal`/`kvno`/`enctype`.
- Dùng credential cache nhị phân **MIT ccache v4 subset** để lưu trữ vé, session key và metadata ticket giữa các phiên chạy của client.
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
| KDF | PBKDF2-HMAC-SHA1, 4096 iterations mặc định theo RFC 3962 |
| Keytab | Định dạng nhị phân MIT Keytab v2 |
| Credential cache | Định dạng nhị phân MIT ccache v4 subset |
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
- `client/credential_cache.py`: credential cache nhị phân MIT ccache v4 subset.
- `kdc/kdc_server.py`: TCP server của KDC.
- `kdc/database.py`: schema/migration, principal store, aliases, audit log, keytab export.
- `kdc/kadmin_web.py`: web dashboard và REST API quản trị principal/audit log trên `127.0.0.1:8088`.
- `kdc/as_handler.py`: AS Exchange.
- `kdc/tgs_handler.py`: TGS Exchange.
- `app_server/service_server.py`: AP Exchange và service mock trả protected file catalog theo group trong service ticket.
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
- Tạo principal mặc định nếu chưa tồn tại, không ghi đè password/kvno đã đổi bằng `kadmin`.
- Sinh keytab tại `app_server/<APP_SERVICE_NAME>.keytab`, mặc định là `app_server/fileserver.keytab`.

Terminal tùy chọn cho dashboard quản trị:

```powershell
python -m kdc.kadmin_web
```

Mở `http://127.0.0.1:8088/` để xem thống kê, danh sách principal và audit log. Web console dùng cùng `KDC_DB_PATH` với KDC, nên nên start KDC ít nhất một lần để database/keytab được khởi tạo.

Terminal 2:

```powershell
python -m app_server.service_server
```

Terminal 3:

```powershell
python -m client.client_app
```

Nếu đã login thành công trước đó và cache còn hạn, lần chạy tiếp theo nhập cùng username rồi để trống password để bỏ qua AS Exchange. Nếu service ticket cũng còn hạn, client sẽ bỏ qua cả TGS Exchange và đi thẳng tới AP Exchange để truy cập dịch vụ.

Các thao tác kiểu Kerberos CLI cũng được hỗ trợ:

```powershell
python -m client.kinit alice
python -m client.klist
python -m client.kvno fileserver
python -m client.kaccess fileserver
python -m client.krenew
python -m client.kdestroy
```

Ý nghĩa:

- `kinit`: nhập password để lấy TGT và lưu vào credential cache.
- `klist`: xem TGT/service ticket đang có trong cache.
- `kvno`: dùng TGT để xin service ticket và in key version number của service ticket.
- `kaccess`: truy cập Application Server bằng service ticket trong cache; nếu thiếu service ticket thì tự xin qua TGS trước.
- `krenew`: renew TGT trong cache nếu còn trong `renew_till`.
- `kdestroy`: xóa credential cache.

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
| Client ↔ Application Server | HTTP `WWW-Authenticate`/`Authorization: Negotiate` chứa raw `AP-REQ`/`AP-REP` DER | Client dùng service ticket để truy cập service; khi AP-REQ hợp lệ, FileServer trả protected file catalog theo group trong ticket. Chưa bọc token SPNEGO/GSS-API đầy đủ. |
| AS ↔ TGS | Nội bộ trong process KDC | Không có socket riêng giữa AS và TGS trong demo. |
| KDC ↔ Application Server | Không có TCP runtime trực tiếp | Trust dựa trên service key: KDC export keytab, Application Server đọc keytab. |

Thông tin truyền trên mạng được bảo vệ ở tầng payload Kerberos demo, không phải nhờ TCP hoặc DER. Cụ thể:

- Password không bao giờ được gửi qua network.
- `AS-REQ` gửi pre-authentication data đã mã hóa bằng `Kc`.
- TGT được mã hóa bằng `Ktgs`, nên client không đọc được nội dung TGT.
- `TGS-REQ` gửi authenticator đã mã hóa bằng `Kc_tgs`.
- Service ticket được mã hóa bằng `Kservice`, nên chỉ Application Server có keytab đúng mới giải mã được.
- `AP-REQ` gửi authenticator đã mã hóa bằng `Kc_service`.
- `AP-REP` được mã hóa bằng `client_subkey` nếu Authenticator có subkey; nếu không thì dùng `Kc_service`. Client dùng AP-REP để xác thực ngược lại server.

Giới hạn: project chưa có TLS/mTLS cho TCP channel. ASN.1/DER chỉ là định dạng tuần tự hóa, không phải cơ chế mã hóa kênh truyền; metadata như IP, port, timing và độ dài message vẫn có thể bị quan sát.

## Cấu Hình

Repo tự đọc file `.env` ở thư mục gốc khi import các module `core.*`. Shell environment vẫn có ưu tiên cao hơn `.env`, nên test/subprocess có thể override từng biến khi cần. File `.env` là cấu hình local và đã được ignore; `.env.example` là template có thể commit/chia sẻ.

| Biến | Default | Ý nghĩa |
| --- | --- | --- |
| `KRB_REALM` | `DEMO.LOCAL` | Realm mặc định |
| `APP_SERVICE_NAME` | `fileserver` | Service component trong service principal |
| `APP_SERVER_NAME` | `localhost` | Host component trong service principal |
| `KDC_BIND_HOST` | Giá trị `KDC_HOST` | Địa chỉ KDC bind/listen |
| `KDC_HOST` | `127.0.0.1` | Địa chỉ client dùng để kết nối KDC |
| `KDC_PORT` | `4321` | Port KDC |
| `KDC_DB_PATH` | `kdc/database.db` | SQLite database của KDC |
| `APP_SERVER_BIND_HOST` | Giá trị `APP_SERVER_HOST` | Địa chỉ Application Server bind/listen |
| `APP_SERVER_HOST` | `127.0.0.1` | Địa chỉ client dùng để kết nối Application Server |
| `APP_SERVER_PORT` | `8000` | Port Application Server |
| `KRB_WIRE_FORMAT` | `der` | `der` để dùng ASN.1/DER, `json` để debug legacy |
| `APP_SERVER_KEYTAB` | `app_server/<APP_SERVICE_NAME>.keytab` | Keytab của Application Server |
| `KRB5CCNAME` | `client/krb5cc_demo` | Credential cache file |
| `KRB_REPLAY_CACHE` | `kdc/database.db` | Replay cache SQLite |
| `KADMIN_WEB_HOST` | `127.0.0.1` | Địa chỉ bind của KAdmin Web |
| `KADMIN_WEB_PORT` | `8088` | Port KAdmin Web |

Chạy local một máy: giữ nguyên `.env` mặc định rồi mở ba terminal:

```powershell
python -m kdc.kdc_server
python -m app_server.service_server
python -m client.client_app
```

Nếu port mặc định bị chiếm, sửa trực tiếp trong `.env`:

```dotenv
KDC_PORT=4322
APP_SERVER_PORT=8001
```

Chạy trên 3 máy cùng LAN:

```dotenv
# Trên máy KDC
KDC_BIND_HOST=0.0.0.0
KDC_HOST=<IP_MAY_KDC>
```

```dotenv
# Trên máy Application Server
KDC_HOST=<IP_MAY_KDC>
APP_SERVER_BIND_HOST=0.0.0.0
APP_SERVER_HOST=<IP_MAY_APP_SERVER>
APP_SERVER_NAME=<IP_MAY_APP_SERVER_HOAC_HOSTNAME>
```

```dotenv
# Trên máy Client
KDC_HOST=<IP_MAY_KDC>
APP_SERVER_HOST=<IP_MAY_APP_SERVER>
APP_SERVER_NAME=<GIONG_GIA_TRI_DA_DUNG_KHI_TAO_KEYTAB>
```

Lưu ý: `APP_SERVER_NAME` là một phần của service principal, ví dụ `fileserver/192.168.1.20@DEMO.LOCAL`. Nếu đổi giá trị này thì phải khởi tạo/export lại keytab tương ứng và dùng cùng giá trị ở KDC, Application Server và Client.

## Luồng Giao Thức

### AS Exchange

```text
AS_REQ = {
  client_principal,
  realm,
  nonce,
  preauth = E_Kc({ ctime, cusec })
}
```

AS trả:

```text
AS_REP = {
  encrypted_data = E_Kc({ Kc_tgs, nonce, flags, authtime, starttime, endtime, renew_till }),
  tgt = Ticket(sname=krbtgt/REALM@REALM, enc-part=E_Ktgs({ client_principal, Kc_tgs, flags, times, authorization_data }))
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
  service_ticket = Ticket(sname=service_principal, enc-part=E_Kservice({ client_principal, Kc_service, flags, times, authorization_data }))
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
AP_REP = E_Kc_service_or_subkey({ ctime, cusec, subkey, seq_number })
```

## KAdmin Web Console

`kdc/kadmin_web.py` là dashboard quản trị local cho demo, không phải giao thức `kadmin` chuẩn của Kerberos production.

Chạy:

```powershell
python -m kdc.kadmin_web
```

URL mặc định:

```text
http://127.0.0.1:8088/
```

Chức năng chính:

- Xem thống kê tổng số principal, AS/TGS request, số request lỗi và success rate.
- Xem danh sách principal gồm `principal_name`, type, realm, `kvno`, enctype, trạng thái disabled và groups.
- Thêm principal user/service; nếu thêm service principal thì ghi keytab theo `DEFAULT_KEYTAB_PATH`.
- Toggle enable/disable principal. Principal disabled sẽ bị AS từ chối bằng `KDC_ERR_CLIENT_REVOKED`.
- Xóa principal và alias tương ứng.
- Xem audit log, có lọc theo `component`, `outcome`, `search` và `limit`.

REST API hiện có:

| Method | Path | Mục đích |
| --- | --- | --- |
| `GET` | `/api/statistics` | Lấy thống kê dashboard |
| `GET` | `/api/principals` | Liệt kê principal |
| `POST` | `/api/principals` | Thêm principal từ JSON `principal_name`, `password`, `type`, `groups` |
| `POST` | `/api/principals/toggle` | Bật/tắt principal từ JSON `principal_name` |
| `POST` | `/api/principals/delete` | Xóa principal từ JSON `principal_name` |
| `GET` | `/api/audit_logs?limit=50` | Xem audit log |

Test tự động liên quan:

```powershell
python tests/test_kadmin_web_api.py
```

Lưu ý bảo mật: KAdmin Web chạy HTTP thô trên localhost, chưa có login riêng, TLS/mTLS, CSRF protection hoặc phân quyền admin như Kerberos production. Chỉ dùng để demo quản trị local và xem audit log.

## Test Và Demo

Repo hiện có ba lớp kiểm thử chính:

| Lớp | File / lệnh | Mục tiêu |
| --- | --- | --- |
| Regression in-process | `python -m unittest discover -s tests -p "test_*.py" -v` | Kiểm các hành vi bảo mật cốt lõi mà không cần mở port. |
| Verbose security-flow demo | `python scratch/demo_security_flows.py` | In rõ message gửi đi, attacker tác động gì, KDC/TGS/App Server chặn hoặc cho qua ra sao. |
| Smoke HTTP/cross-realm | `python scratch/test_cross_realm.py` | Chạy KDC + Application Server + Client bằng temp runtime để kiểm luồng tích hợp. |

Regression tests hiện có 33 case, được tách theo từng cơ chế để có thể chạy riêng từng file:

| File | Cơ chế kiểm |
| --- | --- |
| `tests/test_as_preauth.py` | Sai password, principal không tồn tại, thiếu pre-auth, timestamp quá cũ, AS-REP hợp lệ và lockout tạm thời sau nhiều lần pre-auth fail. |
| `tests/test_replay_protection.py` | Gửi lại cùng TGS authenticator bị `KRB_AP_ERR_REPEAT`. |
| `tests/test_ticket_integrity.py` | TGT bị sửa ciphertext bị `KRB_AP_ERR_MODIFIED`. |
| `tests/test_ticket_lifetime.py` | TGT hết hạn hoặc chưa tới `starttime` bị từ chối. |
| `tests/test_service_lookup.py` | Service principal không tồn tại bị `KDC_ERR_S_PRINCIPAL_UNKNOWN`. |
| `tests/test_key_rotation.py` | TGT cũ vẫn dùng được sau khi rotate TGS key nhờ `kvno` và `principal_keys`; `init_database()` không reset kvno. |
| `tests/test_keytab_kvno.py` | Keytab chọn đúng service key theo `principal`/`kvno`/`enctype`, có fallback kvno cao nhất. |
| `tests/test_ccache_metadata.py` | Ccache reload vẫn giữ metadata `ticket_kvno`/`ticket_enctype` và bỏ service ticket hết hạn. |
| `tests/test_asn1_message_format.py` | Kiểm application tag ASN.1/DER và round-trip `AS_REQ`. |
| `tests/test_application_server_ap.py` | AP-REQ hợp lệ trả protected file catalog, phân quyền user/admin, replay AP authenticator, service sai, service ticket bị sửa và wrong-service khi keytab chứa nhiều service key. |
| `tests/test_tgt_renewal.py` | TGT hết hạn nhưng còn `renew_till` được renew; quá `renew_till` thì bị từ chối. |
| `tests/test_client_tgt_renewal.py` | Client gọi `client_app.renew_tgt_exchange()`, cập nhật ccache rồi dùng TGT mới để xin service ticket. |
| `tests/test_kadmin_cli.py` | `kadmin cpw` tăng kvno, giữ key history/audit; `ktadd --all-versions` export đủ key versions. |
| `tests/test_kadmin_web_api.py` | KAdmin Web REST API add/list/toggle/delete principal, đọc audit log và tính dashboard statistics. |
| `tests/test_env_config.py` | `.env` loader đọc cấu hình local, giữ nguyên biến đã set trong shell và hỗ trợ quote/comment cơ bản. |
| `tests/test_e2e_subprocess.py` | Mở KDC/App Server trên port tạm, chạy client CLI happy path và negative E2E sai password. |

Smoke test `scratch/test_cross_realm.py` chạy bằng runtime tạm, không xóa `kdc/database.db`, keytab hoặc credential cache thật trong repo. Kịch bản này kiểm:

- `charlie@PARTNER.LOCAL` truy cập `fileserver/localhost@PARTNER.LOCAL`.
- `alice@DEMO.LOCAL` lấy cross-realm TGT rồi lấy service ticket cho `fileserver/localhost@PARTNER.LOCAL`.
- Client hoàn tất AP Exchange qua HTTP `Negotiate` chứa raw AP-REQ/AP-REP DER.

Verbose security-flow demo `scratch/demo_security_flows.py` in theo dạng `Client -> AS`, `Attacker -> TGS/App Server`, `KRB_ERROR`, HTTP status và `BLOCKED/ALLOWED`. Kịch bản này trình bày:

- Normal AS -> TGS flow: `AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`.
- Wrong password/forged pre-auth: AS trả `KDC_ERR_PREAUTH_FAILED`.
- Account lockout: nhiều lần pre-auth sai khiến AS trả `KDC_ERR_CLIENT_REVOKED`.
- Tampered TGT: TGS trả `KRB_AP_ERR_MODIFIED`.
- Replayed TGS authenticator: TGS trả `KRB_AP_ERR_REPEAT`.
- Replayed AP authenticator: Application Server trả HTTP `403` và `KRB_AP_ERR_REPEAT`.
- Tampered service ticket: Application Server trả HTTP `403` và `KRB_AP_ERR_MODIFIED`.
- Wrong-service AP-REQ khi keytab có nhiều service key: Application Server vẫn chặn bằng `KRB_AP_ERR_MODIFIED`.
- Key rotation: TGT cũ còn hạn vẫn được chấp nhận nhờ `kvno` và `principal_keys`.

Verbose TGT renewal demo `scratch/demo_tgt_renewal.py` trình bày riêng luồng renew:

- Client có TGT đã hết `endtime` nhưng còn trong `renew_till`.
- Client gửi `TGS_REQ` với `kdc_options=['renew']`.
- TGS trả TGT mới với session key/endtime mới.
- Client dùng TGT mới để xin service ticket bình thường.

Các cơ chế bổ sung mới hiện đã có:

- Negative E2E sai password: client dừng ở AS Exchange, không đi tiếp TGS/AP.
- Client-level TGT renewal: `client_app.renew_tgt_exchange()` renew TGT trong cache rồi dùng được tiếp.
- KAdmin Web API: add/list/toggle/delete principal, audit log và thống kê dashboard `/api/statistics`.
- Rate limiting/account lockout: nhiều lần pre-auth fail sẽ khóa tạm principal bằng `KDC_ERR_CLIENT_REVOKED`.

## Kiểm Tra Nhanh

```powershell
python -m compileall core kdc app_server client tests scratch\test_cross_realm.py scratch\demo_security_flows.py scratch\demo_tgt_renewal.py
```

Regression tests:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Verbose security-flow demo:

```powershell
python scratch/demo_security_flows.py
```

Verbose TGT renewal demo:

```powershell
python scratch/demo_tgt_renewal.py
```

Smoke test an toàn, dùng temp runtime riêng:

```powershell
python scratch/test_cross_realm.py
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

## Giới Hạn Còn Lại (Những điểm chưa làm được)

Dự án hiện tại là một **bản mô phỏng học thuật**, do đó nó **chưa làm được** các yếu tố cần thiết để có thể kết nối hay tương thích trực tiếp với các client/server Kerberos thật:

- **Chưa tương thích giao thức mạng:** Không thể kết nối với `kinit` hay hệ điều hành thật do sử dụng TCP framing tự chế (length-prefixed) thay vì UDP/TCP tiêu chuẩn của RFC 4120.
- **Chưa có cấu trúc PAC (Privilege Attribute Certificate) hoàn chỉnh:** Chỉ mô phỏng RBAC đơn giản, thiếu chữ ký số kép KDC/Server bảo vệ như Active Directory.
- **Chưa phân giải KDC tự động:** Không sử dụng DNS (SRV records) mà phải cấu hình địa chỉ IP tĩnh.
- **Chưa bảo mật OS Session cho Ccache/Keytab:** Việc lưu trữ file nhị phân trên ổ đĩa không được bọc bởi API hệ thống bảo vệ cấp thấp (như Windows LSA).
- **Chưa hỗ trợ giao thức quản trị an toàn:** KAdmin dùng HTTP thô, không có mã hóa TLS hay kadmin RPC chuẩn.
- **Chưa implement** đầy đủ các cờ vé nâng cao (Forwardable, PKINIT, FAST) và mã hóa kênh truyền TLS/mTLS cho socket TCP.

Các hạn chế này được phân tích chi tiết trong [docs/security.md](docs/security.md).
