# Hướng Dẫn Vận Hành

Tài liệu này mô tả cách cài đặt, cấu hình, chạy, kiểm tra và xử lý lỗi cho project KerberosAuthentication. Nội dung phản ánh phiên bản hiện tại: mô phỏng Kerberos V5 theo RFC 4120 ở mức cấu trúc và hành vi, sử dụng định dạng ASN.1/DER cho cả outer message và các payload mã hóa bên trong. Hệ thống hỗ trợ enctype chuẩn `aes256-cts-hmac-sha1-96` và `aes128-cts-hmac-sha1-96` cùng với cơ chế Key Usage và dẫn xuất khóa chuẩn RFC 3961/3962.

## Yêu Cầu Môi Trường

- Python 3.10 trở lên.
- `pip`.
- Windows PowerShell, macOS terminal hoặc Linux shell.
- Quyền ghi file trong thư mục project để tạo database, keytab và credential cache.
- Port local còn trống cho KDC và Application Server.
- Dependency Python trong `requirements.txt`.

## Cài Đặt

Windows PowerShell:

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

## Thành Phần Runtime

| Thành phần | Lệnh chạy | Vai trò |
| --- | --- | --- |
| KDC | `python -m kdc.kdc_server` | Nhận `AS_REQ` và `TGS_REQ`, quản lý principal DB, audit log và keytab export |
| KAdmin Web | `python -m kdc.kadmin_web` | Dashboard local và REST API quản trị principal/audit log trên `127.0.0.1:8088` |
| Application Server | `python -m app_server.service_server` | Nhận `AP_REQ`, đọc service key từ keytab, trả `AP_REP` |
| Client | `python -m client.client_app` | Thực hiện AS/TGS/AP Exchange và lưu credential cache |

## Chạy Hệ Thống

Cần ba terminal riêng tại thư mục gốc project. Có thể mở thêm một terminal cho KAdmin Web nếu muốn demo giao diện quản trị.

### Terminal 1: KDC

```powershell
python -m kdc.kdc_server
```

Khi start, KDC tự thực hiện:

- Tạo hoặc migration `kdc/database.db`.
- Upsert các principal mặc định.
- Tạo alias cho principal, ví dụ `alice` trỏ tới `alice@DEMO.LOCAL`.
- Ghi service keytab tại `app_server/<APP_SERVICE_NAME>.keytab`, mặc định là `app_server/fileserver.keytab`.
- Ghi audit event `database_initialized`.
- Lắng nghe TCP tại `KDC_HOST:KDC_PORT`.

Log kỳ vọng:

```text
[KDC] Database initialized at '...\kdc\database.db'
[KDC] Registered principals: ['alice@DEMO.LOCAL', 'bob@DEMO.LOCAL', ...]
Kerberos KDC Server
Listening on 127.0.0.1:4321
[KDC] Waiting for connections...
```

### Terminal Tùy Chọn: KAdmin Web

```powershell
python -m kdc.kadmin_web
```

Mở dashboard:

```text
http://127.0.0.1:8088/
```

KAdmin Web dùng cùng SQLite database với KDC qua `KDC_DB_PATH`. Nên start KDC ít nhất một lần trước để database, principal mặc định và keytab được khởi tạo.

Chức năng trên dashboard:

- Xem thống kê principal, AS/TGS request, request lỗi và success rate.
- Xem danh sách principal, realm, type, `kvno`, enctype, groups và trạng thái disabled.
- Thêm principal user/service. Khi thêm service principal, web API ghi keytab service theo cấu hình hiện tại.
- Toggle enable/disable principal. Principal disabled sẽ bị AS trả `KDC_ERR_CLIENT_REVOKED`.
- Xóa principal.
- Xem audit log và lọc theo component/outcome/search/limit.

REST API:

| Method | Endpoint | Payload / query |
| --- | --- | --- |
| `GET` | `/api/statistics` | Không cần payload |
| `GET` | `/api/principals` | Không cần payload |
| `POST` | `/api/principals` | JSON: `principal_name`, `password`, `type`, `groups` |
| `POST` | `/api/principals/toggle` | JSON: `principal_name` |
| `POST` | `/api/principals/delete` | JSON: `principal_name` |
| `GET` | `/api/audit_logs` | Query tùy chọn: `limit`, `component`, `outcome`, `search` |

Test nhanh API:

```powershell
python tests/test_kadmin_web_api.py
```

Lưu ý: KAdmin Web là demo local qua HTTP thô, chưa có login riêng, TLS/mTLS, CSRF protection hoặc kadmin RPC chuẩn. Không nên trình bày nó như một kênh quản trị production.

### Terminal 2: Application Server

```powershell
python -m app_server.service_server
```

Application Server cần keytab đã được KDC tạo. Vì vậy, trong demo nên start KDC trước Application Server ít nhất một lần.

Log kỳ vọng:

```text
Kerberos Application Server (File Server)
Principal: fileserver/localhost@DEMO.LOCAL
Keytab:    ...\app_server\fileserver.keytab
Listening on 127.0.0.1:8000
```

### Terminal 3: Client

```powershell
python -m client.client_app
```

Nhập thông tin mặc định:

```text
Enter username: alice
Enter password: alice_password
```

Kết quả kỳ vọng:

```text
AS Exchange successful
TGS Exchange successful
Mutual authentication verified
Full Kerberos authentication completed successfully
```

### Demo Truy Cập Lại Không Nhập Password

Sau một lần login thành công, client đã lưu TGT và service ticket trong credential cache. Để demo truy cập dịch vụ lại mà không đăng nhập lại:

1. Giữ KDC và Application Server đang chạy.
2. Chạy lại client:

```powershell
python -m client.client_app
```

3. Nhập cùng username, ví dụ `alice`.
4. Ở dòng password, nhấn Enter để bỏ trống.

Kỳ vọng:

```text
[Client] Found valid cached TGT for alice@DEMO.LOCAL.
[Client] Leave password empty to reuse cached credentials.
[Client] Reusing cached TGT. Skipping AS Exchange.
[Client] Found valid cached service ticket. Skipping TGS Exchange.
Phase 3: AP Exchange (Service Access via HTTP Negotiate)
[Client] ✓ Mutual authentication verified!
```

Nếu service ticket hết hạn nhưng TGT còn hạn, client sẽ bỏ qua AS Exchange nhưng vẫn chạy TGS Exchange để xin service ticket mới. Nếu TGT cũng hết hạn, client sẽ yêu cầu nhập password lại hoặc phải renew TGT.

### Thao Tác Kerberos-Style

Ngoài app demo chạy liền ba pha, project có các lệnh mô phỏng thao tác người dùng Kerberos cơ bản:

```powershell
python -m client.kinit alice
python -m client.klist
python -m client.kvno fileserver
python -m client.kaccess fileserver
python -m client.krenew
python -m client.kdestroy
```

Kịch bản demo khuyến nghị:

1. `python -m client.kinit alice`: nhập `alice_password`, client chỉ lấy TGT.
2. `python -m client.klist`: chứng minh TGT đã nằm trong credential cache.
3. `python -m client.kvno fileserver`: dùng TGT xin service ticket, in `kvno`.
4. `python -m client.klist`: thấy thêm service ticket `fileserver/localhost@DEMO.LOCAL`.
5. `python -m client.kaccess fileserver`: dùng service ticket truy cập Application Server, nhận `AP_REP`.
6. `python -m client.kdestroy`: xóa cache.
7. `python -m client.klist`: không còn credential hợp lệ.

Các lệnh này dùng cùng cache file với `client.client_app`, mặc định là `client/krb5cc_demo` hoặc đường dẫn trong `KRB5CCNAME`.

## Cấu Hình Runtime

Tất cả process tự đọc file `.env` ở thư mục gốc repo trước khi đọc `os.getenv()`. Biến đã set sẵn trong shell vẫn thắng giá trị trong `.env`, nên test hoặc subprocess vẫn có thể override cấu hình. File `.env` chứa cấu hình local và không được commit; dùng `.env.example` làm template.

| Biến môi trường | Default | Ý nghĩa |
| --- | --- | --- |
| `KRB_REALM` | `DEMO.LOCAL` | Realm mặc định. Nên set trước khi start mọi process |
| `APP_SERVICE_NAME` | `fileserver` | Service component trong service principal |
| `APP_SERVER_NAME` | `localhost` | Host component trong service principal |
| `KDC_BIND_HOST` | Giá trị `KDC_HOST` | Địa chỉ KDC bind/listen |
| `KDC_HOST` | `127.0.0.1` | Địa chỉ client dùng để kết nối KDC |
| `KDC_PORT` | `4321` | Port bind của KDC và target của client |
| `KDC_DB_PATH` | `kdc/database.db` | SQLite database của KDC |
| `APP_SERVER_BIND_HOST` | Giá trị `APP_SERVER_HOST` | Địa chỉ Application Server bind/listen |
| `APP_SERVER_HOST` | `127.0.0.1` | Địa chỉ client dùng để kết nối Application Server |
| `APP_SERVER_PORT` | `8000` | Port bind của Application Server và target của client |
| `KRB_WIRE_FORMAT` | `der` | `der` dùng ASN.1/DER, `json` chỉ dùng khi debug legacy với bytes được bọc Base64 |
| `APP_SERVER_KEYTAB` | `app_server/<APP_SERVICE_NAME>.keytab` | File keytab Application Server đọc khi start |
| `KRB5CCNAME` | `client/krb5cc_demo` | File credential cache của client |
| `KRB_REPLAY_CACHE` | Giá trị `KDC_DB_PATH` | SQLite file chứa replay cache |
| `KADMIN_WEB_HOST` | `127.0.0.1` | Địa chỉ bind của KAdmin Web |
| `KADMIN_WEB_PORT` | `8088` | Port KAdmin Web |
| `PYTHONIOENCODING` | Không set | Có thể set `utf-8` nếu terminal Windows gặp lỗi encoding |

Các biến liên quan realm, service, host và keytab phải nhất quán giữa KDC, Application Server và Client. Nếu đổi `KRB_REALM`, `APP_SERVICE_NAME` hoặc `APP_SERVER_NAME`, hãy set cùng giá trị ở cả ba terminal trước khi chạy.

Mặc định hệ thống gửi message qua TCP bằng ASN.1/DER. Nếu cần debug bằng payload JSON, sửa trong `.env`:

```dotenv
KRB_WIRE_FORMAT=json
```

Ví dụ đổi port:

```dotenv
KDC_PORT=4322
APP_SERVER_PORT=8001
```

Ví dụ chạy 3 máy trong cùng LAN:

```dotenv
# Máy KDC
KDC_BIND_HOST=0.0.0.0
KDC_HOST=<IP_MAY_KDC>
```

```dotenv
# Máy Application Server
KDC_HOST=<IP_MAY_KDC>
APP_SERVER_BIND_HOST=0.0.0.0
APP_SERVER_HOST=<IP_MAY_APP_SERVER>
APP_SERVER_NAME=<IP_MAY_APP_SERVER_HOAC_HOSTNAME>
```

```dotenv
# Máy Client
KDC_HOST=<IP_MAY_KDC>
APP_SERVER_HOST=<IP_MAY_APP_SERVER>
APP_SERVER_NAME=<GIONG_GIA_TRI_DA_DUNG_KHI_TAO_KEYTAB>
```

Khi dùng LAN, mở firewall TCP `KDC_PORT` trên máy KDC và `APP_SERVER_PORT` trên máy Application Server. Nếu đổi `APP_SERVER_NAME`, hãy tạo/export lại keytab service cùng principal mới, ví dụ `fileserver/<APP_SERVER_NAME>@DEMO.LOCAL`.

## Principal Mặc Định

| Principal | Alias | Password demo | Loại |
| --- | --- | --- | --- |
| `alice@DEMO.LOCAL` | `alice` | `alice_password` | User |
| `bob@DEMO.LOCAL` | `bob` | `bob_password` | User |
| `krbtgt/DEMO.LOCAL@DEMO.LOCAL` | `krbtgt/DEMO.LOCAL` | `tgs_secret` | TGS |
| `fileserver/localhost@DEMO.LOCAL` | `fileserver` | `fileserver_secret` | Service |

Client cho phép nhập `alice`; code sẽ chuẩn hóa thành `alice@DEMO.LOCAL`. Service mặc định trong client là `fileserver`, được chuẩn hóa thành `fileserver/localhost@DEMO.LOCAL`.

## Database Và File Runtime

| File | Tạo bởi | Nội dung |
| --- | --- | --- |
| `kdc/database.db` | KDC | Principal store, alias, audit log, replay cache |
| `app_server/<APP_SERVICE_NAME>.keytab` | KDC | Service principal, kvno, enctype và long-term key của service; có thể chứa nhiều kvno |
| `client/krb5cc_demo` | Client | TGT, service ticket, session key và metadata còn hiệu lực theo định dạng MIT ccache v4 subset |

Các file keytab và credential cache là artifact runtime của demo. Không nên commit chúng vào repository.

### Bảng SQLite Chính

| Bảng | Mục đích |
| --- | --- |
| `principals` | Lưu principal, realm, salt, key, kvno, enctype, KDF metadata và trạng thái |
| `principal_aliases` | Map alias ngắn sang canonical principal |
| `principal_keys` | Lưu key history theo `principal`/`kvno`/`enctype` để hỗ trợ key rotation |
| `audit_log` | Ghi sự kiện AS/TGS/KDC |
| `replay_cache` | Lưu fingerprint authenticator đã dùng để chặn replay |

KDC chỉ tạo default principals khi chúng chưa tồn tại. Nếu đã đổi password/key bằng `kadmin cpw`, restart KDC sẽ không reset principal đó về password bootstrap trong code. Khi đổi key, current key nằm trong `principals`, còn các version cũ nằm trong `principal_keys` để TGT/service ticket cũ vẫn có thể được giải mã trong thời gian còn hạn.

## Kiểm Tra Nhanh

Kiểm tra cú pháp:

```powershell
python -m compileall core kdc app_server client tests scratch\test_cross_realm.py scratch\demo_security_flows.py scratch\demo_tgt_renewal.py
```

Chạy regression tests in-process:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Chạy smoke test tích hợp HTTP/cross-realm bằng temp runtime:

```powershell
python scratch/test_cross_realm.py
```

Chạy demo TGT renewal có log message:

```powershell
python scratch/demo_tgt_renewal.py
```

Kiểm tra port trên Windows:

```powershell
Get-NetTCPConnection -LocalPort 4321,8000 -ErrorAction SilentlyContinue
```

Kiểm tra database có bảng:

```powershell
python -c "import sqlite3; c=sqlite3.connect('kdc/database.db'); print([r[0] for r in c.execute(\"select name from sqlite_master where type='table'\")])"
```

## Kịch Bản Test Thủ Công

### 1. Happy Path

Input:

```text
username: alice
password: alice_password
```

Kỳ vọng:

- AS trả `AS_REP`.
- Client decrypt được AS_REP bằng key dẫn xuất từ password.
- TGT được lưu trong credential cache.
- TGS trả `TGS_REP`.
- Service ticket được lưu trong credential cache.
- Application Server trả `AP_REP`.
- Client verify mutual authentication bằng `ctime/cusec` trong AP_REP trùng Authenticator đã gửi.

### 2. Sai Password

Input:

```text
username: alice
password: wrong_password
```

Kỳ vọng:

- AS không decrypt được pre-authentication data.
- KDC trả `KDC_ERR_PREAUTH_FAILED`.
- Client dừng ở pha AS.

### 3. Principal Không Tồn Tại

Input:

```text
username: mallory
password: any
```

Kỳ vọng:

- AS trả `KDC_ERR_C_PRINCIPAL_UNKNOWN`.

### 4. Realm Không Khớp

Set `KRB_REALM` khác nhau giữa client và KDC.

Kỳ vọng:

- AS hoặc TGS trả `KDC_ERR_WRONG_REALM`.

### 5. KDC Không Chạy

Chạy client khi KDC chưa start.

Kỳ vọng:

- Client báo không kết nối được tới KDC.

### 6. Application Server Không Chạy

Chạy KDC, không chạy Application Server, sau đó chạy client.

Kỳ vọng:

- AS và TGS thành công.
- AP Exchange fail vì client không kết nối được tới Application Server.

### 7. Replay Authenticator

Gửi lại cùng TGS authenticator hoặc AP authenticator trong khoảng `MAX_CLOCK_SKEW`.

Kỳ vọng:

- TGS hoặc Application Server trả `KRB_AP_ERR_REPEAT`.
- Replay cache ghi nhận fingerprint đã tồn tại.

### 8. Ticket Hết Hạn

Giảm `TICKET_LIFETIME` trong `core/messages.py` hoặc chờ quá `endtime`, sau đó dùng lại ticket cũ.

Kỳ vọng:

- TGS hoặc Application Server trả `KRB_AP_ERR_TKT_EXPIRED`.
- Client tự bỏ cache entry đã hết hạn ở lần đọc tiếp theo.

### 9. Ticket Chưa Có Hiệu Lực

Tạo hoặc chỉnh test để service ticket/TGT có `starttime` nằm xa hơn `MAX_CLOCK_SKEW` so với thời gian hiện tại.

Kỳ vọng:

- TGS hoặc Application Server trả `KRB_AP_ERR_TKT_NYV`.
- Ticket không được dùng trước thời gian hiệu lực.

## Troubleshooting

### Application Server báo không đọc được keytab

Nguyên nhân thường gặp:

- Chưa chạy KDC lần nào nên keytab chưa được tạo.
- `APP_SERVER_KEYTAB` trỏ tới sai file.
- `KRB_REALM`, `APP_SERVICE_NAME` hoặc `APP_SERVER_NAME` khác giữa lúc tạo keytab và lúc chạy Application Server.

Cách xử lý:

1. Start KDC để tạo lại keytab.
2. Kiểm tra `APP_SERVER_KEYTAB`.
3. Đảm bảo `KRB_REALM`, `APP_SERVICE_NAME` và `APP_SERVER_NAME` giống nhau ở KDC, Application Server và Client.

### `KDC_ERR_PREAUTH_FAILED`

Nguyên nhân thường gặp:

- Sai password.
- Client derive key với realm khác KDC.
- Database cũ không khớp cấu hình hiện tại.

Cách xử lý:

1. Thử `alice/alice_password`.
2. Kiểm tra `KRB_REALM` ở terminal client và KDC.
3. Start lại KDC để upsert lại principal mặc định.

### `KRB_AP_ERR_SKEW`

Nguyên nhân:

- Đồng hồ giữa process lệch quá `MAX_CLOCK_SKEW`.
- Test thủ công dùng timestamp cũ.

Cách xử lý:

1. Đồng bộ thời gian hệ điều hành.
2. Kiểm tra giá trị `MAX_CLOCK_SKEW` trong `core/messages.py`.

### `KRB_AP_ERR_REPEAT`

Nguyên nhân:

- Cùng authenticator bị gửi lại.
- Credential cache không phải nguyên nhân trực tiếp; replay dựa trên `client_principal`, `server_principal`, `ctime` và `cusec`.

Đây là hành vi đúng. Nếu đang test lại từ đầu và muốn xóa trạng thái demo, dừng server rồi xóa cache runtime tương ứng.

### `KRB_AP_ERR_TKT_NYV`

Nguyên nhân:

- Ticket có `starttime` nằm trong tương lai quá cửa sổ `MAX_CLOCK_SKEW`.
- Đồng hồ hệ điều hành bị lùi nhiều so với lúc KDC cấp ticket.

Cách xử lý:

1. Đồng bộ thời gian hệ điều hành.
2. Lấy ticket mới bằng cách chạy lại AS/TGS Exchange.
3. Nếu đang test thủ công, chỉnh `starttime` về gần thời gian hiện tại.

### `KRB_AP_ERR_MODIFIED`

Nguyên nhân thường gặp:

- Ticket bị sửa hoặc decrypt bằng sai key.
- Service ticket không dành cho service đang chạy.
- Keytab không có entry khớp `principal`, `kvno` hoặc `enctype` trong outer ticket.
- Authenticator không khớp client principal trong ticket.

Cách xử lý:

1. Start KDC để export lại keytab.
2. Gửi lại AP request; Application Server đọc keytab khi xử lý request. Chỉ cần restart Application Server nếu đổi `APP_SERVER_KEYTAB` hoặc biến cấu hình service.
3. Xóa credential cache cũ nếu đã đổi realm, service host hoặc key.

Keytab hiện lưu entry theo `principal`/`kvno`/`enctype`; Application Server ưu tiên exact `kvno` từ `Ticket.enc-part`. Nếu vừa đổi password service bằng `kadmin cpw`, hãy export keytab mới bằng `kadmin.py ktadd --all-versions` và lấy service ticket mới. KDC DB lưu key history trong bảng `principal_keys` để TGT cũ còn hạn vẫn có thể được giải mã theo `kvno`.

### Client dùng ticket cũ ngoài ý muốn

Client lưu credential cache ở `client/krb5cc_demo` hoặc path trong `KRB5CCNAME`. Nếu muốn chạy lại từ AS Exchange với ticket mới, xóa cache file này sau khi dừng client.

### UnicodeEncodeError trên Windows

Các entrypoint chính đã reconfigure stdout/stderr sang UTF-8. Nếu terminal vẫn lỗi encoding:

```powershell
$env:PYTHONIOENCODING = "utf-8"
python -m client.client_app
```

## Runbook Demo

1. Chạy `python -m unittest discover -s tests -p "test_*.py" -v` để chứng minh các case bảo mật tự động: pre-auth, account lockout, TGS/AP replay, wrong-service, ticket integrity/lifetime, unknown service, TGT renewal, client-level renewal, kvno/key rotation, KAdmin CLI/Web API, keytab, ccache, ASN.1 và E2E subprocess.
2. Chạy `python scratch/demo_security_flows.py` để trình bày rõ message nào được gửi, attacker sửa/gửi lại gì và hệ thống trả `BLOCKED/ALLOWED` ra sao.
3. Chạy `python scratch/demo_tgt_renewal.py` để trình bày riêng luồng renew TGT.
4. Chạy `python scratch/test_cross_realm.py` để chứng minh luồng tích hợp có KDC socket, Application Server HTTP và cross-realm.
5. Mở terminal KDC và chạy `python -m kdc.kdc_server`.
6. Mở terminal Application Server và chạy `python -m app_server.service_server`.
7. Mở terminal Client và chạy `python -m client.client_app`.
8. Đăng nhập bằng `alice/alice_password`.
9. Ghi lại ba pha thành công: AS, TGS, AP.
10. Chạy lại client với `alice/wrong_password` và ghi lại lỗi `KDC_ERR_PREAUTH_FAILED`; nếu nhập sai lặp lại tới ngưỡng, AS trả `KDC_ERR_CLIENT_REVOKED` trong thời gian lockout.

## Dừng Process

Trong terminal server, nhấn `Ctrl+C`.

Nếu process chạy nền trên Windows:

```powershell
Get-Process python
Stop-Process -Id <PID>
```

Kiểm tra kỹ PID trước khi dừng để tránh ảnh hưởng process Python khác.
