# Hướng Dẫn Vận Hành

Tài liệu này mô tả cách cài đặt, cấu hình, chạy, kiểm tra và xử lý lỗi cho project KerberosAuthentication. Nội dung phản ánh phiên bản hiện tại: mô phỏng Kerberos V5 theo RFC 4120 ở mức cấu trúc và hành vi, dùng ASN.1/DER cho outer wire message và Fernet/JSON cho phần encrypted payload demo bên trong.

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
| Application Server | `python -m app_server.service_server` | Nhận `AP_REQ`, đọc service key từ keytab, trả `AP_REP` |
| Client | `python -m client.client_app` | Thực hiện AS/TGS/AP Exchange và lưu credential cache |

## Chạy Hệ Thống

Cần ba terminal riêng tại thư mục gốc project.

### Terminal 1: KDC

```powershell
python -m kdc.kdc_server
```

Khi start, KDC tự thực hiện:

- Tạo hoặc migration `kdc/database.db`.
- Upsert các principal mặc định.
- Tạo alias cho principal, ví dụ `alice` trỏ tới `alice@DEMO.LOCAL`.
- Ghi service keytab tại `app_server/<APP_SERVICE_NAME>.keytab.json`, mặc định là `app_server/fileserver.keytab.json`.
- Ghi audit event `database_initialized`.
- Lắng nghe TCP tại `KDC_HOST:KDC_PORT`.

Log kỳ vọng:

```text
[KDC] Database initialized at '...\kdc\database.db'
[KDC] Registered principals: ['alice@DEMO.LOCAL', 'bob@DEMO.LOCAL', ...]
Kerberos KDC Server
Listening on 127.0.0.1:8888
[KDC] Waiting for connections...
```

### Terminal 2: Application Server

```powershell
python -m app_server.service_server
```

Application Server cần keytab đã được KDC tạo. Vì vậy, trong demo nên start KDC trước Application Server ít nhất một lần.

Log kỳ vọng:

```text
Kerberos Application Server (File Server)
Principal: fileserver/localhost@DEMO.LOCAL
Keytab:    ...\app_server\fileserver.keytab.json
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

## Cấu Hình Runtime

| Biến môi trường | Default | Ý nghĩa |
| --- | --- | --- |
| `KRB_REALM` | `DEMO.LOCAL` | Realm mặc định. Nên set trước khi start mọi process |
| `APP_SERVICE_NAME` | `fileserver` | Service component trong service principal |
| `APP_SERVER_NAME` | `localhost` | Host component trong service principal |
| `KDC_HOST` | `127.0.0.1` | Địa chỉ bind của KDC và target của client |
| `KDC_PORT` | `8888` | Port bind của KDC và target của client |
| `KDC_DB_PATH` | `kdc/database.db` | SQLite database của KDC |
| `APP_SERVER_HOST` | `127.0.0.1` | Địa chỉ bind của Application Server và target của client |
| `APP_SERVER_PORT` | `8000` | Port bind của Application Server và target của client |
| `KRB_WIRE_FORMAT` | `der` | `der` dùng ASN.1/DER, `json` chỉ dùng khi debug legacy |
| `APP_SERVER_KEYTAB` | `app_server/<APP_SERVICE_NAME>.keytab.json` | File keytab Application Server đọc khi start |
| `KRB5CCNAME` | `client/krb5cc_demo.json` | File credential cache của client |
| `KRB_REPLAY_CACHE` | Giá trị `KDC_DB_PATH` | SQLite file chứa replay cache |
| `PYTHONIOENCODING` | Không set | Có thể set `utf-8` nếu terminal Windows gặp lỗi encoding |

Các biến liên quan realm, service, host và keytab phải nhất quán giữa KDC, Application Server và Client. Nếu đổi `KRB_REALM`, `APP_SERVICE_NAME` hoặc `APP_SERVER_NAME`, hãy set cùng giá trị ở cả ba terminal trước khi chạy.

Mặc định hệ thống gửi message qua TCP bằng ASN.1/DER. Nếu cần debug bằng payload JSON cũ, set cùng biến ở cả ba terminal:

```powershell
$env:KRB_WIRE_FORMAT = "json"
```

Ví dụ đổi port KDC:

```powershell
$env:KDC_PORT = "8889"
python -m kdc.kdc_server
```

Client phải dùng cùng port:

```powershell
$env:KDC_PORT = "8889"
python -m client.client_app
```

Ví dụ đổi port Application Server:

```powershell
$env:APP_SERVER_PORT = "8001"
python -m app_server.service_server
```

Client terminal cũng phải set:

```powershell
$env:APP_SERVER_PORT = "8001"
python -m client.client_app
```

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
| `app_server/<APP_SERVICE_NAME>.keytab.json` | KDC | Service principal, kvno, enctype và long-term key của service |
| `client/krb5cc_demo.json` | Client | TGT, service ticket, session key và metadata còn hiệu lực |

Các file keytab và credential cache là artifact runtime của demo. Không nên commit chúng vào repository.

### Bảng SQLite Chính

| Bảng | Mục đích |
| --- | --- |
| `principals` | Lưu principal, realm, salt, key, kvno, enctype, KDF metadata và trạng thái |
| `principal_aliases` | Map alias ngắn sang canonical principal |
| `audit_log` | Ghi sự kiện AS/TGS/KDC |
| `replay_cache` | Lưu fingerprint authenticator đã dùng để chặn replay |

KDC dùng upsert khi khởi tạo, nên principal mặc định sẽ được đồng bộ lại theo code hiện tại. Nếu muốn thay password hoặc principal theo cách nghiêm túc hơn, nên bổ sung admin CLI thay vì sửa trực tiếp SQLite.

## Kiểm Tra Nhanh

Kiểm tra cú pháp:

```powershell
python -m py_compile core\crypto.py core\principal.py core\keytab.py core\replay_cache.py core\messages.py core\asn1_codec.py core\network.py kdc\database.py kdc\as_handler.py kdc\tgs_handler.py kdc\kdc_server.py app_server\service_server.py client\credential_cache.py client\client_app.py
```

Kiểm tra port trên Windows:

```powershell
Get-NetTCPConnection -LocalPort 8888,8000 -ErrorAction SilentlyContinue
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
- Client verify mutual authentication bằng `timestamp + 1`.

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

### `KRB_AP_ERR_MODIFIED`

Nguyên nhân thường gặp:

- Ticket bị sửa hoặc decrypt bằng sai key.
- Service ticket không dành cho service đang chạy.
- Keytab không khớp key service trong KDC DB.
- Authenticator không khớp client principal trong ticket.

Cách xử lý:

1. Start KDC để export lại keytab.
2. Start lại Application Server để đọc keytab mới.
3. Xóa credential cache cũ nếu đã đổi realm, service host hoặc key.

### Client dùng ticket cũ ngoài ý muốn

Client lưu credential cache ở `client/krb5cc_demo.json` hoặc path trong `KRB5CCNAME`. Nếu muốn chạy lại từ AS Exchange với ticket mới, xóa cache file này sau khi dừng client.

### UnicodeEncodeError trên Windows

Các entrypoint chính đã reconfigure stdout/stderr sang UTF-8. Nếu terminal vẫn lỗi encoding:

```powershell
$env:PYTHONIOENCODING = "utf-8"
python -m client.client_app
```

## Runbook Demo

1. Mở terminal KDC và chạy `python -m kdc.kdc_server`.
2. Mở terminal Application Server và chạy `python -m app_server.service_server`.
3. Mở terminal Client và chạy `python -m client.client_app`.
4. Đăng nhập bằng `alice/alice_password`.
5. Ghi lại ba pha thành công: AS, TGS, AP.
6. Chạy lại client với `alice/wrong_password`.
7. Ghi lại lỗi `KDC_ERR_PREAUTH_FAILED`.
8. Nếu cần trình bày replay, gửi lại cùng authenticator và ghi lại `KRB_AP_ERR_REPEAT`.

## Dừng Process

Trong terminal server, nhấn `Ctrl+C`.

Nếu process chạy nền trên Windows:

```powershell
Get-Process python
Stop-Process -Id <PID>
```

Kiểm tra kỹ PID trước khi dừng để tránh ảnh hưởng process Python khác.
