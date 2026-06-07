# Hướng Dẫn Phát Triển

Tài liệu này dành cho người tiếp tục phát triển hoặc bảo trì project KerberosAuthentication. Mục tiêu chính là giữ code dễ đọc cho mục đích học thuật, đồng thời đảm bảo mọi thay đổi giao thức đều được phản ánh đầy đủ trong tài liệu.

## Nguyên Tắc Phát Triển

- Logic Kerberos nằm trong AS/TGS/AP handler, không trộn vào network layer.
- Network layer chỉ xử lý TCP framing và gọi ASN.1/DER codec hoặc JSON fallback.
- ASN.1/DER schema và mapping nằm trong `core/asn1_codec.py`.
- Crypto layer chỉ xử lý KDF, sinh key, encrypt/decrypt và chuyển đổi key.
- Principal/realm normalization nằm trong `core/principal.py`.
- State bền vững của KDC nằm trong `kdc/database.py`.
- Keytab và replay cache dùng helper riêng trong `core/keytab.py` và `core/replay_cache.py`.
- Mọi thay đổi message field phải cập nhật `docs/protocol.md` và `docs/message-reference.md`.
- Mọi thay đổi security behavior phải cập nhật `docs/security.md`.
- Lỗi protocol nên trả `KRB_ERROR`, tránh để exception làm client timeout.
- Validation phía server phải fail closed: thiếu field, sai principal, timestamp lệch, ticket hết hạn hoặc decrypt fail đều bị từ chối.

## Quy Ước Code

| Chủ đề | Quy ước |
| --- | --- |
| Entry point | Chạy bằng `python -m package.module` |
| Message model | Handler dùng dict nội bộ để dễ đọc; wire format mặc định là ASN.1/DER |
| Message type | Dùng constant từ `core/messages.py` |
| Principal | Dùng helper trong `core/principal.py`, không tự nối chuỗi rời rạc |
| Key derivation | Dùng `derive_key(password, salt=principal_salt(...))` |
| Session key | Dùng `generate_session_key()` |
| Ticket lifetime | Dùng constants trong `core/messages.py` |
| Replay | Dùng `authenticator_cache_key()` và `check_and_store()` |
| File runtime | Keytab/cache/database không nên commit |

## Luồng Thay Đổi Giao Thức

Khi thêm hoặc sửa một field trong AS/TGS/AP:

1. Cập nhật constant hoặc helper nếu cần.
2. Cập nhật `core/asn1_codec.py` nếu field nằm trên wire DER.
3. Cập nhật handler sinh field.
4. Cập nhật handler validate field.
5. Cập nhật client đọc và kiểm tra field.
6. Cập nhật credential cache nếu field cần lưu lâu hơn một process.
7. Cập nhật `docs/protocol.md`.
8. Cập nhật `docs/message-reference.md`.
9. Chạy `py_compile` và end-to-end test với `KRB_WIRE_FORMAT=der`.

## Thêm Service Demo Mới

Application Server hiện được cấu hình mặc định cho service:

```text
fileserver/localhost@DEMO.LOCAL
```

Để chạy service khác, set `APP_SERVICE_NAME` ở cả KDC, Application Server và Client. Code hiện đọc logical service từ:

```python
APP_SERVICE_NAME = os.getenv("APP_SERVICE_NAME", "fileserver")
APP_SERVICE_PRINCIPAL = service_principal(APP_SERVICE_NAME, APP_SERVER_NAME, REALM)
```

### 1. Thêm principal service vào KDC

Trong `kdc/database.py`, thêm service vào `DEFAULT_PRINCIPALS` hoặc tạo admin CLI riêng.

Ví dụ service `mailserver/localhost@DEMO.LOCAL`:

```python
{
    "principal_name": service_principal("mailserver", "localhost", REALM),
    "password": "mailserver_secret",
    "principal_type": "service",
    "keytab_path": os.path.join(PROJECT_ROOT, "app_server", "mailserver.keytab.json"),
}
```

KDC sẽ upsert principal và export keytab khi start.

### 2. Cập nhật client

Trong `client/client_app.py`, service hiện tại được request bằng:

```python
service_name = APP_SERVICE_NAME
```

Nếu thay đổi service mặc định, hãy set `APP_SERVICE_NAME` trước khi chạy client.

### 3. Cập nhật tài liệu và test

Cần cập nhật:

- `README.md`.
- `docs/operations.md`.
- `docs/architecture.md`.
- `docs/protocol.md` nếu message thay đổi.
- Test happy path với service mới.
- Test ticket cho service A không dùng được ở service B.

## Thêm Error Code Mới

1. Thêm constant vào `core/messages.py`.
2. Dùng constant trong handler tương ứng.
3. Đảm bảo response giữ format:

```python
{
    "msg_type": ERROR,
    "error_code": NEW_ERROR_CODE,
    "error_message": "Human-readable message"
}
```

4. Cập nhật `docs/message-reference.md`.
5. Cập nhật `docs/operations.md` nếu lỗi có thể xuất hiện trong vận hành.
6. Thêm test cho error path.

## Chiến Lược Automated Test

Project hiện chưa có test suite chính thức. Cấu trúc đề xuất:

```text
tests/
  test_crypto.py
  test_principal.py
  test_keytab.py
  test_asn1_codec.py
  test_replay_cache.py
  test_database.py
  test_as_handler.py
  test_tgs_handler.py
  test_service_server.py
  test_end_to_end.py
```

### Test crypto

- `derive_key` deterministic với cùng password, salt và iteration.
- `derive_key` tạo key khác nhau nếu salt khác.
- `generate_session_key` tạo key khác nhau.
- `encrypt`/`decrypt` round trip.
- Wrong key gây `InvalidToken`.

### Test principal

- `user_principal("alice") -> alice@REALM`.
- `service_principal("fileserver") -> fileserver/host@REALM`.
- `tgs_principal(REALM) -> krbtgt/REALM@REALM`.
- Alias service trả cả `fileserver/host` và `fileserver`.

### Test ASN.1/DER codec

- Round-trip `AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`, `AP_REQ`, `AP_REP`, `KRB_ERROR`.
- Kiểm application tag đúng: 10, 11, 12, 13, 14, 15, 30.
- Kiểm `TGS_REQ` có `PA-TGS-REQ` chứa `AP-REQ` DER.
- Kiểm `Ticket` encode bằng `[APPLICATION 1]`.
- Kiểm nonce là `UInt32`.

### Test database

- `ensure_schema` tạo đủ bảng.
- `init_database` upsert principal mặc định.
- `get_principal` resolve được alias.
- Service keytab được ghi đúng principal, kvno và enctype.
- `audit_event` ghi được event.

### Test AS handler

- Known user + valid preauth -> `AS_REP`.
- Unknown user -> `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
- Missing preauth -> `KDC_ERR_PREAUTH_FAILED`.
- Wrong password/preauth key -> `KDC_ERR_PREAUTH_FAILED`.
- Old timestamp -> `KRB_AP_ERR_SKEW`.
- Nonce được echo trong encrypted client part.
- TGT có `server_principal = krbtgt/REALM@REALM`.

### Test TGS handler

- Valid TGT + authenticator -> `TGS_REP`.
- Tampered TGT -> `KRB_AP_ERR_MODIFIED`.
- Expired TGT -> `KRB_AP_ERR_TKT_EXPIRED`.
- Authenticator principal mismatch -> `KRB_AP_ERR_MODIFIED`.
- Replayed authenticator -> `KRB_AP_ERR_REPEAT`.
- Unknown service -> `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
- Service ticket có `server_principal` đúng service.

### Test Application Server

- Valid `AP_REQ` -> `AP_REP`.
- Tampered service ticket -> `KRB_AP_ERR_MODIFIED`.
- Ticket for different service -> `KRB_AP_ERR_MODIFIED`.
- Expired ticket -> `KRB_AP_ERR_TKT_EXPIRED`.
- Authenticator replay -> `KRB_AP_ERR_REPEAT`.
- AP_REP timestamp bằng request timestamp + 1.

### End-to-End Test

Nên start KDC và Application Server trong subprocess với port riêng:

```powershell
$env:KRB_WIRE_FORMAT = "der"
$env:KDC_PORT = "18888"
$env:APP_SERVER_PORT = "18000"
```

Sau đó feed input cho client:

```text
alice
alice_password
```

Kỳ vọng:

- Client hoàn thành đủ ba pha.
- Credential cache được tạo.
- KDC audit log có event AS/TGS success.
- Wrong password fail ở AS.

## Test In-Process Không Dùng Port

Nếu không muốn phụ thuộc network port:

1. Tạo SQLite database tạm.
2. Gọi `ensure_schema`.
3. Upsert principal bằng `upsert_principal`.
4. Gọi trực tiếp `handle_as_request`.
5. Gọi trực tiếp `handle_tgs_request`.
6. Test AP handler bằng `socket.socketpair()` hoặc tách validation thành hàm thuần.

Cách này nhanh và phù hợp cho CI.

## Cơ Hội Refactor

### Structured Models

Message hiện là raw dict. Có thể dùng:

- `dataclasses`.
- `TypedDict`.
- `pydantic`.

Lợi ích:

- Validate field tốt hơn.
- Type hints rõ hơn.
- Giảm lỗi typo field name.

### Config Object

Config hiện nằm rải rác trong `core/messages.py`, `core/principal.py`, `kdc/database.py` và environment variable. Có thể gom vào:

```text
core/config.py
```

Nội dung nên gồm:

- Realm.
- Host/port.
- Ticket lifetime.
- Clock skew.
- DB path.
- Keytab path.
- Credential cache path.
- Replay cache path.

### Principal Management CLI

Nên bổ sung:

```text
python -m kdc.admin create-principal alice
python -m kdc.admin disable-principal alice@DEMO.LOCAL
python -m kdc.admin rotate-key fileserver/localhost@DEMO.LOCAL
python -m kdc.admin export-keytab fileserver/localhost@DEMO.LOCAL
python -m kdc.admin list-principals
```

CLI này sẽ giảm nhu cầu sửa `DEFAULT_PRINCIPALS` trong code.

### Distributed Replay Cache

Replay cache hiện dùng SQLite. Nếu mô phỏng nhiều KDC/App Server instance, có thể tách backend:

```python
class ReplayCache:
    def check_and_store(self, cache_name, cache_key, client, server, auth_time, now, max_age) -> bool:
        ...
```

Backend có thể là SQLite, Redis hoặc database dùng chung.

### Authorization Layer

Kerberos chỉ xác thực danh tính. Application Server hiện chưa có authorization. Có thể thêm:

- Role.
- Group.
- ACL theo service resource.
- Authorization data trong service ticket.

## Quy Tắc Cập Nhật Tài Liệu

| Thay đổi | Tài liệu cần cập nhật |
| --- | --- |
| Message field | `docs/message-reference.md`, `docs/protocol.md` |
| ASN.1/DER schema/tag | `core/asn1_codec.py`, `docs/message-reference.md`, `docs/protocol.md` |
| Error code | `docs/message-reference.md`, `docs/operations.md` |
| Config/env var | `README.md`, `docs/operations.md` |
| Component mới | `README.md`, `docs/architecture.md` |
| Security behavior | `docs/security.md`, `docs/protocol.md` |
| Run command | `README.md`, `docs/operations.md` |
| Database schema | `docs/architecture.md`, `docs/operations.md` |

## Definition Of Done Cho Thay Đổi Giao Thức

- Code pass `py_compile`.
- Happy path chạy đủ AS/TGS/AP với `KRB_WIRE_FORMAT=der`.
- ASN.1/DER round-trip test pass.
- Sai password fail ở AS.
- Wrong service principal fail ở AP.
- Replay authenticator fail ở TGS hoặc AP.
- Ticket hết hạn bị từ chối.
- `README.md` vẫn phản ánh đúng luồng chạy.
- `docs/protocol.md` và `docs/message-reference.md` đã cập nhật.
- `docs/security.md` đã cập nhật nếu có thay đổi bảo mật.
