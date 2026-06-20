# Chiến Lược Test Và Demo

Tài liệu này gom các lệnh kiểm tra và kịch bản demo nên dùng khi báo cáo. Mục tiêu là chứng minh project không chỉ chạy happy path, mà còn kiểm được các hành vi bảo mật quan trọng của Kerberos.

## Test Pyramid

| Tầng | Lệnh | Mục đích |
| --- | --- | --- |
| Compile check | `python -m compileall core kdc app_server client tests scratch\test_cross_realm.py scratch\demo_security_flows.py scratch\demo_tgt_renewal.py` | Bắt lỗi cú pháp/import ở các module chính. |
| Regression in-process | `python -m unittest discover -s tests -p "test_*.py" -v` | Kiểm 32 tests cho preauth, lockout, replay, AP, renewal, kvno/key rotation, keytab, ccache, KAdmin Web API và E2E. |
| Verbose security-flow demo | `python scratch/demo_security_flows.py` | In rõ message nào được gửi, attacker tác động gì, hệ thống trả lỗi/chặn ra sao. |
| Verbose TGT renewal demo | `python scratch/demo_tgt_renewal.py` | In riêng luồng TGT hết hạn nhưng còn `renew_till`, renew thành công rồi xin service ticket. |
| Smoke HTTP/cross-realm | `python scratch/test_cross_realm.py` | Chạy KDC + App Server bằng temp runtime, kiểm AS/TGS/AP qua HTTP Negotiate-style và cross-realm demo. |
| Manual demo | `python -m kdc.kdc_server`, `python -m app_server.service_server`, `python -m client.client_app` | Trình bày trực quan ba pha AS, TGS, AP cho người chấm. |

## Lệnh Nên Chạy Trước Khi Nộp

```powershell
python -m compileall core kdc app_server client tests scratch\test_cross_realm.py scratch\demo_security_flows.py scratch\demo_tgt_renewal.py
```

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

```powershell
python scratch/demo_security_flows.py
```

```powershell
python scratch/demo_tgt_renewal.py
```

```powershell
python scratch/test_cross_realm.py
```

## Regression Cases Đã Có

Mỗi cơ chế chính có một file test riêng, có thể chạy lẻ hoặc chạy toàn bộ bằng `unittest discover`.

| File | Case | Ý nghĩa khi báo cáo |
| --- | --- | --- |
| `tests/test_as_preauth.py` | Wrong password, unknown principal, missing pre-auth, old timestamp, valid AS-REP, account lockout | Chứng minh AS chỉ cấp TGT khi client chứng minh được long-term key hợp lệ và khóa tạm khi fail nhiều lần. |
| `tests/test_replay_protection.py` | Replayed TGS authenticator -> `KRB_AP_ERR_REPEAT` | Chứng minh replay cache hoạt động, timestamp một mình là chưa đủ. |
| `tests/test_ticket_integrity.py` | Tampered TGT -> `KRB_AP_ERR_MODIFIED` | Chứng minh ticket ciphertext bị sửa sẽ không qua được decrypt/checksum. |
| `tests/test_ticket_lifetime.py` | Expired / not-yet-valid TGT | Chứng minh TGS kiểm `starttime`/`endtime` của ticket. |
| `tests/test_service_lookup.py` | Unknown service -> `KDC_ERR_S_PRINCIPAL_UNKNOWN` | Chứng minh TGS không cấp ticket cho service không có trong DB. |
| `tests/test_key_rotation.py` | Old TGT sau khi rotate `krbtgt` key vẫn xin được service ticket | Chứng minh key history/kvno gần Kerberos thật hơn. |
| `tests/test_keytab_kvno.py` | Keytab exact kvno và highest fallback | Chứng minh App Server có thể chọn đúng service key version. |
| `tests/test_ccache_metadata.py` | Ccache metadata và expired service ticket | Chứng minh cache giữ metadata quan trọng và tự bỏ ticket hết hạn. |
| `tests/test_asn1_message_format.py` | ASN.1 application tags và AS-REQ round-trip | Chứng minh wire format bám đúng lớp message Kerberos chính. |
| `tests/test_application_server_ap.py` | AP replay, wrong service, tampered service ticket, wrong-service khi keytab có nhiều service key | Chứng minh Application Server chặn replay và ticket không dùng được sai ngữ cảnh. |
| `tests/test_tgt_renewal.py` | TGT renewal success/fail | Chứng minh `renew_till` kiểm soát việc gia hạn TGT. |
| `tests/test_client_tgt_renewal.py` | `client_app.renew_tgt_exchange()` renew cache rồi xin service ticket | Chứng minh renewal chạy được qua client-level flow, không chỉ gọi TGS handler trực tiếp. |
| `tests/test_kadmin_cli.py` | `cpw`, `ktadd --all-versions`, audit | Chứng minh key rotation có kvno/key history và keytab export đủ version. |
| `tests/test_kadmin_web_api.py` | Add/list/toggle/delete principal, audit log | Chứng minh Web API quản trị nối đúng vào database/audit. |
| `tests/test_e2e_subprocess.py` | KDC/App Server subprocess + client CLI happy path và wrong password | Chứng minh luồng thật qua socket/HTTP/input CLI, gồm cả case fail ở AS. |

## Verbose Security-Flow Demo

Khi cần cho người chấm thấy rõ luồng và hành vi tấn công, chạy:

```powershell
python scratch/demo_security_flows.py
```

Script này in theo dạng:

```text
[MSG] Client -> AS: AS_REQ
[MSG] AS -> Client: AS_REP
[MSG] Attacker -> TGS: TGS_REQ
[MSG] TGS -> Attacker: KRB_ERROR
[RESULT] BLOCKED: ...
```

Các scenario hiện có:

| Scenario | Message/tác động | Kết quả |
| --- | --- | --- |
| Normal AS -> TGS flow | Client gửi `AS_REQ`, nhận `AS_REP`, gửi `TGS_REQ`, nhận `TGS_REP` | `ALLOWED` |
| Wrong password / forged pre-auth | Attacker mã hóa `PA-ENC-TIMESTAMP` bằng key derive từ password sai | `KDC_ERR_PREAUTH_FAILED`, `BLOCKED` |
| Tampered TGT | Attacker sửa 1 byte trong encrypted TGT | `KRB_AP_ERR_MODIFIED`, `BLOCKED` |
| Replayed TGS authenticator | Attacker gửi lại nguyên `TGS_REQ` cũ với cùng `ctime/cusec` | `KRB_AP_ERR_REPEAT`, `BLOCKED` |
| Key rotation | Admin rotate `krbtgt` key sau khi TGT đã cấp | TGT cũ còn hạn vẫn `ALLOWED` nhờ `kvno` và `principal_keys` |

## Verbose TGT Renewal Demo

Khi cần trình bày riêng cơ chế renew, chạy:

```powershell
python scratch/demo_tgt_renewal.py
```

Script này in rõ:

```text
[MSG] Client cache: Expired renewable TGT
[MSG] Client -> TGS: TGS_REQ renew
[MSG] TGS -> Client: TGS_REP renewed TGT
[RESULT] ALLOWED: Expired TGT was renewed because renew_till has not passed
```

## Demo Matrix

| Demo | Cách chạy | Kỳ vọng |
| --- | --- | --- |
| Happy path local realm | Manual demo với `alice/alice_password` | Client hoàn tất AS -> TGS -> AP, nhận AP-REP và nội dung admin. |
| Wrong password | Manual demo với `alice/wrong_password`, `python tests/test_e2e_subprocess.py` hoặc regression test | Dừng ở AS, trả `KDC_ERR_PREAUTH_FAILED`, không đi tiếp TGS/AP. |
| Cross-realm | `python scratch/test_cross_realm.py` | `alice@DEMO.LOCAL` lấy ticket cho `fileserver/localhost@PARTNER.LOCAL`. |
| Replay protection | `python tests/test_replay_protection.py` | Request thứ hai với cùng authenticator bị `KRB_AP_ERR_REPEAT`. |
| AP replay/wrong service | `python tests/test_application_server_ap.py` | Replay tại Application Server bị `KRB_AP_ERR_REPEAT`; ticket bị sửa hoặc dùng sai service bị `KRB_AP_ERR_MODIFIED`, kể cả khi keytab chứa nhiều service key. |
| TGT renewal | `python scratch/demo_tgt_renewal.py` | TGT hết hạn nhưng còn `renew_till` được renew và dùng tiếp để xin service ticket. |
| Client-level renewal | `python tests/test_client_tgt_renewal.py` | Client gọi `renew_tgt_exchange()`, cập nhật cache và dùng TGT mới cho TGS Exchange. |
| Kerberos-style CLI | `python -m client.kinit alice`, `python -m client.klist`, `python -m client.kvno fileserver`, `python -m client.kaccess fileserver`, `python -m client.kdestroy` | Chứng minh thao tác người dùng cơ bản: lấy TGT, xem cache, xin service ticket, truy cập service và xóa cache. |
| Key rotation | Regression test `test_old_tgt_survives_tgs_key_rotation` | TGT cũ vẫn dùng được nhờ `principal_keys` và `kvno`. |
| KAdmin Web API | `python tests/test_kadmin_web_api.py` | REST API add/list/toggle/delete principal và ghi audit log. |
| Account lockout | `python tests/test_as_preauth.py` | Sau nhiều lần pre-auth fail, AS trả `KDC_ERR_CLIENT_REVOKED` cho tới khi hết lockout. |
| E2E subprocess | `python tests/test_e2e_subprocess.py` | KDC/App Server chạy bằng subprocess trên port tạm, client CLI hoàn tất đủ AS/TGS/AP; wrong password bị chặn ngay AS. |

## Thứ Tự Demo Khuyến Nghị

1. Chạy `python -m unittest discover -s tests -p "test_*.py" -v` để chứng minh các case bảo mật tự động.
2. Chạy `python scratch/demo_security_flows.py` để cho thấy message, attacker action và kết quả `BLOCKED/ALLOWED`.
3. Chạy `python scratch/demo_tgt_renewal.py` nếu muốn trình bày riêng TGT renewal.
4. Chạy `python scratch/test_cross_realm.py` để chứng minh luồng đầy đủ có HTTP App Server và cross-realm.
5. Demo thủ công ba terminal nếu người chấm muốn nhìn interaction thật.
6. Mở KAdmin Web sau cùng để xem principal/audit log; không dùng nó làm bằng chứng bảo mật chính vì admin web là demo local.

## Không Nên Demo Trực Tiếp

- Không demo bằng cách sửa/xóa `kdc/database.db` thật trong repo.
- Không chạy test cũ/hard-code đường dẫn máy cá nhân.
- Không nhận rằng HTTP Negotiate là SPNEGO/GSSAPI đầy đủ; project đang dùng raw AP-REQ/AP-REP DER trong header.
- Không gọi authorization-data demo là PAC Active Directory thật.

## Điểm Cần Nói Khi Bị Hỏi

- Test in-process nhanh và ổn định hơn vì không phụ thuộc port, timing server hoặc terminal.
- Smoke cross-realm vẫn cần vì nó kiểm đường tích hợp thật: KDC socket, App Server HTTP, client cache và HTTP Negotiate-style.
- Manual demo dùng để trình bày, không thay thế regression test.
