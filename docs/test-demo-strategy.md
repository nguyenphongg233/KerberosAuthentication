# Chiến Lược Test Và Demo

Tài liệu này gom các lệnh kiểm tra và kịch bản demo nên dùng khi báo cáo. Mục tiêu là chứng minh project không chỉ chạy happy path, mà còn kiểm được các hành vi bảo mật quan trọng của Kerberos.

## Test Pyramid

| Tầng | Lệnh | Mục đích |
| --- | --- | --- |
| Compile check | `python -m py_compile ...` | Bắt lỗi cú pháp/import ở các module chính. |
| Regression in-process | `python -m unittest discover -s tests -p "test_*.py" -v` | Kiểm các logic bảo mật không cần mở port: preauth fail, replay, kvno/key rotation, keytab, ccache. |
| Smoke HTTP/cross-realm | `python scratch/test_cross_realm.py` | Chạy KDC + App Server bằng temp runtime, kiểm AS/TGS/AP qua HTTP Negotiate-style và cross-realm demo. |
| Manual demo | `python -m kdc.kdc_server`, `python -m app_server.service_server`, `python -m client.client_app` | Trình bày trực quan ba pha AS, TGS, AP cho người chấm. |

## Lệnh Nên Chạy Trước Khi Nộp

```powershell
python -m py_compile core\crypto.py core\principal.py core\keytab.py core\replay_cache.py core\messages.py core\asn1_codec.py core\network.py kdc\database.py kdc\as_handler.py kdc\tgs_handler.py kdc\kdc_server.py kdc\kadmin.py kdc\kadmin_web.py app_server\service_server.py client\credential_cache.py client\client_app.py scratch\test_cross_realm.py tests\test_kerberos_regression.py
```

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

```powershell
python scratch/test_cross_realm.py
```

## Regression Cases Đã Có

| Case | Ý nghĩa khi báo cáo |
| --- | --- |
| Wrong password -> `KDC_ERR_PREAUTH_FAILED` | Chứng minh password không gửi qua mạng; KDC chỉ kiểm encrypted pre-auth. |
| Unknown principal -> `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Chứng minh AS kiểm principal database trước khi cấp TGT. |
| Replayed TGS authenticator -> `KRB_AP_ERR_REPEAT` | Chứng minh replay cache hoạt động, timestamp một mình là chưa đủ. |
| Old TGT sau khi rotate `krbtgt` key vẫn xin được service ticket | Chứng minh key history/kvno gần Kerberos thật hơn. |
| Keytab exact kvno và highest fallback | Chứng minh App Server có thể chọn đúng service key version. |
| Ccache reload vẫn giữ `ticket_kvno`/`ticket_enctype` | Chứng minh cache bền vững hơn, không mất metadata quan trọng sau khi restart client. |

## Demo Matrix

| Demo | Cách chạy | Kỳ vọng |
| --- | --- | --- |
| Happy path local realm | Manual demo với `alice/alice_password` | Client hoàn tất AS -> TGS -> AP, nhận AP-REP và nội dung admin. |
| Wrong password | Manual demo với `alice/wrong_password` hoặc regression test | Dừng ở AS, trả `KDC_ERR_PREAUTH_FAILED`. |
| Cross-realm | `python scratch/test_cross_realm.py` | `alice@DEMO.LOCAL` lấy ticket cho `fileserver/localhost@PARTNER.LOCAL`. |
| Replay protection | Regression test `test_tgs_rejects_replayed_authenticator` | Request thứ hai với cùng authenticator bị `KRB_AP_ERR_REPEAT`. |
| Key rotation | Regression test `test_old_tgt_survives_tgs_key_rotation` | TGT cũ vẫn dùng được nhờ `principal_keys` và `kvno`. |

## Thứ Tự Demo Khuyến Nghị

1. Chạy `python -m unittest discover -s tests -p "test_*.py" -v` để chứng minh các case bảo mật.
2. Chạy `python scratch/test_cross_realm.py` để chứng minh luồng đầy đủ có HTTP App Server và cross-realm.
3. Demo thủ công ba terminal nếu người chấm muốn nhìn interaction thật.
4. Mở KAdmin Web sau cùng để xem principal/audit log; không dùng nó làm bằng chứng bảo mật chính vì admin web là demo local.

## Không Nên Demo Trực Tiếp

- Không demo bằng cách sửa/xóa `kdc/database.db` thật trong repo.
- Không chạy test cũ/hard-code đường dẫn máy cá nhân.
- Không nhận rằng HTTP Negotiate là SPNEGO/GSSAPI đầy đủ; project đang dùng raw AP-REQ/AP-REP DER trong header.
- Không gọi authorization-data demo là PAC Active Directory thật.

## Điểm Cần Nói Khi Bị Hỏi

- Test in-process nhanh và ổn định hơn vì không phụ thuộc port, timing server hoặc terminal.
- Smoke cross-realm vẫn cần vì nó kiểm đường tích hợp thật: KDC socket, App Server HTTP, client cache và HTTP Negotiate-style.
- Manual demo dùng để trình bày, không thay thế regression test.
