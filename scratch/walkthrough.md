# Demo Scenarios Walkthrough — KerberosAuthentication

## Tổng Quan

Đã tạo file [demo_all_features.py](file:///d:/OneDrive/Documents/KerberosAuthentication/scratch/demo_all_features.py) chứa **17 kịch bản demo** bao phủ toàn bộ tính năng đã triển khai trong project. Script chạy **in-process** (không cần mở 3 terminal), sử dụng temp runtime riêng, không ảnh hưởng database/keytab của repo.

## Cách Chạy

```powershell
python scratch/demo_all_features.py
```

> [!NOTE]
> Script tự tạo temp database + keytab + ccache riêng. Không cần khởi động KDC hay App Server.

---

## 17 Kịch Bản Demo

### Nhóm 1: Ba Pha Chính (AS → TGS → AP)

| # | Demo | Tính năng RFC 4120 | Kỳ vọng |
|---|---|---|---|
| 1 | **Happy Path** | AS Exchange + TGS Exchange + AP Exchange | alice hoàn tất cả 3 pha, nhận service ticket có authorization data (admin) |

### Nhóm 2: Xử Lý Lỗi & Bảo Mật

| # | Demo | Tính năng RFC 4120 | Kỳ vọng |
|---|---|---|---|
| 2 | **Wrong Password** | Pre-authentication (Section 3.1) | `KDC_ERR_PREAUTH_FAILED` — chứng minh password không gửi qua mạng |
| 3 | **Unknown Principal** | Principal database (Section 3.1.2) | `KDC_ERR_C_PRINCIPAL_UNKNOWN` |
| 4 | **Replay Detection** | Replay cache (Section 3.2.3) | Request thứ 2 bị `KRB_AP_ERR_REPEAT` |
| 8 | **Unknown Service** | Service lookup (Section 3.3.2) | `KDC_ERR_S_PRINCIPAL_UNKNOWN` |
| 14 | **Clock Skew** | Clock skew check (Section 3.1.2) | Timestamp 10 phút trước bị `KRB_AP_ERR_SKEW` |
| 16 | **Ticket Tampering** | AES-CTS-HMAC-SHA1-96 (RFC 3961) | Cố tình sửa đổi 1 byte của TGT bị từ chối với lỗi `KRB_AP_ERR_MODIFIED` (sai MAC/Ciphertext) |
| 17 | **Forged Authenticator**| Session Key Validation | Kẻ tấn công giả mạo Authenticator bằng random key bị từ chối với lỗi `KRB_AP_ERR_MODIFIED` |

### Nhóm 3: Ticket Flags & Renewal

| # | Demo | Tính năng RFC 4120 | Kỳ vọng |
|---|---|---|---|
| 5 | **TGT Renewal** | Renewable tickets (Section 2.3) | TGS cấp TGT mới với `endtime` mở rộng |

### Nhóm 4: Key Management & Rotation

| # | Demo | Tính năng RFC 4120 | Kỳ vọng |
|---|---|---|---|
| 6 | **Key Rotation** | Key version number (kvno) | TGT cũ vẫn dùng được sau khi rotate key nhờ `principal_keys` history |
| 11 | **Key History DB** | `principal_keys` table | 3+ versions lưu trữ, lookup by exact kvno hoạt động |
| 12 | **Idempotent Init** | Database migration | `init_database()` không reset kvno đã thay đổi |

### Nhóm 5: Authorization & RBAC

| # | Demo | Tính năng RFC 4120 | Kỳ vọng |
|---|---|---|---|
| 7 | **RBAC (bob vs alice)** | Authorization Data (Section 5.2.6) | alice có `admins` group, bob chỉ có `users` → phân quyền khác nhau tại App Server |

### Nhóm 6: Keytab & Credential Cache

| # | Demo | Tính năng | Kỳ vọng |
|---|---|---|---|
| 9 | **Keytab Multi-Version** | MIT Keytab v2 binary | 3 kvno entries, exact kvno lookup + highest fallback |
| 10 | **Ccache Persistence** | MIT ccache v4 binary | `ticket_kvno` + `ticket_enctype` vẫn đúng sau reload |

### Nhóm 7: Encoding & Handshake

| # | Demo | Tính năng | Kỳ vọng |
|---|---|---|---|
| 13 | **ASN.1/DER Roundtrip** | ASN.1 encoding (Section 5) | Encode → decode KRB_ERROR + AS_REQ giữ nguyên nội dung |
| 15 | **Subkey & Seq Number** | AP Exchange handshake (Section 3.2) | Authenticator chứa subkey + seq-number, decrypt thành công |

---

## So Sánh Với Test Hiện Có

| Test hiện có | Demo mới bổ sung |
|---|---|
| [test_kerberos_regression.py](file:///d:/OneDrive/Documents/KerberosAuthentication/tests/test_kerberos_regression.py): 6 test cases | [demo_all_features.py](file:///d:/OneDrive/Documents/KerberosAuthentication/scratch/demo_all_features.py): 17 scenarios |
| ❌ Không có happy path end-to-end | ✅ Demo 1: Full 3-phase path |
| ❌ Không demo RBAC bob vs alice | ✅ Demo 7: So sánh groups |
| ❌ Không demo clock skew | ✅ Demo 14: Timestamp cũ bị reject |
| ❌ Không demo ASN.1 roundtrip | ✅ Demo 13: Encode/decode cycle |
| ❌ Không demo subkey/seq-number | ✅ Demo 15: Handshake fields |
| ❌ Không demo TGT renewal | ✅ Demo 5: Renew kdc-options |
| ❌ Không demo unknown service | ✅ Demo 8: Service principal not found |
| ❌ Chưa mô phỏng tấn công (Ticket Tampering / Forged Authenticator) | ✅ Demo 16, 17: Phản hồi lỗi `KRB_AP_ERR_MODIFIED` |

---

## Output Mẫu Kỳ Vọng

```
██████████████████████████████████████████████████████████████████████
  KERBEROS V5 COMPREHENSIVE DEMO — ALL FEATURES
  Dựa trên RFC 4120 / RFC 3961 / RFC 3962
██████████████████████████████████████████████████████████████████████

======================================================================
  Demo 1: Happy Path — AS → TGS → AP (alice@DEMO.LOCAL)
======================================================================
  ▸ Phase 1: AS Exchange — alice xin TGT
    ✅ PASS: AS_REP received with TGT
    ✅ PASS: TGT has 'initial' flag
    ✅ PASS: TGT has 'pre_authent' flag
    ✅ PASS: TGT has 'renewable' flag
  ▸ Phase 2: TGS Exchange — alice xin Service Ticket cho fileserver
    ✅ PASS: TGS_REP received for 'fileserver/localhost@DEMO.LOCAL'
  ▸ Phase 3: AP Exchange — alice truy cập fileserver
    ✅ PASS: Service ticket contains correct client principal
    ✅ PASS: alice has admin group in ticket authorization data
    ✅ PASS: Complete AS→TGS→AP path succeeded

...

======================================================================
  SUMMARY: 35/35 passed, 0/35 failed
  🎉 ALL DEMOS PASSED!
======================================================================
```

## Thứ Tự Demo Khuyến Nghị Khi Báo Cáo

1. **Chạy regression test** trước: `python -m unittest discover -s tests -p "test_*.py" -v`
2. **Chạy demo toàn bộ**: `python scratch/demo_all_features.py`
3. **Chạy cross-realm smoke**: `python scratch/test_cross_realm.py`
4. **Demo thủ công 3 terminal** nếu cần interaction trực quan
5. Mở **KAdmin Web** cuối cùng để xem principal/audit log
