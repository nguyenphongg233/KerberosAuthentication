# Demo Walkthrough Cho Bao Cao

Thu muc `scratch/` dung de chay demo co log ro rang, khong dung runtime that cua repo. Cac script tao temp database/keytab/ccache rieng, vi vay co the chay nhieu lan ma khong lam hong `kdc/database.db`, keytab hoac credential cache dang demo thu cong.

## Lenh Nen Chay Khi Bao Cao

```powershell
python scratch/demo_security_flows.py
python scratch/demo_tgt_renewal.py
python scratch/test_cross_realm.py
```

Neu can kiem tra nhanh truoc khi nop:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

## Demo Truy Cap Service Sau Khi Co Ve

Khi chup anh cho report, nen co mot anh rieng the hien client dung service ticket de truy cap FileServer va nhan protected resource:

```powershell
python -m client.kinit alice
python -m client.kvno fileserver
python -m client.kaccess fileserver
```

Phan can chup trong output:

```text
[Client] Mutual authentication verified
SERVICE RESPONSE (HTML/Text)
Protected File Server access granted
authorized_action: LIST_PROTECTED_FILES
available_resources:
- project-overview.txt
- kdc-audit-log.txt
```

Neu chay lai `kaccess` khi cache con han, client dung ve trong cache de truy cap service ma khong can nhap lai password.

## `demo_security_flows.py`

Day la script quan trong nhat de dua output vao bao cao. Moi scenario in theo mau:

```text
[STEP] attacker/client lam gi
[MSG]  ben gui -> ben nhan: message
[RESULT] BLOCKED/ALLOWED: ket luan
```

Scenario hien co:

| Scenario | Tac dong / message | Ket qua can chup vao bao cao |
| --- | --- | --- |
| Normal AS -> TGS flow | Client gui `AS_REQ`, nhan `AS_REP`, gui `TGS_REQ`, nhan `TGS_REP` | `ALLOWED`, `Kc_tgs` duoc thiet lap |
| Wrong password / forged pre-auth | Attacker ma hoa `PA-ENC-TIMESTAMP` bang key sai | `KDC_ERR_PREAUTH_FAILED`, `BLOCKED` |
| Account lockout | Gui sai pre-auth nhieu lan roi thu password dung | `KDC_ERR_CLIENT_REVOKED`, `BLOCKED` |
| Tampered TGT | Sua 1 byte trong encrypted TGT | `KRB_AP_ERR_MODIFIED`, `BLOCKED` |
| Replayed TGS authenticator | Gui lai nguyen `TGS_REQ` cu | `KRB_AP_ERR_REPEAT`, `BLOCKED` |
| Replayed AP authenticator | Gui lai nguyen `AP_REQ` qua HTTP Negotiate | HTTP `403`, `KRB_AP_ERR_REPEAT`, `BLOCKED` |
| Tampered service ticket | Sua 1 byte trong encrypted service ticket | HTTP `403`, `KRB_AP_ERR_MODIFIED`, `BLOCKED` |
| Wrong-service AP-REQ | Keytab co `fileserver` va `mailserver`, attacker doi outer service sang `mailserver` nhung giu ticket cua `fileserver` | HTTP `403`, `KRB_AP_ERR_MODIFIED`, `BLOCKED` |
| Key rotation | Rotate `krbtgt` key sau khi TGT da cap | TGT cu con han van `ALLOWED` nho `kvno` va `principal_keys` |

## `demo_tgt_renewal.py`

Dung khi can trinh bay rieng co che renew TGT:

```text
[MSG] Client cache: Expired renewable TGT
[MSG] Client -> TGS: TGS_REQ renew
[MSG] TGS -> Client: TGS_REP renewed TGT
[RESULT] ALLOWED: Expired TGT was renewed because renew_till has not passed
[RESULT] ALLOWED: Renewed TGT can be used for normal TGS exchange
```

Nen dua vao bao cao cac field: `old_endtime`, `new_endtime`, `renew_till`, `service_principal`.

## `test_cross_realm.py`

Dung de chung minh full flow co subprocess KDC/App Server va cross-realm:

| Case | Y nghia |
| --- | --- |
| `charlie@PARTNER.LOCAL -> fileserver/localhost@PARTNER.LOCAL` | User trong realm PARTNER truy cap service PARTNER thanh cong |
| `alice@DEMO.LOCAL -> fileserver/localhost@PARTNER.LOCAL` | Client realm DEMO lay cross-realm TGT roi lay service ticket realm PARTNER |

Output can chup:

```text
[Client] Step 1: Requesting Cross-Realm TGT for 'krbtgt/PARTNER.LOCAL@DEMO.LOCAL'
[Client] Cross-Realm TGT obtained successfully
[Client] Service Ticket for 'fileserver/localhost@PARTNER.LOCAL' cached successfully via Cross-Realm Trust
[Client] Mutual authentication verified
[Smoke] SUCCESS: cross-realm smoke test passed.
```

## Nen Dua Vao Report Nhu The Nao

Khong nen dan toan bo log. Moi co che chi can 5-10 dong dai dien:

1. Lenh da chay.
2. Message bi tac dong.
3. Error code hoac HTTP status.
4. Dong `[RESULT] BLOCKED/ALLOWED`.

Thu tu de trong bao cao:

1. Bang tong hop `unittest`: `Ran 35 tests ... OK`.
2. Trich `demo_security_flows.py` cho wrong password, tampered TGT, replay TGS, replay AP, wrong-service AP.
3. Trich `demo_tgt_renewal.py` cho TGT renewal.
4. Trich `test_cross_realm.py` cho cross-realm.
