# Report screenshot checklist

Save screenshots in this folder with the exact filenames below. The LaTeX report
already contains placeholders for these files.

## Run/test summary

- `test-unittest-34-pass.png`: full regression command and final `Ran 34 tests ... OK`.

## Operation demos

- `kadmin-web-dashboard.png`: KAdmin Web dashboard, principal list, status toggle, or audit log.
- `client-cli-kinit-klist-kvno-kaccess.png`: `kinit`, `klist`, `kvno`, and `kaccess` workflow.
- `service-protected-file-catalog.png`: terminal `kaccess` response after AP-REQ succeeds, showing `LIST_PROTECTED_FILES` and the allowed protected resources.
- `cache-reuse-second-run.png`: second client run with blank password, cached TGT/service ticket reused, AS/TGS skipped.

## Security-flow demo

Run:

```powershell
python scratch/demo_security_flows.py
```

Then capture the relevant scenario blocks:

- `security-normal-as-tgs.png`: Scenario 1, normal AS/TGS flow is `ALLOWED`.
- `security-wrong-password.png`: Scenario 2, wrong password returns `KDC_ERR_PREAUTH_FAILED`.
- `security-account-lockout.png`: Scenario 3, repeated bad pre-auth returns `KDC_ERR_CLIENT_REVOKED`.
- `security-tampered-tgt.png`: Scenario 4, tampered TGT returns `KRB_AP_ERR_MODIFIED`.
- `security-replay-tgs-authenticator.png`: Scenario 5, replayed TGS authenticator returns `KRB_AP_ERR_REPEAT`.
- `security-replay-ap-authenticator.png`: Scenario 6, replayed AP authenticator returns HTTP `403` and `KRB_AP_ERR_REPEAT`.
- `security-tampered-service-ticket.png`: Scenario 7, tampered service ticket returns HTTP `403` and `KRB_AP_ERR_MODIFIED`.
- `security-wrong-service-ap.png`: Scenario 8, wrong-service AP-REQ returns HTTP `403` and `KRB_AP_ERR_MODIFIED`.
- `security-key-rotation-kvno.png`: Scenario 9, old TGT remains `ALLOWED` after key rotation by `kvno`.

## Renewal and cross-realm

- `demo-tgt-renewal.png`: `python scratch/demo_tgt_renewal.py`, renewed TGT with old/new endtime and `ALLOWED`.
- `demo-cross-realm.png`: `python scratch/test_cross_realm.py`, cross-realm TGT/service ticket and mutual authentication success.
