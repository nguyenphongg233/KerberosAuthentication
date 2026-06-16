import os
import sys
import time
import subprocess
from pathlib import Path

PROJECT_ROOT = "d:/OneDrive-ntdxl/prj/KerberosAuthentication"
sys.path.insert(0, PROJECT_ROOT)

print(f"Project root: {PROJECT_ROOT}")

# 1. Clean up old databases and caches to ensure a fresh, consistent environment
db_path = os.path.join(PROJECT_ROOT, "kdc", "database.db")
keytab_path = os.path.join(PROJECT_ROOT, "app_server", "fileserver.keytab")
ccache_path = os.path.join(PROJECT_ROOT, "client", "krb5cc_demo")

for path in [db_path, keytab_path, ccache_path]:
    if os.path.exists(path):
        try:
            os.remove(path)
            print(f"[Test] Removed old file: {path}")
        except OSError as e:
            print(f"[Test] Warning: Could not remove {path}: {e}")

# 2. Start KDC, KAdmin Web, and File Server as subprocesses
print("[Test] Starting KDC, KAdmin Web, and Application Servers...")

kdc_proc = subprocess.Popen(
    [sys.executable, "-u", "-m", "kdc.kdc_server"],
    cwd=PROJECT_ROOT,
    text=True
)

kadmin_proc = subprocess.Popen(
    [sys.executable, "-u", "-m", "kdc.kadmin_web"],
    cwd=PROJECT_ROOT,
    text=True
)

srv_proc = subprocess.Popen(
    [sys.executable, "-u", "-m", "app_server.service_server"],
    cwd=PROJECT_ROOT,
    text=True
)

# Wait for servers to start and initialize database
time.sleep(4)

try:
    from client.client_app import (
        phase1_as_exchange,
        phase2_tgs_exchange,
        phase3_ap_exchange,
        cache
    )
    import client.client_app as client_app

    # -------------------------------------------------------------
    # TEST CASE 1: Charlie@PARTNER.LOCAL (Local Realm Access)
    # -------------------------------------------------------------
    print("\n=================== TEST CASE 1: CHARLIE (PARTNER.LOCAL LOCAL ACCESS) ===================")
    client_app.client_principal_global = "charlie@PARTNER.LOCAL"
    cache.clear()

    print("[Test] Running AS Exchange for Charlie...")
    as_ok = phase1_as_exchange("charlie@PARTNER.LOCAL", "charlie_password")
    assert as_ok == True, "Charlie AS Exchange failed!"

    print("[Test] Running TGS Exchange for Charlie (Local Partner Service)...")
    tgs_ok = phase2_tgs_exchange("fileserver/localhost@PARTNER.LOCAL")
    assert tgs_ok == True, "Charlie TGS Exchange failed!"

    print("[Test] Running AP Exchange for Charlie...")
    ap_ok = phase3_ap_exchange("fileserver/localhost@PARTNER.LOCAL")
    assert ap_ok == True, "Charlie AP Exchange failed!"

    # -------------------------------------------------------------
    # TEST CASE 2: Alice@DEMO.LOCAL (Cross-Realm Trust Access)
    # -------------------------------------------------------------
    print("\n=================== TEST CASE 2: ALICE (CROSS-REALM ACCESS TO PARTNER.LOCAL) ===================")
    client_app.client_principal_global = "alice@DEMO.LOCAL"
    cache.clear()

    print("[Test] Running AS Exchange for Alice...")
    as_ok = phase1_as_exchange("alice@DEMO.LOCAL", "alice_password")
    assert as_ok == True, "Alice AS Exchange failed!"

    print("[Test] Running Cross-Realm TGS Exchange for Alice (DEMO.LOCAL -> PARTNER.LOCAL)...")
    tgs_ok = phase2_tgs_exchange("fileserver/localhost@PARTNER.LOCAL")
    assert tgs_ok == True, "Alice Cross-Realm TGS Exchange failed!"

    print("[Test] Running AP Exchange for Alice (Cross-Realm service access)...")
    ap_ok = phase3_ap_exchange("fileserver/localhost@PARTNER.LOCAL")
    assert ap_ok == True, "Alice AP Exchange failed!"

    print("\n[Test] SUCCESS! All cross-realm and dynamic realm tests passed successfully.")

except Exception as e:
    print(f"\n[Test] FAILURE: {e}")
    import traceback
    traceback.print_exc()

finally:
    print("\n[Test] Terminating KDC, KAdmin, and Service processes...")
    kdc_proc.terminate()
    kadmin_proc.terminate()
    srv_proc.terminate()

    # Wait for termination
    kdc_proc.wait()
    kadmin_proc.wait()
    srv_proc.wait()
    print("[Test] Processes terminated.")
