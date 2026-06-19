"""Safe cross-realm smoke test for the Kerberos demo.

This script starts a temporary KDC and application server using runtime files
under a temp directory. It never deletes or rewrites the repository database,
keytab, or credential cache.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_tcp(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for {host}:{port}: {last_error}")


def _start_module(module: str, env: dict[str, str], log_path: Path) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [PYTHON, "-u", "-m", module],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    proc._codex_log_handle = log_handle  # type: ignore[attr-defined]
    return proc


def _stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    log_handle = getattr(proc, "_codex_log_handle", None)
    if log_handle is not None:
        log_handle.close()


def _tail(path: Path, lines: int = 60) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="krb-demo-smoke-") as temp_dir_raw:
        temp_dir = Path(temp_dir_raw)
        kdc_port = _free_port()
        app_port = _free_port()

        runtime = temp_dir / "runtime"
        db_path = runtime / "kdc" / "database.db"
        keytab_path = runtime / "app_server" / "fileserver.keytab"
        ccache_path = runtime / "client" / "krb5cc_demo"
        replay_path = runtime / "replay" / "replay.db"
        log_dir = temp_dir / "logs"

        env = os.environ.copy()
        env.update(
            {
                "KDC_HOST": "127.0.0.1",
                "KDC_PORT": str(kdc_port),
                "APP_SERVER_HOST": "127.0.0.1",
                "APP_SERVER_PORT": str(app_port),
                "KDC_DB_PATH": str(db_path),
                "APP_SERVER_KEYTAB": str(keytab_path),
                "KRB5CCNAME": str(ccache_path),
                "KRB_REPLAY_CACHE": str(replay_path),
                "PYTHONPATH": str(PROJECT_ROOT),
            }
        )

        print(f"[Smoke] Project root: {PROJECT_ROOT}")
        print(f"[Smoke] Temp runtime: {runtime}")
        print(f"[Smoke] KDC port: {kdc_port}")
        print(f"[Smoke] App port: {app_port}")

        kdc_log = log_dir / "kdc.log"
        app_log = log_dir / "app_server.log"
        kdc_proc = _start_module("kdc.kdc_server", env, kdc_log)
        app_proc = None

        try:
            _wait_for_tcp("127.0.0.1", kdc_port)
            app_proc = _start_module("app_server.service_server", env, app_log)
            _wait_for_tcp("127.0.0.1", app_port)

            os.environ.update(env)
            sys.path.insert(0, str(PROJECT_ROOT))

            import client.client_app as client_app

            cases = [
                (
                    "charlie@PARTNER.LOCAL",
                    "charlie_password",
                    "fileserver/localhost@PARTNER.LOCAL",
                ),
                (
                    "alice@DEMO.LOCAL",
                    "alice_password",
                    "fileserver/localhost@PARTNER.LOCAL",
                ),
            ]

            for principal, password, service in cases:
                print(f"[Smoke] AS/TGS/AP for {principal} -> {service}")
                client_app.client_principal_global = principal
                client_app.cache.clear()
                assert client_app.phase1_as_exchange(principal, password)
                assert client_app.phase2_tgs_exchange(service)
                assert client_app.phase3_ap_exchange(service)

            print("[Smoke] SUCCESS: cross-realm smoke test passed.")
            return 0

        except Exception as exc:
            print(f"[Smoke] FAILURE: {exc}")
            print("\n[KDC log tail]\n" + _tail(kdc_log))
            print("\n[App Server log tail]\n" + _tail(app_log))
            return 1

        finally:
            if app_proc is not None:
                _stop_process(app_proc)
            _stop_process(kdc_proc)


if __name__ == "__main__":
    raise SystemExit(main())
