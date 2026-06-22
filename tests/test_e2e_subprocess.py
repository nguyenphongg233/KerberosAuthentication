"""End-to-end subprocess smoke test for local AS/TGS/AP flow."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
        [sys.executable, "-u", "-m", module],
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


def _tail(path: Path, lines: int = 80) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


class E2ESubprocessTests(unittest.TestCase):
    def test_cli_client_wrong_password_fails_at_as_exchange(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="krb-e2e-negative-",
            ignore_cleanup_errors=True,
        ) as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            runtime = temp_dir / "runtime"
            log_dir = temp_dir / "logs"
            kdc_port = _free_port()
            env = os.environ.copy()
            env.update(
                {
                    "KDC_HOST": "127.0.0.1",
                    "KDC_PORT": str(kdc_port),
                    "APP_SERVER_HOST": "127.0.0.1",
                    "APP_SERVER_PORT": str(_free_port()),
                    "KDC_DB_PATH": str(runtime / "kdc" / "database.db"),
                    "APP_SERVER_KEYTAB": str(runtime / "app" / "fileserver.keytab"),
                    "KRB5CCNAME": str(runtime / "client" / "krb5cc_demo"),
                    "KRB_REPLAY_CACHE": str(runtime / "replay" / "replay.db"),
                    "PYTHONPATH": str(PROJECT_ROOT),
                    "PYTHONIOENCODING": "utf-8",
                }
            )

            kdc_log = log_dir / "kdc.log"
            kdc_proc = _start_module("kdc.kdc_server", env, kdc_log)
            try:
                _wait_for_tcp("127.0.0.1", kdc_port)
                client = subprocess.run(
                    [sys.executable, "-u", "-m", "client.client_app"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    input="alice\nwrong_password\n",
                    text=True,
                    capture_output=True,
                    timeout=30,
                )

                combined = client.stdout + "\n" + client.stderr
                self.assertEqual(0, client.returncode, combined + "\n[KDC]\n" + _tail(kdc_log))
                self.assertIn("ERROR from KDC: Pre-authentication failed.", combined)
                self.assertIn("Authentication failed. Exiting.", combined)
                self.assertNotIn("TGS Exchange successful", combined)
            finally:
                _stop_process(kdc_proc)

    def test_cli_client_completes_as_tgs_ap_against_subprocess_servers(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="krb-e2e-test-",
            ignore_cleanup_errors=True,
        ) as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            runtime = temp_dir / "runtime"
            log_dir = temp_dir / "logs"
            kdc_port = _free_port()
            app_port = _free_port()
            env = os.environ.copy()
            env.update(
                {
                    "KDC_HOST": "127.0.0.1",
                    "KDC_PORT": str(kdc_port),
                    "APP_SERVER_HOST": "127.0.0.1",
                    "APP_SERVER_PORT": str(app_port),
                    "KDC_DB_PATH": str(runtime / "kdc" / "database.db"),
                    "APP_SERVER_KEYTAB": str(runtime / "app" / "fileserver.keytab"),
                    "KRB5CCNAME": str(runtime / "client" / "krb5cc_demo"),
                    "KRB_REPLAY_CACHE": str(runtime / "replay" / "replay.db"),
                    "PYTHONPATH": str(PROJECT_ROOT),
                    "PYTHONIOENCODING": "utf-8",
                }
            )

            kdc_log = log_dir / "kdc.log"
            app_log = log_dir / "app.log"
            kdc_proc = _start_module("kdc.kdc_server", env, kdc_log)
            app_proc = None
            try:
                _wait_for_tcp("127.0.0.1", kdc_port)
                app_proc = _start_module("app_server.service_server", env, app_log)
                _wait_for_tcp("127.0.0.1", app_port)

                client = subprocess.run(
                    [sys.executable, "-u", "-m", "client.client_app"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    input="alice\nalice_password\n",
                    text=True,
                    capture_output=True,
                    timeout=30,
                )

                combined = client.stdout + "\n" + client.stderr
                self.assertEqual(
                    0,
                    client.returncode,
                    combined + "\n[KDC]\n" + _tail(kdc_log) + "\n[APP]\n" + _tail(app_log),
                )
                self.assertIn("AS Exchange successful", combined)
                self.assertIn("TGS Exchange successful", combined)
                self.assertIn("Mutual authentication verified", combined)
                self.assertIn("authorized_action: LIST_PROTECTED_FILES", combined)
                self.assertIn("Full Kerberos authentication completed successfully", combined)

                cached_client = subprocess.run(
                    [sys.executable, "-u", "-m", "client.client_app"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    input="alice\n\n",
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                cached_combined = cached_client.stdout + "\n" + cached_client.stderr
                self.assertEqual(
                    0,
                    cached_client.returncode,
                    cached_combined + "\n[KDC]\n" + _tail(kdc_log) + "\n[APP]\n" + _tail(app_log),
                )
                self.assertIn("Reusing cached TGT. Skipping AS Exchange.", cached_combined)
                self.assertIn("Found valid cached service ticket. Skipping TGS Exchange.", cached_combined)
                self.assertIn("Mutual authentication verified", cached_combined)
                self.assertIn("authorized_action: LIST_PROTECTED_FILES", cached_combined)
                self.assertIn("Full Kerberos authentication completed successfully", cached_combined)

                klist = subprocess.run(
                    [sys.executable, "-u", "-m", "client.klist"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                klist_combined = klist.stdout + "\n" + klist.stderr
                self.assertEqual(0, klist.returncode, klist_combined)
                self.assertIn("Credentials cache:", klist_combined)
                self.assertIn("krbtgt/DEMO.LOCAL@DEMO.LOCAL", klist_combined)
                self.assertIn("fileserver/localhost@DEMO.LOCAL", klist_combined)

                kaccess = subprocess.run(
                    [sys.executable, "-u", "-m", "client.kaccess", "fileserver"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                kaccess_combined = kaccess.stdout + "\n" + kaccess.stderr
                self.assertEqual(
                    0,
                    kaccess.returncode,
                    kaccess_combined + "\n[KDC]\n" + _tail(kdc_log) + "\n[APP]\n" + _tail(app_log),
                )
                self.assertIn("Mutual authentication verified", kaccess_combined)
                self.assertIn("authorized_action: LIST_PROTECTED_FILES", kaccess_combined)

                kdestroy = subprocess.run(
                    [sys.executable, "-u", "-m", "client.kdestroy"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(0, kdestroy.returncode, kdestroy.stdout + kdestroy.stderr)
                self.assertIn("Destroyed credential cache", kdestroy.stdout)

                kinit = subprocess.run(
                    [
                        sys.executable,
                        "-u",
                        "-m",
                        "client.kinit",
                        "alice",
                        "--password",
                        "alice_password",
                    ],
                    cwd=PROJECT_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                kinit_combined = kinit.stdout + "\n" + kinit.stderr
                self.assertEqual(0, kinit.returncode, kinit_combined + "\n[KDC]\n" + _tail(kdc_log))
                self.assertIn("AS Exchange successful", kinit_combined)

                kvno = subprocess.run(
                    [sys.executable, "-u", "-m", "client.kvno", "fileserver"],
                    cwd=PROJECT_ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                kvno_combined = kvno.stdout + "\n" + kvno.stderr
                self.assertEqual(0, kvno.returncode, kvno_combined + "\n[KDC]\n" + _tail(kdc_log))
                self.assertIn("fileserver/localhost@DEMO.LOCAL: kvno =", kvno_combined)
            finally:
                if app_proc is not None:
                    _stop_process(app_proc)
                _stop_process(kdc_proc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
