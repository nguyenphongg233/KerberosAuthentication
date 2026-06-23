"""KAdmin Web API tests."""

from __future__ import annotations

import json
import socket
import unittest

try:
    from tests.support import KerberosTestCase
except ModuleNotFoundError:
    from support import KerberosTestCase


class KAdminWebAPITests(KerberosTestCase):
    def _request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = [
            f"{method} {path} HTTP/1.1",
            "Host: localhost",
            "Connection: close",
        ]
        if payload is not None:
            headers.extend(
                [
                    "Content-Type: application/json",
                    f"Content-Length: {len(body)}",
                ]
            )
        request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
        raw = self._send_raw_kadmin_request(request_bytes)
        head, _sep, response_body = raw.partition(b"\r\n\r\n")
        status = int(head.decode("iso-8859-1").split()[1])
        data = json.loads(response_body.decode("utf-8")) if response_body else {}
        return status, data

    def _send_raw_kadmin_request(self, request_bytes: bytes) -> bytes:
        client_sock, server_sock = socket.socketpair()
        client_sock.settimeout(5)
        server_sock.settimeout(5)
        try:
            client_sock.sendall(request_bytes)
            client_sock.shutdown(socket.SHUT_WR)
            self.mods.kadmin_web.KAdminWebHandler(
                server_sock,
                ("127.0.0.1", 0),
                object(),
            )
            server_sock.close()
            chunks = []
            while True:
                try:
                    chunk = client_sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            client_sock.close()
            try:
                server_sock.close()
            except OSError:
                pass

    def test_add_list_toggle_and_delete_principal(self) -> None:
        self.init_database()
        principal = "webtest/localhost@DEMO.LOCAL"

        status, data = self._request(
            "POST",
            "/api/principals",
            {
                "principal_name": principal,
                "password": "webtest_secret",
                "type": "service",
                "groups": ["services"],
            },
        )
        self.assertEqual(201, status, data)
        self.assertEqual(principal, data["principal"])

        status, principals = self._request("GET", "/api/principals")
        self.assertEqual(200, status, principals)
        self.assertIn(principal, [row["principal_name"] for row in principals])

        status, toggle = self._request(
            "POST",
            "/api/principals/toggle",
            {"principal_name": principal},
        )
        self.assertEqual(200, status, toggle)
        self.assertEqual(1, toggle["disabled"])

        status, logs = self._request("GET", "/api/audit_logs?limit=20")
        self.assertEqual(200, status, logs)
        self.assertTrue(
            any(row["event"] == "principal_toggled" and row["principal"] == principal for row in logs),
            logs,
        )

        status, deleted = self._request(
            "POST",
            "/api/principals/delete",
            {"principal_name": principal},
        )
        self.assertEqual(200, status, deleted)

        status, principals_after = self._request("GET", "/api/principals")
        self.assertEqual(200, status, principals_after)
        self.assertNotIn(principal, [row["principal_name"] for row in principals_after])

    def test_statistics_use_current_as_tgs_audit_event_names(self) -> None:
        conn = self.init_database()
        self.issue_service_ticket(conn)
        self.mods.as_handler.handle_as_request(
            self.make_as_req("alice@DEMO.LOCAL", "wrong_password"),
            conn.cursor(),
        )
        conn.commit()

        status, data = self._request("GET", "/api/statistics")
        self.assertEqual(200, status, data)
        self.assertEqual(2, data["as_requests"])
        self.assertEqual(1, data["tgs_requests"])
        self.assertEqual(1, data["failed_requests"])
        self.assertAlmostEqual(2 / 3 * 100, data["success_rate"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
