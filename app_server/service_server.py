"""
service_server.py - Application Server (File Server mock).

Handles the Kerberos AP Exchange over an HTTP Negotiate-style flow:
    GET / -> 401 Unauthorized + WWW-Authenticate: Negotiate
    GET / + Authorization: Negotiate <AP-REQ b64> -> 200 OK + WWW-Authenticate: Negotiate <AP-REP b64>

This demo sends raw Kerberos AP-REQ/AP-REP DER tokens in the Negotiate
headers. It does not implement the full GSS-API/SPNEGO token wrapping.
"""

import os
import sys
import time
import base64
from html import escape
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from core.crypto import (
    decrypt,
    encrypt,
    str_to_key,
    InvalidToken,
    KEY_USAGE_TICKET,
    KEY_USAGE_AP_REQ_AUTH,
    KEY_USAGE_AP_REP_ENCPART,
    DEFAULT_ENCTYPE,
)
from core.asn1_codec import (
    decode_enc_ticket_part,
    decode_authenticator,
    encode_enc_ap_rep_part,
    decode_message,
    encode_message,
)
from core.keytab import load_keytab
from core.messages import (
    AP_REP,
    AP_REQ,
    APP_SERVER_BIND_HOST,
    APP_SERVER_HOST,
    APP_SERVER_PORT,
    APP_SERVICE_PRINCIPAL,
    ERROR,
    KRB_AP_ERR_MODIFIED,
    KRB_AP_ERR_REPEAT,
    KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED,
    KRB_AP_ERR_TKT_NYV,
    MAX_CLOCK_SKEW,
    REALM,
)
from core.replay_cache import authenticator_cache_key, check_and_store
from kdc.database import DEFAULT_KEYTAB_PATH

SERVICE_PRINCIPAL = APP_SERVICE_PRINCIPAL
KEYTAB_PATH = os.getenv("APP_SERVER_KEYTAB", DEFAULT_KEYTAB_PATH)
SERVICE_KEY = None

PROTECTED_FILES = [
    {
        "name": "project-overview.txt",
        "title": "Kerberos demo project overview",
        "required_group": "users",
        "summary": "Read the protected service introduction.",
    },
    {
        "name": "team-handbook.txt",
        "title": "Internal team handbook",
        "required_group": "users",
        "summary": "Read shared user documentation.",
    },
    {
        "name": "kdc-audit-log.txt",
        "title": "KDC audit log snapshot",
        "required_group": "admins",
        "summary": "Review authentication and administration events.",
    },
    {
        "name": "keytab-rotation-plan.txt",
        "title": "Service key rotation plan",
        "required_group": "admins",
        "summary": "Review kvno/keytab rotation guidance.",
    },
]


def _visible_files(groups: list[str]) -> list[dict]:
    group_set = set(groups)
    return [
        item
        for item in PROTECTED_FILES
        if item["required_group"] in group_set
    ]


def _build_service_data(client_principal: str, requested_service_princ: str,
                        client_groups: list[str], visible_files: list[dict],
                        is_admin: bool) -> str:
    access_level = "admin" if is_admin else "standard-user"
    groups_text = ", ".join(client_groups) if client_groups else "(none)"
    lines = [
        "Protected File Server access granted",
        f"client_principal: {client_principal}",
        f"service_principal: {requested_service_princ}",
        f"groups: {groups_text}",
        f"access_level: {access_level}",
        "authorized_action: LIST_PROTECTED_FILES",
        "available_resources:",
    ]
    for item in visible_files:
        lines.append(
            f"- {item['name']} [{item['required_group']}] - {item['summary']}"
        )
    if not is_admin:
        lines.append("admin_resources: hidden (requires admins group)")
    lines.append("result: service data returned only after a valid AP-REQ")
    return "\n".join(lines)


def _render_file_catalog_html(client_principal: str, requested_service_princ: str,
                              client_groups: list[str], visible_files: list[dict],
                              is_admin: bool, access_time: str,
                              service_data: str) -> str:
    rows = "\n".join(
        "<tr>"
        f"<td>{escape(item['name'])}</td>"
        f"<td>{escape(item['title'])}</td>"
        f"<td>{escape(item['required_group'])}</td>"
        f"<td>{escape(item['summary'])}</td>"
        "</tr>"
        for item in visible_files
    )
    if not rows:
        rows = (
            "<tr><td colspan=\"4\">No files are visible for this ticket's "
            "authorization groups.</td></tr>"
        )

    groups_text = ", ".join(client_groups) if client_groups else "(none)"
    access_label = "Administrator" if is_admin else "Standard User"
    admin_note = (
        "Admin-only files are visible because the service ticket carries the "
        "admins group."
        if is_admin
        else "Admin-only files are hidden because this ticket does not carry "
             "the admins group."
    )

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Kerberos File Server</title>
    <style>
        body {{
            font-family: "Segoe UI", Arial, sans-serif;
            background: #f4f6f8;
            color: #1f2937;
            margin: 0;
            padding: 32px;
        }}
        .shell {{
            max-width: 980px;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #d9e0e8;
            border-radius: 8px;
            box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
            overflow: hidden;
        }}
        .header {{
            padding: 24px 28px;
            background: #0f766e;
            color: #ffffff;
        }}
        .header h1 {{
            margin: 0 0 6px;
            font-size: 24px;
            letter-spacing: 0;
        }}
        .header p {{
            margin: 0;
            color: #ccfbf1;
        }}
        .content {{
            padding: 24px 28px 28px;
        }}
        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 12px;
            margin-bottom: 22px;
        }}
        .meta div {{
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 12px;
            background: #f8fafc;
        }}
        .label {{
            display: block;
            color: #64748b;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0 18px;
        }}
        th, td {{
            border-bottom: 1px solid #e5e7eb;
            text-align: left;
            padding: 11px 10px;
            vertical-align: top;
        }}
        th {{
            background: #f8fafc;
            color: #475569;
            font-size: 13px;
            text-transform: uppercase;
        }}
        .note {{
            border-left: 4px solid #0f766e;
            background: #ecfdf5;
            padding: 12px 14px;
            margin-bottom: 18px;
        }}
        pre {{
            white-space: pre-wrap;
            background: #111827;
            color: #e5e7eb;
            border-radius: 6px;
            padding: 14px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="shell">
        <div class="header">
            <h1>Kerberos Protected File Server</h1>
            <p>HTTP 200 returned after a valid AP-REQ and mutual AP-REP verification.</p>
        </div>
        <div class="content">
            <div class="meta">
                <div><span class="label">Client</span>{escape(client_principal)}</div>
                <div><span class="label">Service</span>{escape(requested_service_princ)}</div>
                <div><span class="label">Groups</span>{escape(groups_text)}</div>
                <div><span class="label">Access level</span>{escape(access_label)}</div>
            </div>
            <div class="note">{escape(admin_note)} Access granted at {escape(access_time)}.</div>
            <h2>Protected File Catalog</h2>
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Resource</th>
                        <th>Required group</th>
                        <th>Allowed action</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            <h2>Service response payload</h2>
            <pre>{escape(service_data)}</pre>
        </div>
    </div>
</body>
</html>"""


def _ticket_expired(ticket: dict, now: float) -> bool:
    try:
        return now > float(ticket.get("endtime", 0))
    except (TypeError, ValueError):
        return True


def _ticket_not_yet_valid(ticket: dict, now: float) -> bool:
    try:
        starttime = float(ticket.get("starttime") or 0)
    except (TypeError, ValueError):
        return False
    return bool(starttime) and (now + MAX_CLOCK_SKEW) < starttime


def _error(code: str, message: str) -> dict:
    return {
        "msg_type": ERROR,
        "error_code": code,
        "error_message": message,
    }


class NegotiateRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for the demo's Negotiate-style Kerberos authentication."""

    def log_message(self, format, *args):
        sys.stdout.write(f"[FileServer] HTTP {self.address_string()} - - [{self.log_date_time_string()}] {format % args}\n")

    def do_GET(self):
        auth_header = self.headers.get("Authorization")

        # Phase 3a: Client requests resource without auth header -> challenge with Negotiate
        if not auth_header or not auth_header.startswith("Negotiate "):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Negotiate")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>401 Unauthorized</h1><p>Negotiate authentication required.</p></body></html>")
            return

        # Phase 3b: Client sends AP-REQ encoded in base64
        token_b64 = auth_header[len("Negotiate "):].strip()
        try:
            token_bytes = base64.b64decode(token_b64)
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>400 Bad Request</h1><p>Invalid Base64 token: {e}</p></body></html>".encode("utf-8"))
            return

        try:
            request = decode_message(token_bytes)
        except Exception as e:
            print(f"[FileServer] ERROR: Failed to decode AP-REQ DER: {e}")
            err_msg = _error(KRB_AP_ERR_MODIFIED, f"Failed to decode DER AP-REQ: {e}")
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: decoding error.</p></body></html>")
            return

        if request.get("msg_type") != AP_REQ:
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                f"Expected AP_REQ, got: {request.get('msg_type')}",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: invalid message type.</p></body></html>")
            return

        encrypted_service_ticket = request.get("service_ticket")
        encrypted_authenticator = request.get("authenticator")
        
        ticket_enctype = request.get("ticket_enctype", DEFAULT_ENCTYPE)
        ticket_kvno = request.get("ticket_kvno")

        if not encrypted_service_ticket or not encrypted_authenticator:
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "AP_REQ missing ticket or authenticator.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: missing ticket/authenticator.</p></body></html>")
            return

        requested_service_princ = request.get("service_principal")
        try:
            keytab_entry = load_keytab(
                KEYTAB_PATH,
                requested_service_princ,
                kvno=ticket_kvno,
                enctype=ticket_enctype,
            )
            current_service_key = str_to_key(keytab_entry["key"])
        except Exception as e:
            print(f"[FileServer] ERROR: Failed to load key from keytab for principal '{requested_service_princ}': {e}")
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                f"Service key not found in keytab for principal '{requested_service_princ}'."
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: Service key not found.</p></body></html>")
            return

        try:
            # Decrypt Service Ticket using KEY_USAGE_TICKET (2)
            st_der = decrypt(encrypted_service_ticket, current_service_key, KEY_USAGE_TICKET)
            service_ticket = decode_enc_ticket_part(st_der)
        except InvalidToken:
            print("[FileServer] ERROR: Failed to decrypt service ticket.")
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "Service ticket decryption failed.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: ticket decryption failed.</p></body></html>")
            return

        client_principal = service_ticket.get("client_principal")
        session_key_bytes = service_ticket["key"]["keyvalue"]
        
        if not client_principal or not session_key_bytes:
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "Malformed service ticket.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: malformed ticket.</p></body></html>")
            return

        client_realm = str(service_ticket.get("realm", REALM)).upper()
        ALLOWED_REALMS = ["DEMO.LOCAL", "PARTNER.LOCAL"]
        if client_realm not in ALLOWED_REALMS:
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "Client realm is not trusted.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: realm mismatch.</p></body></html>")
            return

        now = time.time()
        if _ticket_not_yet_valid(service_ticket, now):
            print("[FileServer] ERROR: Service ticket is not yet valid.")
            err_msg = _error(
                KRB_AP_ERR_TKT_NYV,
                "Service ticket is not yet valid.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: ticket not yet valid.</p></body></html>")
            return

        if _ticket_expired(service_ticket, now):
            print("[FileServer] ERROR: Service ticket has expired.")
            err_msg = _error(
                KRB_AP_ERR_TKT_EXPIRED,
                "Service ticket has expired.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: ticket expired.</p></body></html>")
            return

        try:
            # Decrypt Authenticator using service session key and KEY_USAGE_AP_REQ_AUTH (11)
            auth_der = decrypt(encrypted_authenticator, session_key_bytes, KEY_USAGE_AP_REQ_AUTH)
            authenticator = decode_authenticator(auth_der)
        except InvalidToken:
            print("[FileServer] ERROR: Failed to decrypt authenticator.")
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "Authenticator decryption failed.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: authenticator decryption failed.</p></body></html>")
            return

        if authenticator.get("client_principal") != client_principal:
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "Authenticator principal mismatch.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: principal mismatch.</p></body></html>")
            return

        auth_timestamp = authenticator.get("ctime")
        if auth_timestamp is None:
            err_msg = _error(
                KRB_AP_ERR_MODIFIED,
                "Invalid authenticator timestamp.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: invalid timestamp.</p></body></html>")
            return

        if abs(now - auth_timestamp) > MAX_CLOCK_SKEW:
            print("[FileServer] ERROR: Clock skew too great.")
            err_msg = _error(
                KRB_AP_ERR_SKEW,
                "Clock skew too great.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: clock skew too great.</p></body></html>")
            return

        cache_key = authenticator_cache_key(
            client_principal,
            SERVICE_PRINCIPAL,
            auth_timestamp,
            authenticator.get("cusec"),
        )
        if check_and_store("AP", cache_key, client_principal, SERVICE_PRINCIPAL,
                           auth_timestamp, now, MAX_CLOCK_SKEW):
            print("[FileServer] ERROR: Replayed authenticator detected.")
            err_msg = _error(
                KRB_AP_ERR_REPEAT,
                "Replayed authenticator detected.",
            )
            err_der = encode_message(err_msg)
            err_b64 = base64.b64encode(err_der).decode("utf-8")
            self.send_response(403)
            self.send_header("WWW-Authenticate", f"Negotiate {err_b64}")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>403 Forbidden</h1><p>Authentication failed: replay detected.</p></body></html>")
            return

        print(f"[FileServer] ✓ Client '{client_principal}' authenticated successfully!")

        # Extract client groups from ticket's authorization data
        auth_data = service_ticket.get("authorization_data", [])
        client_groups = []
        import json
        for entry in auth_data:
            if entry["ad_type"] == 100:
                try:
                    client_groups = json.loads(entry["ad_data"].decode("utf-8"))
                except Exception:
                    pass

        # Perform access control based on groups and build protected service data.
        is_admin = "admins" in client_groups
        visible_files = _visible_files(client_groups)
        access_time = time.strftime("%Y-%m-%d %H:%M:%S")
        service_data = _build_service_data(
            client_principal,
            requested_service_princ,
            client_groups,
            visible_files,
            is_admin,
        )

        # Handle subkey and sequence number handshake
        client_subkey = authenticator.get("subkey")
        client_seq = authenticator.get("seq_number")

        import secrets
        server_seq = secrets.randbits(30)
        server_subkey = {"keytype": ticket_enctype, "keyvalue": secrets.token_bytes(32)}

        print(f"[FileServer] Handshake Negotiation Details:")
        if client_subkey:
            print(f"             Client Subkey: {client_subkey['keyvalue'].hex()[:12]}...")
        else:
            print("             Client Subkey: None")
        if client_seq is not None:
            print(f"             Client Seq:    {client_seq}")
        else:
            print("             Client Seq:    None")
        print(f"             Server Subkey: {server_subkey['keyvalue'].hex()[:12]}...")
        print(f"             Server Seq:    {server_seq}")

        # 1. Build standard EncAPRepPart (contains ctime and cusec from authenticator, server subkey/seq_number)
        ap_rep_plaintext = {
            "ctime": authenticator["ctime"],
            "cusec": authenticator["cusec"],
            "service_principal": requested_service_princ,
            "subkey": server_subkey,
            "seq_number": server_seq,
        }
        
        ap_rep_der = encode_enc_ap_rep_part(ap_rep_plaintext)
        # Encrypt using the client subkey if present in authenticator, otherwise ticket session key
        encryption_key = client_subkey["keyvalue"] if client_subkey else session_key_bytes
        encrypted_ap_rep = encrypt(ap_rep_der, encryption_key, KEY_USAGE_AP_REP_ENCPART)

        # 2. Build the AP_REP message dictionary
        ap_rep_msg = {
            "msg_type": AP_REP,
            "service_principal": requested_service_princ,
            "encrypted_data": encrypted_ap_rep,
            "enctype": ticket_enctype,
        }
        
        ap_rep_bytes = encode_message(ap_rep_msg)
        ap_rep_b64 = base64.b64encode(ap_rep_bytes).decode("utf-8")

        # 3. Send successful response
        self.send_response(200)
        self.send_header("WWW-Authenticate", f"Negotiate {ap_rep_b64}")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        
        html_body = _render_file_catalog_html(
            client_principal,
            requested_service_princ,
            client_groups,
            visible_files,
            is_admin,
            access_time,
            service_data,
        )
        self.wfile.write(html_body.encode("utf-8"))
        print("[FileServer] AP_REP sent via HTTP Negotiate. Mutual authentication complete.")


def start_service_server():
    """Start the Application Server."""
    if not os.path.exists(KEYTAB_PATH):
        print(f"[FileServer] WARNING: Keytab file not found at '{KEYTAB_PATH}'. "
              f"It will be loaded dynamically when requests arrive.")

    server_address = (APP_SERVER_BIND_HOST, APP_SERVER_PORT)
    httpd = HTTPServer(server_address, NegotiateRequestHandler)

    print(f"\n{'='*60}")
    print("  Kerberos HTTP Application Server (File Server)")
    print(f"  Listening on http://{APP_SERVER_BIND_HOST}:{APP_SERVER_PORT}/")
    if APP_SERVER_BIND_HOST != APP_SERVER_HOST:
        print(f"  Client target: http://{APP_SERVER_HOST}:{APP_SERVER_PORT}/")
    print(f"  Keytab:    {KEYTAB_PATH}")
    print(f"{'='*60}")
    print("[FileServer] Waiting for HTTP requests...\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[FileServer] Server shutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    start_service_server()
