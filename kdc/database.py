"""SQLite schema and repository helpers for the demo KDC."""

from __future__ import annotations

import json
import os
import sqlite3
import time

from core.crypto import ENCTYPE, DEFAULT_KDF_ITERATIONS, derive_key, key_to_str
from core.keytab import write_keytab
from core.messages import APP_SERVICE_NAME, APP_SERVICE_PRINCIPAL, REALM, TGS_PRINCIPAL
from core.principal import principal_aliases, principal_realm, principal_salt, user_principal


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.getenv("KDC_DB_PATH", os.path.join(os.path.dirname(__file__), "database.db"))
DEFAULT_KEYTAB_PATH = os.getenv(
    "APP_SERVER_KEYTAB",
    os.path.join(PROJECT_ROOT, "app_server", f"{APP_SERVICE_NAME}.keytab"),
)


DEFAULT_PRINCIPALS = [
    {
        "principal_name": user_principal("alice", REALM),
        "password": "alice_password",
        "principal_type": "user",
        "groups": '["users", "admins"]',
    },
    {
        "principal_name": user_principal("bob", REALM),
        "password": "bob_password",
        "principal_type": "user",
        "groups": '["users"]',
    },
    {
        "principal_name": TGS_PRINCIPAL,
        "password": "tgs_secret",
        "principal_type": "tgs",
        "groups": '[]',
    },
    {
        "principal_name": APP_SERVICE_PRINCIPAL,
        "password": "fileserver_secret",
        "principal_type": "service",
        "keytab_path": DEFAULT_KEYTAB_PATH,
        "groups": '[]',
    },
    # Cross-Realm / Partner Realm Principals
    {
        "principal_name": "charlie@PARTNER.LOCAL",
        "password": "charlie_password",
        "principal_type": "user",
        "groups": '["users"]',
    },
    {
        "principal_name": "fileserver/localhost@PARTNER.LOCAL",
        "password": "partner_fileserver_secret",
        "principal_type": "service",
        "keytab_path": DEFAULT_KEYTAB_PATH,
        "groups": '[]',
    },
    {
        "principal_name": "krbtgt/PARTNER.LOCAL@DEMO.LOCAL",
        "password": "cross_realm_secret_123",
        "principal_type": "tgs",
        "groups": '[]',
    },
    {
        "principal_name": "krbtgt/PARTNER.LOCAL@PARTNER.LOCAL",
        "password": "partner_tgs_secret",
        "principal_type": "tgs",
        "groups": '[]',
    },
]


def connect() -> sqlite3.Connection:
    """Open a KDC database connection."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_database() -> list[str]:
    """Create/migrate the demo database and upsert default principals."""
    conn = connect()
    try:
        ensure_schema(conn)
        registered = []
        for spec in DEFAULT_PRINCIPALS:
            record = upsert_principal(
                conn,
                spec["principal_name"],
                spec["password"],
                spec["principal_type"],
                groups=spec.get("groups", "[]"),
            )
            registered.append(record["principal_name"])

            if spec.get("principal_type") == "service":
                write_keytab(
                    spec["keytab_path"],
                    record["principal_name"],
                    record["key"],
                    record["kvno"],
                    record["enctype"],
                    record["realm"],
                )

        audit_event(conn, "KDC", "database_initialized", None, "success",
                    {"registered_principals": registered})
        conn.commit()
        return registered
    finally:
        conn.close()


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables and add missing columns for older demo databases."""
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS principals (principal_name TEXT PRIMARY KEY)")
    _add_column_if_missing(cursor, "principals", "secret_key", "TEXT")
    _add_column_if_missing(cursor, "principals", "principal_type", "TEXT DEFAULT 'unknown'")
    _add_column_if_missing(cursor, "principals", "realm", "TEXT DEFAULT ''")
    _add_column_if_missing(cursor, "principals", "salt", "TEXT DEFAULT ''")
    _add_column_if_missing(cursor, "principals", "key", "TEXT DEFAULT ''")
    _add_column_if_missing(cursor, "principals", "kvno", "INTEGER DEFAULT 1")
    _add_column_if_missing(cursor, "principals", "enctype", "TEXT DEFAULT ''")
    _add_column_if_missing(cursor, "principals", "kdf", "TEXT DEFAULT 'pbkdf2-hmac-sha1'")
    _add_column_if_missing(cursor, "principals", "iterations", f"INTEGER DEFAULT {DEFAULT_KDF_ITERATIONS}")
    _add_column_if_missing(cursor, "principals", "created_at", "REAL DEFAULT 0")
    _add_column_if_missing(cursor, "principals", "updated_at", "REAL DEFAULT 0")
    _add_column_if_missing(cursor, "principals", "disabled", "INTEGER DEFAULT 0")
    _add_column_if_missing(cursor, "principals", "groups", "TEXT DEFAULT '[]'")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS principal_aliases (
            alias TEXT PRIMARY KEY,
            principal_name TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            component TEXT NOT NULL,
            event TEXT NOT NULL,
            principal TEXT,
            peer TEXT,
            outcome TEXT NOT NULL,
            detail TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS replay_cache (
            cache_name TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            client_principal TEXT NOT NULL,
            server_principal TEXT NOT NULL,
            auth_time REAL NOT NULL,
            seen_at REAL NOT NULL,
            PRIMARY KEY (cache_name, cache_key)
        )
        """
    )
    conn.commit()


def _add_column_if_missing(cursor: sqlite3.Cursor, table: str, column: str,
                           definition: str) -> None:
    columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def upsert_principal(conn: sqlite3.Connection, principal_name: str, password: str,
                     principal_type: str, kvno: int = 1, groups: str = "[]") -> dict:
    """Insert or update a principal with a deterministic Kerberos-like salt."""
    now = time.time()
    realm = principal_realm(principal_name, REALM)
    salt = principal_salt(principal_name, realm)
    key = key_to_str(derive_key(password, salt=salt))

    existing = get_principal(conn.cursor(), principal_name, resolve_alias=False)
    created_at = existing["created_at"] if existing else now

    conn.execute(
        """
        INSERT INTO principals (
            principal_name, secret_key, principal_type, realm, salt, key, kvno,
            enctype, kdf, iterations, created_at, updated_at, disabled, groups
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        ON CONFLICT(principal_name) DO UPDATE SET
            secret_key=excluded.secret_key,
            principal_type=excluded.principal_type,
            realm=excluded.realm,
            salt=excluded.salt,
            key=excluded.key,
            kvno=excluded.kvno,
            enctype=excluded.enctype,
            kdf=excluded.kdf,
            iterations=excluded.iterations,
            updated_at=excluded.updated_at,
            disabled=0,
            groups=excluded.groups
        """,
        (
            principal_name,
            key,
            principal_type,
            realm,
            salt,
            key,
            kvno,
            ENCTYPE,
            "pbkdf2-hmac-sha1",
            DEFAULT_KDF_ITERATIONS,
            created_at,
            now,
            groups,
        ),
    )

    for alias in principal_aliases(principal_name):
        conn.execute(
            """
            INSERT INTO principal_aliases (alias, principal_name)
            VALUES (?, ?)
            ON CONFLICT(alias) DO UPDATE SET principal_name=excluded.principal_name
            """,
            (alias, principal_name),
        )

    record = get_principal(conn.cursor(), principal_name, resolve_alias=False)
    audit_event(conn, "KDC", "principal_upserted", principal_name, "success",
                {"principal_type": principal_type, "kvno": kvno})
    return record


def resolve_principal(cursor: sqlite3.Cursor, name: str) -> str | None:
    """Resolve a canonical principal name or a short alias."""
    row = cursor.execute(
        "SELECT principal_name FROM principals WHERE principal_name = ?",
        (name,),
    ).fetchone()
    if row:
        return row[0]

    alias_row = cursor.execute(
        "SELECT principal_name FROM principal_aliases WHERE alias = ?",
        (name,),
    ).fetchone()
    if alias_row:
        return alias_row[0]

    return None


def get_principal(cursor: sqlite3.Cursor, name: str,
                  resolve_alias: bool = True) -> dict | None:
    """Return a principal record as a dictionary."""
    principal_name = resolve_principal(cursor, name) if resolve_alias else name
    if not principal_name:
        return None

    cursor.execute(
        """
        SELECT principal_name, principal_type, realm, salt, key, kvno, enctype,
               kdf, iterations, created_at, updated_at, disabled, groups
        FROM principals
        WHERE principal_name = ?
        """,
        (principal_name,),
    )
    row = cursor.fetchone()
    if row is None:
        return None

    columns = [
        "principal_name", "principal_type", "realm", "salt", "key", "kvno",
        "enctype", "kdf", "iterations", "created_at", "updated_at", "disabled",
        "groups",
    ]
    record = dict(zip(columns, row))
    if record["disabled"]:
        return None
    return record


def audit_event(conn_or_cursor, component: str, event: str, principal: str | None,
                outcome: str, detail: dict | str | None = None,
                peer: str | None = None) -> None:
    """Append an audit event. Accepts either a connection or cursor."""
    if isinstance(detail, dict):
        detail_text = json.dumps(detail, sort_keys=True)
    else:
        detail_text = detail

    executor = conn_or_cursor
    executor.execute(
        """
        INSERT INTO audit_log (
            timestamp, component, event, principal, peer, outcome, detail
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (time.time(), component, event, principal, peer, outcome, detail_text),
    )
