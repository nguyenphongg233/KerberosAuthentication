"""SQLite schema and repository helpers for the demo KDC."""

from __future__ import annotations

import json
import os
import sqlite3
import time

from core.crypto import (
    ENCTYPE,
    ENCTYPE_TO_NAME,
    DEFAULT_KDF_ITERATIONS,
    derive_key,
    key_to_str,
)
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
    """Create/migrate the demo database and register missing default principals."""
    conn = connect()
    try:
        ensure_schema(conn)
        registered = []
        for spec in DEFAULT_PRINCIPALS:
            existing = get_principal(
                conn.cursor(),
                spec["principal_name"],
                resolve_alias=False,
            )
            if existing:
                record = existing
            else:
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
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS principal_keys (
            principal_name TEXT NOT NULL,
            kvno INTEGER NOT NULL,
            enctype TEXT NOT NULL,
            key TEXT NOT NULL,
            salt TEXT DEFAULT '',
            kdf TEXT DEFAULT 'pbkdf2-hmac-sha1',
            iterations INTEGER DEFAULT 0,
            created_at REAL DEFAULT 0,
            retired_at REAL,
            PRIMARY KEY (principal_name, kvno, enctype)
        )
        """
    )
    _backfill_principal_keys(cursor)
    conn.commit()


def _add_column_if_missing(cursor: sqlite3.Cursor, table: str, column: str,
                           definition: str) -> None:
    columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _backfill_principal_keys(cursor: sqlite3.Cursor) -> None:
    """Populate key history from legacy databases that only had current keys."""
    cursor.execute(
        """
        INSERT OR IGNORE INTO principal_keys (
            principal_name, kvno, enctype, key, salt, kdf, iterations,
            created_at, retired_at
        )
        SELECT principal_name, kvno, enctype, key, salt, kdf, iterations,
               CASE WHEN created_at IS NULL OR created_at = 0
                    THEN strftime('%s', 'now')
                    ELSE created_at
               END,
               NULL
        FROM principals
        WHERE key IS NOT NULL
          AND key != ''
          AND kvno IS NOT NULL
          AND enctype IS NOT NULL
          AND enctype != ''
        """
    )


def upsert_principal(conn: sqlite3.Connection, principal_name: str, password: str,
                     principal_type: str, kvno: int = 1, groups: str = "[]") -> dict:
    """Insert or update a principal with a deterministic Kerberos-like salt."""
    now = time.time()
    realm = principal_realm(principal_name, REALM)
    salt = principal_salt(principal_name, realm)
    key = key_to_str(derive_key(password, salt=salt))

    existing = get_principal(conn.cursor(), principal_name, resolve_alias=False)
    created_at = existing["created_at"] if existing else now
    if existing and existing.get("key"):
        _store_principal_key(conn, existing)

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
    if existing and int(existing["kvno"]) != int(record["kvno"]):
        conn.execute(
            """
            UPDATE principal_keys
            SET retired_at = COALESCE(retired_at, ?)
            WHERE principal_name = ? AND kvno = ? AND enctype = ?
            """,
            (
                now,
                existing["principal_name"],
                int(existing["kvno"]),
                existing["enctype"],
            ),
        )
    _store_principal_key(conn, record)
    audit_event(conn, "KDC", "principal_upserted", principal_name, "success",
                {"principal_type": principal_type, "kvno": kvno})
    return record


def _store_principal_key(conn_or_cursor, record: dict) -> None:
    """Persist one principal key version in the key history table."""
    conn_or_cursor.execute(
        """
        INSERT INTO principal_keys (
            principal_name, kvno, enctype, key, salt, kdf, iterations,
            created_at, retired_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(principal_name, kvno, enctype) DO UPDATE SET
            key=excluded.key,
            salt=excluded.salt,
            kdf=excluded.kdf,
            iterations=excluded.iterations,
            created_at=excluded.created_at,
            retired_at=NULL
        """,
        (
            record["principal_name"],
            int(record["kvno"]),
            record["enctype"],
            record["key"],
            record.get("salt", ""),
            record.get("kdf", "pbkdf2-hmac-sha1"),
            int(record.get("iterations") or DEFAULT_KDF_ITERATIONS),
            float(record.get("updated_at") or record.get("created_at") or time.time()),
        ),
    )


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


def get_principal_key(cursor: sqlite3.Cursor, name: str,
                      kvno: int | None = None,
                      enctype: str | int | None = None,
                      resolve_alias: bool = True) -> dict | None:
    """Return a principal key version.

    Without ``kvno`` this returns the current principal record. With ``kvno``
    it can return an older key from ``principal_keys`` so tickets issued before
    key rotation remain decryptable until they expire.
    """
    current = get_principal(cursor, name, resolve_alias=resolve_alias)
    if current is None:
        return None
    if kvno is None:
        return current

    requested_enctype = _normalize_enctype(enctype) if enctype is not None else None
    params: list = [current["principal_name"], int(kvno)]
    where = "principal_name = ? AND kvno = ?"
    if requested_enctype:
        where += " AND enctype = ?"
        params.append(requested_enctype)

    row = cursor.execute(
        f"""
        SELECT principal_name, kvno, enctype, key, salt, kdf, iterations,
               created_at, retired_at
        FROM principal_keys
        WHERE {where}
        ORDER BY retired_at IS NULL DESC, created_at DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    if row is None:
        if int(current["kvno"]) == int(kvno):
            if requested_enctype is None or current["enctype"] == requested_enctype:
                return current
        return None

    columns = [
        "principal_name", "kvno", "enctype", "key", "salt", "kdf",
        "iterations", "created_at", "retired_at",
    ]
    key_record = dict(zip(columns, row))
    result = dict(current)
    result.update(key_record)
    return result


def list_principal_keys(cursor: sqlite3.Cursor, name: str,
                        resolve_alias: bool = True) -> list[dict]:
    """Return all stored key versions for a principal, newest first."""
    current = get_principal(cursor, name, resolve_alias=resolve_alias)
    if current is None:
        return []

    rows = cursor.execute(
        """
        SELECT principal_name, kvno, enctype, key, salt, kdf, iterations,
               created_at, retired_at
        FROM principal_keys
        WHERE principal_name = ?
        ORDER BY kvno DESC, created_at DESC
        """,
        (current["principal_name"],),
    ).fetchall()
    columns = [
        "principal_name", "kvno", "enctype", "key", "salt", "kdf",
        "iterations", "created_at", "retired_at",
    ]
    return [dict(zip(columns, row)) for row in rows]


def _normalize_enctype(enctype: str | int) -> str:
    if isinstance(enctype, int):
        return ENCTYPE_TO_NAME.get(enctype, str(enctype))
    return str(enctype)


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
