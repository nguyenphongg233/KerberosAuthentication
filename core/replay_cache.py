"""Persistent replay cache backed by SQLite."""

from __future__ import annotations

import os
import sqlite3
import time


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_REPLAY_CACHE_PATH = os.getenv(
    "KRB_REPLAY_CACHE",
    os.getenv("KDC_DB_PATH", os.path.join(PROJECT_ROOT, "kdc", "database.db")),
)


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
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


def check_and_store(cache_name: str, cache_key: str, client_principal: str,
                    server_principal: str, auth_time: float, now: float,
                    max_age: int,
                    db_path: str = DEFAULT_REPLAY_CACHE_PATH) -> bool:
    """
    Store an authenticator fingerprint.

    Returns True if the fingerprint already exists and should be treated as a
    replay. Returns False when the fingerprint is newly stored.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        _ensure_schema(conn)
        cutoff = now - max_age
        conn.execute(
            "DELETE FROM replay_cache WHERE seen_at < ?",
            (cutoff,),
        )
        try:
            conn.execute(
                """
                INSERT INTO replay_cache (
                    cache_name, cache_key, client_principal, server_principal,
                    auth_time, seen_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (cache_name, cache_key, client_principal, server_principal,
                 auth_time, now),
            )
        except sqlite3.IntegrityError:
            return True
        return False


def authenticator_cache_key(client_principal: str, server_principal: str,
                            timestamp: float, cusec: int | None = None) -> str:
    """Build a stable replay-cache key for an authenticator."""
    if cusec is None:
        cusec = int(round((timestamp - int(timestamp)) * 1_000_000))
    return f"{client_principal}|{server_principal}|{int(timestamp)}|{int(cusec)}"


def current_kerberos_time() -> tuple[float, int, int]:
    """Return timestamp, ctime, cusec in Kerberos-like form."""
    timestamp = time.time()
    ctime = int(timestamp)
    cusec = int(round((timestamp - ctime) * 1_000_000))
    return timestamp, ctime, cusec
