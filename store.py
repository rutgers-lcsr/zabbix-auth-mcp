"""
SQLite persistence for OAuth clients, pending logins, authorization codes and
tokens.

Codes and tokens are stored as SHA-256 hashes, so a copy of the database file
cannot be used to impersonate anyone here. The users' Zabbix API tokens are
stored as-is, since they have to be sent along with every MCP call: keep the
file readable by root only. Client registrations persist across restarts so
MCP clients (claude.ai, Claude Code) keep working after a deploy.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT,
    client_name TEXT,
    redirect_uris TEXT NOT NULL,
    token_endpoint_auth_method TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_requests (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    state TEXT,
    scope TEXT,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT,
    username TEXT NOT NULL,
    zabbix_token TEXT NOT NULL,
    zabbix_tokenid TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    client_id TEXT NOT NULL,
    username TEXT NOT NULL,
    scope TEXT,
    zabbix_token TEXT NOT NULL,
    zabbix_tokenid TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
"""


@contextmanager
def _connect():
    db = sqlite3.connect(config.DB_PATH, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        with db:  # commit on success, roll back on error
            yield db
    finally:
        db.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(config.DB_PATH) or ".", exist_ok=True)
    with _connect() as db:
        db.executescript(SCHEMA)


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _get(table: str, column: str, value: str) -> dict | None:
    """Return the row, or None if it is missing or expired."""
    with _connect() as db:
        row = db.execute(f"SELECT * FROM {table} WHERE {column} = ?", (value,)).fetchone()
    if row is None or row["expires_at"] < time.time():
        return None
    return dict(row)


def _pop(table: str, column: str, value: str) -> dict | None:
    """Delete and return the row, or None if it is missing or expired."""
    with _connect() as db:
        row = db.execute(f"SELECT * FROM {table} WHERE {column} = ?", (value,)).fetchone()
        db.execute(f"DELETE FROM {table} WHERE {column} = ?", (value,))
    if row is None or row["expires_at"] < time.time():
        return None
    return dict(row)


# --- OAuth clients (dynamic client registration) ---------------------------

def save_client(client: dict) -> None:
    with _connect() as db:
        db.execute(
            "INSERT INTO clients VALUES (?, ?, ?, ?, ?, ?)",
            (
                client["client_id"],
                client["client_secret"],
                client["client_name"],
                json.dumps(client["redirect_uris"]),
                client["token_endpoint_auth_method"],
                client["created_at"],
            ),
        )


def get_client(client_id: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    if row is None:
        return None
    client = dict(row)
    client["redirect_uris"] = json.loads(client["redirect_uris"])
    return client


# --- pending logins ---------------------------------------------------------

def save_auth_request(client_id: str, redirect_uri: str, code_challenge: str, state: str | None, scope: str | None) -> str:
    rid = new_secret(24)
    with _connect() as db:
        db.execute(
            "INSERT INTO auth_requests VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rid, client_id, redirect_uri, code_challenge, state, scope, int(time.time()) + config.AUTH_REQUEST_TTL),
        )
    return rid


def get_auth_request(rid: str) -> dict | None:
    return _get("auth_requests", "id", rid)


def delete_auth_request(rid: str) -> None:
    with _connect() as db:
        db.execute("DELETE FROM auth_requests WHERE id = ?", (rid,))


# --- authorization codes ----------------------------------------------------

def save_auth_code(code: str, client_id: str, redirect_uri: str, code_challenge: str, scope: str | None,
                   username: str, zabbix_token: str, zabbix_tokenid: str) -> None:
    with _connect() as db:
        db.execute(
            "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (_hash(code), client_id, redirect_uri, code_challenge, scope, username, zabbix_token, zabbix_tokenid,
             int(time.time()) + config.AUTH_CODE_TTL),
        )


def pop_auth_code(code: str) -> dict | None:
    return _pop("auth_codes", "code_hash", _hash(code))


# --- access / refresh tokens ------------------------------------------------

def save_token(token: str, kind: str, client_id: str, username: str, scope: str | None, ttl: int,
               zabbix_token: str, zabbix_tokenid: str) -> None:
    with _connect() as db:
        db.execute(
            "INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (_hash(token), kind, client_id, username, scope, zabbix_token, zabbix_tokenid, int(time.time()) + ttl),
        )


def get_token(token: str, kind: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM tokens WHERE token_hash = ? AND kind = ?", (_hash(token), kind)).fetchone()
    if row is None or row["expires_at"] < time.time():
        return None
    return dict(row)


def delete_token(token: str) -> None:
    with _connect() as db:
        db.execute("DELETE FROM tokens WHERE token_hash = ?", (_hash(token),))


def purge_expired() -> None:
    now = int(time.time())
    with _connect() as db:
        for table in ("auth_requests", "auth_codes", "tokens"):
            db.execute(f"DELETE FROM {table} WHERE expires_at < ?", (now,))
