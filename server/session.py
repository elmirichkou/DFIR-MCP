"""
Lightweight case/session state, backed by SQLite. Tracks which memory
image is under investigation, which plugins have been run against it,
and the analyst's (or the LLM's) pinned findings.

Deliberately simple: one SQLite file, no ORM. This is meant to be
readable, not to scale past a single analyst's workstation.
"""
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "cases" / "cases.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    os TEXT NOT NULL DEFAULT 'linux',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS active_session (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS plugin_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    plugin TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    anomaly_count INTEGER NOT NULL,
    ran_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    note TEXT NOT NULL,
    source TEXT,
    created_at TEXT NOT NULL
);
"""


def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def create_session(name: str, image: str, os: str = "linux") -> str:
    if os not in ("linux", "windows"):
        raise ValueError("os must be 'linux' or 'windows'")
    session_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO sessions (id, name, image, os, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, name, image, os, now),
        )
        conn.execute(
            "INSERT INTO active_session (id, session_id) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET session_id = excluded.session_id",
            (session_id,),
        )
    return session_id


def get_active_session() -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            """
            SELECT s.* FROM sessions s
            JOIN active_session a ON a.session_id = s.id
            WHERE a.id = 1
            """
        ).fetchone()
        return dict(row) if row else None


def set_active_session(session_id: str):
    with _conn() as conn:
        conn.execute(
            "INSERT INTO active_session (id, session_id) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET session_id = excluded.session_id",
            (session_id,),
        )


def list_sessions() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def record_plugin_run(session_id: str, plugin: str, row_count: int, anomaly_count: int) -> int:
    """Insert a plugin-run record and return the new plugin_run_id (lastrowid)."""
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO plugin_runs (session_id, plugin, row_count, anomaly_count, ran_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, plugin, row_count, anomaly_count, now),
        )
        return cur.lastrowid


def update_plugin_run_anomaly_count(plugin_run_id: int, anomaly_count: int) -> None:
    """Patch the anomaly_count on an existing plugin run (e.g. after filtering)."""
    with _conn() as conn:
        conn.execute(
            "UPDATE plugin_runs SET anomaly_count = ? WHERE id = ?",
            (anomaly_count, plugin_run_id),
        )


def add_finding(session_id: str, note: str, source: str | None = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO findings (session_id, note, source, created_at) VALUES (?, ?, ?, ?)",
            (session_id, note, source, now),
        )
        return cur.lastrowid


def list_findings(session_id: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_plugin_runs(session_id: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM plugin_runs WHERE session_id = ? ORDER BY ran_at",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]
