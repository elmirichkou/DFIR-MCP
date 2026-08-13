"""
Persistent evidence store for dfir-mcp.

After every Volatility execution the flow is:
    raw rows  →  evidence_store  →  filter  →  MCP response

Evidence records survive past the tool call, enabling:
  - Cross-tool correlation without re-running Volatility
  - Plugin result caching (cache-hit returns rows + evidence_map instantly)
  - Full provenance: anomaly → evidence_id → raw row → plugin run → image
"""
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Shared DB with session.py  (same cases/cases.db file)
DB_PATH = Path(__file__).parent.parent / "cases" / "cases.db"

# ─────────────────────────── Plugin metadata ─────────────────────────────────
# Tuple: (evidence_type, entity_type, id_field_aliases, name_field_aliases)
_PLUGIN_META: dict[str, tuple[str, str, list[str], list[str]]] = {
    "linux_pslist":        ("process_record",    "process",    ["PID", "Pid"],              ["COMM", "Comm"]),
    "linux_psscan":        ("process_record",    "process",    ["PID", "Pid"],              ["COMM", "Comm"]),
    "linux_pstree":        ("process_record",    "process",    ["PID", "Pid"],              ["COMM", "Comm"]),
    "linux_bash":          ("bash_history",      "process",    ["Pid", "PID"],              ["Command"]),
    "linux_sockstat":      ("network_connection","process",    ["Pid", "PID"],              ["Comm", "COMM"]),
    "linux_lsmod":         ("kernel_module",     "module",     ["Module Name"],             ["Module Name"]),
    "linux_check_modules": ("suspicious_module", "module",     ["Module Name"],             ["Module Name"]),
    "win_pstree":          ("process_record",    "process",    ["PID", "Pid"],              ["ImageFileName"]),
    "win_psscan":          ("process_record",    "process",    ["PID", "Pid"],              ["ImageFileName"]),
    "win_netscan":         ("network_connection","process",    ["Pid", "PID", "Owner PID"], ["Owner"]),
    "win_modules":         ("kernel_module",     "module",     ["Offset"],                  ["Name"]),
    "win_malfind":         ("malware_indicator", "process",    ["PID", "Pid"],              ["Process", "ImageFileName", "COMM"]),
    "linux_malfind":       ("malware_indicator", "process",    ["PID", "Pid"],              ["Process", "ImageFileName", "COMM"]),
    "win_ssdt":            ("ssdt_entry",        "ssdt",       ["Index", "Offset"],         ["Symbol"]),
}

# ─────────────────────────── Schema ──────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id   TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    plugin_run_id INTEGER,
    plugin        TEXT NOT NULL,
    tool          TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    entity_id     TEXT,
    entity_name   TEXT,
    attributes    TEXT NOT NULL DEFAULT '{}',
    raw           TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugin_cache (
    cache_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    image         TEXT NOT NULL,
    plugin        TEXT NOT NULL,
    args_hash     TEXT NOT NULL,
    plugin_run_id INTEGER,
    rows_json     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE(session_id, plugin, args_hash)
);

CREATE INDEX IF NOT EXISTS idx_evidence_session    ON evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_evidence_plugin     ON evidence(plugin);
CREATE INDEX IF NOT EXISTS idx_evidence_plugin_run ON evidence(plugin_run_id);
CREATE INDEX IF NOT EXISTS idx_evidence_entity     ON evidence(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type       ON evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_plugin_cache_lookup ON plugin_cache(session_id, plugin, args_hash);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


# ─────────────────────────── Internal helpers ─────────────────────────────────

def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def _flatten_tree(rows: list[dict]) -> list[dict]:
    """Recursively flatten Volatility pstree __children arrays."""
    flat: list[dict] = []
    for row in rows:
        flat.append(row)
        for child in (row.get("__children") or []):
            flat.extend(_flatten_tree([child]))
    return flat


def _maybe_flatten(plugin: str, rows: list[dict]) -> list[dict]:
    """Flatten tree-structured plugins so every process gets its own evidence record."""
    if plugin in ("linux_pstree", "win_pstree"):
        return _flatten_tree(rows)
    return rows


def _extract_entity(plugin: str, row: dict) -> tuple[str | None, str | None]:
    """Return (entity_id_str, entity_name_str) for a single Volatility row."""
    meta = _PLUGIN_META.get(plugin)
    if not meta:
        return None, None
    _, _, id_aliases, name_aliases = meta
    eid = _get(row, *id_aliases)
    ename = _get(row, *name_aliases)
    return (
        str(eid) if eid is not None else None,
        str(ename) if ename is not None else None,
    )


def _extract_attributes(plugin: str, row: dict) -> dict:
    """Extract meaningful structured fields as convenience attributes."""
    attrs: dict = {}
    if plugin in ("linux_pslist", "linux_psscan", "linux_pstree", "win_pstree", "win_psscan"):
        ppid = _get(row, "PPID", "Ppid")
        if ppid is not None:
            attrs["ppid"] = ppid
        tid = _get(row, "TID", "Tid")
        if tid is not None:
            attrs["tid"] = tid
        if "EXIT_STATE" in row:
            attrs["exit_state"] = row["EXIT_STATE"]
        if "OFFSET (P)" in row:
            attrs["physical_offset"] = row["OFFSET (P)"]
        if "OFFSET (V)" in row:
            attrs["virtual_offset"] = row["OFFSET (V)"]
    elif plugin == "linux_bash":
        cmd = _get(row, "Command")
        if cmd is not None:
            attrs["command"] = cmd
        t = _get(row, "CommandTime", "Command Time")
        if t is not None:
            attrs["command_time"] = t
    elif plugin in ("linux_sockstat", "win_netscan"):
        da = _get(row, "Destination Addr", "DestAddr", "ForeignAddr", "Foreign Addr")
        if da is not None:
            attrs["dest_addr"] = da
        dp = _get(row, "Destination Port", "DestPort", "ForeignPort", "Foreign Port")
        if dp is not None:
            attrs["dest_port"] = dp
        st = row.get("State")
        if st is not None:
            attrs["state"] = st
        sp = _get(row, "Source Port", "SourcePort", "LocalPort", "Local Port")
        if sp is not None:
            attrs["source_port"] = sp
    return attrs


# ─────────────────────────── Plugin cache ────────────────────────────────────

def hash_args(extra_args: list[str]) -> str:
    """Deterministic cache key component for plugin extra_args."""
    payload = json.dumps(sorted(extra_args))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def get_cached_plugin_result(
    session_id: str,
    image: str,
    plugin: str,
    args_hash: str,
) -> dict | None:
    """
    Return cached plugin result or None.
    Result dict: {"rows": list[dict], "plugin_run_id": int}
    """
    with _conn() as conn:
        row = conn.execute(
            "SELECT rows_json, plugin_run_id FROM plugin_cache "
            "WHERE session_id = ? AND image = ? AND plugin = ? AND args_hash = ?",
            (session_id, image, plugin, args_hash),
        ).fetchone()
    if not row:
        return None
    return {
        "rows": json.loads(row["rows_json"]),
        "plugin_run_id": row["plugin_run_id"],
    }


def store_plugin_cache(
    session_id: str,
    image: str,
    plugin: str,
    args_hash: str,
    rows: list[dict],
    plugin_run_id: int,
) -> None:
    """Cache the raw plugin result. INSERT OR IGNORE — never overwrites existing cache."""
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO plugin_cache "
            "(session_id, image, plugin, args_hash, plugin_run_id, rows_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, image, plugin, args_hash, plugin_run_id, json.dumps(rows), now),
        )


# ─────────────────────────── Evidence records ─────────────────────────────────

def store_plugin_evidence(
    session_id: str,
    plugin_run_id: int,
    plugin: str,
    tool: str,
    rows: list[dict],
) -> dict[str, list[str]]:
    """
    Store one evidence record per Volatility row.

    Idempotent: if evidence already exists for this plugin_run_id, returns
    the existing entity_evidence_map without inserting duplicates.

    Returns: entity_id_str → [evidence_id, ...] for all rows.
    """
    # Idempotency check
    with _conn() as conn:
        existing_count = conn.execute(
            "SELECT COUNT(*) FROM evidence WHERE plugin_run_id = ? AND session_id = ?",
            (plugin_run_id, session_id),
        ).fetchone()[0]
    if existing_count > 0:
        return get_entity_evidence_map(session_id, plugin_run_id)

    meta = _PLUGIN_META.get(plugin)
    evidence_type = meta[0] if meta else "raw_record"
    entity_type = meta[1] if meta else "unknown"

    flat_rows = _maybe_flatten(plugin, rows)
    now = datetime.now(timezone.utc).isoformat()
    entity_map: dict[str, list[str]] = {}

    with _conn() as conn:
        for row in flat_rows:
            ev_id = f"ev-{uuid.uuid4().hex[:8]}"
            entity_id, entity_name = _extract_entity(plugin, row)
            attributes = _extract_attributes(plugin, row)
            conn.execute(
                "INSERT INTO evidence "
                "(evidence_id, session_id, plugin_run_id, plugin, tool, evidence_type, "
                " entity_type, entity_id, entity_name, attributes, raw, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ev_id, session_id, plugin_run_id, plugin, tool,
                    evidence_type, entity_type, entity_id, entity_name,
                    json.dumps(attributes), json.dumps(row), now,
                ),
            )
            if entity_id is not None:
                entity_map.setdefault(entity_id, []).append(ev_id)

    return entity_map


def get_entity_evidence_map(session_id: str, plugin_run_id: int) -> dict[str, list[str]]:
    """Return entity_id_str → [evidence_id, ...] for every record in a plugin run."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT evidence_id, entity_id FROM evidence "
            "WHERE session_id = ? AND plugin_run_id = ? AND entity_id IS NOT NULL",
            (session_id, plugin_run_id),
        ).fetchall()
    result: dict[str, list[str]] = {}
    for row in rows:
        result.setdefault(row["entity_id"], []).append(row["evidence_id"])
    return result


def get_evidence(evidence_id: str) -> dict | None:
    """Retrieve a complete evidence record, deserializing JSON fields."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["attributes"] = json.loads(d["attributes"])
    d["raw"] = json.loads(d["raw"])
    return d


def search_evidence(
    session_id: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    evidence_type: str | None = None,
    plugin: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """
    Search evidence records with optional filters. All filters AND-combined.
    Results ordered by creation time, capped at `limit`.
    """
    clauses = ["session_id = ?"]
    params: list = [session_id]

    if entity_type:
        clauses.append("entity_type = ?")
        params.append(entity_type)
    if entity_id is not None:
        clauses.append("entity_id = ?")
        params.append(str(entity_id))
    if evidence_type:
        clauses.append("evidence_type = ?")
        params.append(evidence_type)
    if plugin:
        clauses.append("plugin = ?")
        params.append(plugin)

    params.append(limit)
    sql = (
        f"SELECT * FROM evidence WHERE {' AND '.join(clauses)} "
        f"ORDER BY created_at LIMIT ?"
    )
    with _conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        d["attributes"] = json.loads(d["attributes"])
        d["raw"] = json.loads(d["raw"])
        result.append(d)
    return result
