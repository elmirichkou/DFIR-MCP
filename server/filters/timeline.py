"""
Timeline filter: transforms stored evidence records into a unified
chronological timeline of forensic events.

NOT a Volatility plugin runner — operates entirely on evidence already
persisted in the evidence_store.

Timestamp strategy
------------------
Only evidence sources that contain a genuine forensic timestamp in their
raw data produce chronological ("temporal") events.  Evidence sources
with no usable timestamp are included as "contextual" events — they
carry forensic value but cannot be placed on a timeline.

Currently supported temporal sources:
  - linux_bash  → CommandTime / Command Time field

Contextual (non-temporal) sources — included but sorted after all
temporal events:
  - process_record (pslist, psscan, pstree variants)
  - network_connection (sockstat, netscan)
  - kernel_module / suspicious_module (lsmod, check_modules)

Ordering rules
--------------
1. Temporal events are sorted chronologically by their parsed timestamp.
2. Events with identical timestamps maintain a stable secondary sort by
   (plugin, entity_id, evidence_id).
3. Contextual events (no timestamp) are grouped after all temporal events,
   sorted by (plugin, entity_id, evidence_id) for determinism.
4. Malformed timestamps are treated as missing — the event becomes
   contextual rather than crashing.
"""
from datetime import datetime, timezone


# ─────────────────── Timestamp extraction per plugin ──────────────────────

# Maps plugin name → list of raw-field aliases that contain a forensic
# timestamp.  Only plugins listed here produce temporal events.
_TIMESTAMP_FIELDS: dict[str, list[str]] = {
    "linux_bash": ["CommandTime", "Command Time"],
    "win_pstree": ["CreateTime", "Create Time", "Created"],
    "win_psscan": ["CreateTime", "Create Time", "Created"],
    "win_pslist": ["CreateTime", "Create Time", "Created"],
    "linux_pslist": ["StartTime", "Start Time"],
    "linux_psscan": ["StartTime", "Start Time"],
    "linux_pstree": ["StartTime", "Start Time"],
    "win_netscan": ["Created", "CreateTime", "Create Time"],
}


def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def _parse_timestamp(raw_value) -> datetime | None:
    """
    Best-effort ISO-8601 timestamp parse.  Returns None on any failure
    so a single bad record never crashes the timeline.
    """
    if raw_value is None:
        return None
    s = str(raw_value).strip()
    if not s:
        return None
    # Try several common ISO variants Volatility may emit.
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # Last resort: Python 3.11+ fromisoformat handles most variants.
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


# ─────────────────── Event description builders ───────────────────────────

def _describe_event(evidence: dict) -> str:
    """Build a human-readable one-liner from an evidence record."""
    plugin = evidence.get("plugin", "")
    raw = evidence.get("raw", {})
    attrs = evidence.get("attributes", {})
    etype = evidence.get("evidence_type", "")

    if etype == "bash_history":
        cmd = attrs.get("command") or _get(raw, "Command", "CommandLine", default="")
        return f"bash: {cmd}" if cmd else "bash command"

    if etype == "process_record":
        name = evidence.get("entity_name", "")
        pid = evidence.get("entity_id", "")
        ppid = attrs.get("ppid", "")
        return f"process: {name} (PID {pid}, PPID {ppid})"

    if etype == "network_connection":
        da = attrs.get("dest_addr") or ""
        dp = attrs.get("dest_port") or ""
        sp = attrs.get("source_port") or ""
        state = attrs.get("state") or ""
        name = evidence.get("entity_name", "")
        parts = [f"network: {name}"]
        if da:
            parts.append(f"→ {da}:{dp}")
        if sp:
            parts.append(f"from :{sp}")
        if state:
            parts.append(f"[{state}]")
        return " ".join(parts)

    if etype in ("kernel_module", "suspicious_module"):
        name = evidence.get("entity_name", "")
        return f"module: {name}" if name else "kernel module"

    # Fallback
    name = evidence.get("entity_name", "") or ""
    return f"{etype}: {name}" if name else etype or "evidence"


# ─────────────────── Core timeline builder ────────────────────────────────

def build_timeline(
    evidence_records: list[dict],
    entity_id: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 200,
) -> dict:
    """
    Transform a list of evidence records into a sorted timeline.

    Parameters
    ----------
    evidence_records : flat list of evidence dicts (as returned by
                       evidence_store.search_evidence)
    entity_id        : if set, include only records matching this entity
    start_time       : ISO-8601 lower bound (inclusive) for temporal events
    end_time         : ISO-8601 upper bound (inclusive) for temporal events
    limit            : max events returned

    Returns
    -------
    {
        "event_count": int,
        "events": [...],
        "sources": [...],       # distinct plugin names that contributed
        "temporal_count": int,  # events with a real forensic timestamp
        "contextual_count": int # events without a forensic timestamp
    }
    """
    # Parse time bounds once.
    start_dt = _parse_timestamp(start_time)
    end_dt = _parse_timestamp(end_time)

    temporal: list[tuple[datetime, dict]] = []
    contextual: list[dict] = []
    sources: set[str] = set()

    for ev in evidence_records:
        # Entity filter
        if entity_id is not None and ev.get("entity_id") != str(entity_id):
            continue

        plugin = ev.get("plugin", "")
        raw = ev.get("raw", {})
        ev_id = ev.get("evidence_id", "")
        sources.add(plugin)

        # Attempt to extract a forensic timestamp.
        ts_aliases = _TIMESTAMP_FIELDS.get(plugin, [])
        raw_ts = _get(raw, *ts_aliases) if ts_aliases else None
        parsed_ts = _parse_timestamp(raw_ts)

        event = {
            "timestamp": str(raw_ts) if raw_ts is not None else None,
            "timestamp_parsed": parsed_ts.isoformat() if parsed_ts else None,
            "event_type": ev.get("evidence_type", "unknown"),
            "entity_type": ev.get("entity_type", "unknown"),
            "entity_id": ev.get("entity_id"),
            "entity_name": ev.get("entity_name"),
            "description": _describe_event(ev),
            "plugin": plugin,
            "evidence_ids": list(set([ev_id])),
            "is_temporal": parsed_ts is not None,
            "classification": "observed",
        }

        if parsed_ts is not None:
            # Apply time-range filter only to temporal events.
            if start_dt and parsed_ts < start_dt:
                continue
            if end_dt and parsed_ts > end_dt:
                continue
            temporal.append((parsed_ts, event))
        else:
            contextual.append(event)

    # Sort: temporal first by timestamp, then stable secondary key.
    temporal.sort(key=lambda pair: (
        pair[0],
        pair[1]["plugin"],
        pair[1]["entity_id"] or "",
        pair[1]["evidence_ids"][0],
    ))

    # Contextual: deterministic sort by (plugin, entity_id, evidence_id).
    contextual.sort(key=lambda e: (
        e["plugin"],
        e["entity_id"] or "",
        e["evidence_ids"][0],
    ))

    all_events = [ev for _, ev in temporal] + contextual

    # Apply limit.
    truncated = all_events[:limit]

    return {
        "event_count": len(truncated),
        "events": truncated,
        "sources": sorted(sources),
        "temporal_count": sum(1 for e in truncated if e["is_temporal"]),
        "contextual_count": sum(1 for e in truncated if not e["is_temporal"]),
    }
