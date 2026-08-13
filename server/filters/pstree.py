"""
Turns raw windows.pstree.PsTree rows into a short, structured summary
plus a list of flagged anomalies. This is where the actual analysis
value lives — an LLM reading 200 raw process rows will miss the same
things a human skimming a wall of text misses. Flag it here instead
and hand the model a short list.

NOTE ON SCHEMA: Volatility 3's JSON renderer field names can shift
slightly between versions. Run one plugin against a known image and
check `rows[0].keys()` before relying on this in anger — the field
lookups below use `.get()` with common aliases for that reason.
"""

# Well-known Windows processes and the parent process name we'd expect
# to see them spawned under. Not exhaustive — extend as you encounter
# more cases. A mismatch doesn't prove malice, it's a lead to check.
EXPECTED_PARENTS = {
    "svchost.exe": {"services.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "winlogon.exe": {"smss.exe"},
    "explorer.exe": {"userinit.exe"},
    "csrss.exe": {"smss.exe"},
}


def _flatten(rows: list[dict]) -> list[dict]:
    """
    windows.pstree's JSON output is a tree — root processes with nested
    __children arrays — not a flat list. Walk it recursively so every
    process gets counted, not just the roots.
    """
    flat = []
    for row in rows:
        flat.append(row)
        children = row.get("__children") or []
        if children:
            flat.extend(_flatten(children))
    return flat


def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def analyze(rows: list[dict], evidence_map: dict[str, list[str]] = None) -> dict:
    evidence_map = evidence_map or {}
    rows = _flatten(rows)
    by_pid: dict[int, dict] = {}
    for row in rows:
        pid = _get(row, "PID", "Pid")
        if pid is not None:
            by_pid[int(pid)] = row

    anomalies = []

    for row in rows:
        pid = _get(row, "PID", "Pid")
        ppid = _get(row, "PPID", "Ppid")
        name = (_get(row, "ImageFileName", "Process", default="") or "").strip()

        if pid is None:
            continue
        pid = int(pid)
        name_lower = name.lower()

        # Orphaned process: parent PID not present among live processes,
        # and not one of the well-known root PIDs (System=4, idle=0).
        if ppid is not None:
            ppid = int(ppid)
            if ppid not in by_pid and ppid not in (0, 4):
                anomalies.append({
                    "type": "orphaned_parent",
                    "pid": pid,
                    "ppid": ppid,
                    "process": name,
                    "detail": f"PPID {ppid} not found among live processes — "
                              f"possible unlinked/terminated parent or DKOM artifact",
                    "evidence_ids": evidence_map.get(str(pid), []) + evidence_map.get(str(ppid), [])
                })

        # Unexpected parent for a well-known process name
        expected = EXPECTED_PARENTS.get(name_lower)
        if expected and ppid in by_pid:
            parent_name = (_get(by_pid[ppid], "ImageFileName", "Process", default="") or "").lower()
            if parent_name and parent_name not in expected:
                anomalies.append({
                    "type": "unexpected_parent",
                    "pid": pid,
                    "process": name,
                    "detail": f"expected parent in {sorted(expected)}, found '{parent_name}' (PID {ppid})",
                    "evidence_ids": evidence_map.get(str(pid), []) + evidence_map.get(str(ppid), [])
                })

    # Duplicate PIDs (shouldn't happen in a clean snapshot, worth flagging if it does)
    seen = set()
    for pid in by_pid:
        if pid in seen:
            anomalies.append({
                "type": "duplicate_pid", 
                "pid": pid, 
                "detail": "PID appears more than once",
                "evidence_ids": evidence_map.get(str(pid), [])
            })
        seen.add(pid)

    return {
        "process_count": len(by_pid),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }