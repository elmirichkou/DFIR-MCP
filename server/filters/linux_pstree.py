"""
Linux process-tree heuristics. Different from Windows in one important
way: on Linux, orphaned processes get legitimately reparented to PID 1
(init/systemd) or PID 2 (kthreadd, for kernel threads) — that's normal
behavior, not an anomaly. So "orphan" detection here is intentionally
much quieter than the Windows version; a missing parent that ISN'T 1
or 2 is the interesting case.

Field names assume linux.pslist/pstree JSON output uses COMM, PID, PPID.
Verify against your Volatility version before trusting this in anger.
"""

REPARENT_TARGETS = {0, 1, 2}  # kernel/swapper, init/systemd, kthreadd


def _flatten(rows: list[dict]) -> list[dict]:
    """
    linux.pstree's JSON output is a tree — root processes with nested
    __children arrays — unlike pslist/psscan which are flat. Walk it
    recursively so every process gets counted, not just the roots.
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
        comm = (_get(row, "COMM", "Comm", "Command", default="") or "").strip()

        if pid is None or ppid is None:
            continue
        pid, ppid = int(pid), int(ppid)

        if ppid not in by_pid and ppid not in REPARENT_TARGETS:
            anomalies.append({
                "type": "unresolved_parent",
                "pid": pid,
                "ppid": ppid,
                "process": comm,
                "detail": f"PPID {ppid} not found among live processes and isn't init/kthreadd — "
                          f"check whether this process was DKOM-unlinked from its real parent",
                "evidence_ids": evidence_map.get(str(pid), []) + evidence_map.get(str(ppid), [])
            })

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