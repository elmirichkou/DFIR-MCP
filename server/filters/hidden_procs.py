"""
The linked-list-walking plugins (windows.pstree, linux.pslist) are
exactly what a rootkit doing DKOM (Direct Kernel Object Manipulation)
unlinking attacks: it removes its process from the list those plugins
walk, so it simply doesn't appear.

windows.psscan / linux.psscan instead scan memory pools/slabs directly
for process-struct signatures, so they see processes regardless of
whether they're linked into the list. A PID present in the scan but
absent from the list-walk is exactly the DKOM signature — this is the
same class of technique used to find the hidden 'singularity' process
in the Phantom case.
"""


def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def _pid_map(rows: list[dict]) -> dict[int, dict]:
    out = {}
    for row in rows:
        pid = _get(row, "PID", "Pid")
        if pid is not None:
            out[int(pid)] = row
    return out


def analyze(
    list_walk_rows: list[dict],
    pool_scan_rows: list[dict],
    psscan_evidence_map: dict[str, list[str]] | None = None,
) -> dict:
    walked = _pid_map(list_walk_rows)
    scanned = _pid_map(pool_scan_rows)

    hidden_pids = sorted(set(scanned) - set(walked))
    
    ev_map = psscan_evidence_map or {}

    anomalies = [
        {
            "type": "hidden_process",
            "pid": pid,
            "process": (_get(scanned[pid], "ImageFileName", "COMM", "Comm", default="") or ""),
            "ppid": _get(scanned[pid], "PPID", "Ppid"),
            "creation_time": _get(scanned[pid], "CreateTime", "Create Time", "Start Time", "StartTime"),
            "exit_time": _get(scanned[pid], "ExitTime", "Exit Time"),
            "virtual_offset": _get(scanned[pid], "Offset(V)", "Offset", "Virtual Offset", "OFFSET (V)"),
            "physical_offset": _get(scanned[pid], "Offset(P)", "Physical Offset", "OFFSET (P)"),
            "uid": _get(scanned[pid], "UID"),
            "gid": _get(scanned[pid], "GID"),
            "thread_count": _get(scanned[pid], "Threads", "Thread Count"),
            "session_id": _get(scanned[pid], "SessionId", "Session"),
            "detail": f"PID {pid} found by the pool/memory scan but absent from the linked-list walk — "
                      f"likely DKOM-unlinked. Investigate this process before anything else.",
            "raw": scanned[pid],
            "evidence_ids": ev_map.get(str(pid), []),
        }
        for pid in hidden_pids
    ]

    return {
        "list_walk_count": len(walked),
        "pool_scan_count": len(scanned),
        "hidden_count": len(hidden_pids),
        "anomalies": anomalies,
    }
