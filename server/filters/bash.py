"""
Filter for linux_bash Volatility 3 output.
Normalizes raw bash history rows into a stable structured format.
"""

def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def analyze(rows: list[dict], evidence_map: dict[str, list[str]] = None) -> dict:
    evidence_map = evidence_map or {}
    
    results = []
    
    for row in rows:
        pid = _get(row, "Pid", "PID")
        pid_str = str(pid) if pid is not None else None
        
        timestamp = _get(row, "CommandTime", "Command Time")
        command = _get(row, "Command", "CommandLine")
        process = _get(row, "Process", "ProcessName")
        terminal = _get(row, "Terminal", "TTY")
        
        # Build evidence list associated with this PID
        # Evidence store uses the PID as the entity_id for bash_history records
        ev_ids = evidence_map.get(pid_str, []) if pid_str else []
        
        result = {
            "source": "linux_bash",
            "evidence_ids": ev_ids
        }
        
        if timestamp is not None:
            result["timestamp"] = timestamp
        if command is not None:
            result["command"] = command
        if pid is not None:
            result["pid"] = pid
        if process is not None:
            result["process"] = process
        if terminal is not None:
            result["terminal"] = terminal
            
        results.append(result)

    # Sort chronologically if timestamps exist, else by PID
    def sort_key(item):
        ts = item.get("timestamp", "")
        p = item.get("pid", 0)
        return (str(ts), int(p) if isinstance(p, (int, str)) and str(p).isdigit() else 0)

    results.sort(key=sort_key)

    return {
        "plugin": "linux_bash",
        "command_count": len(results),
        "results": results,
    }
