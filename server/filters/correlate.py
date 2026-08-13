"""
Takes the PIDs flagged as DKOM-hidden (from hidden_procs.analyze) and
joins them against linux.bash and linux.sockstat output, so each hidden
process comes back with what it actually did — commands run, connections
made — instead of a bare PID number the analyst has to go look up by hand.

Field name caveats apply here too: linux.bash and linux.sockstat column
names can vary by Volatility version, hence the alias lookups.
"""


def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def _group_by_pid(rows: list[dict]) -> dict[int, list[dict]]:
    grouped: dict[int, list[dict]] = {}
    for row in rows:
        pid = _get(row, "Pid", "PID")
        if pid is None:
            continue
        grouped.setdefault(int(pid), []).append(row)
    return grouped


def analyze(hidden_pids: list[int], bash_rows: list[dict], sockstat_rows: list[dict]) -> dict:
    bash_by_pid = _group_by_pid(bash_rows)
    sock_by_pid = _group_by_pid(sockstat_rows)

    profiles = []
    for pid in hidden_pids:
        commands = [
            {
                "command": _get(row, "Command", "CommandLine", default=""),
                "time": _get(row, "CommandTime", "Command Time", default=""),
            }
            for row in bash_by_pid.get(pid, [])
        ]
        connections = [
            {
                "dest_addr": _get(row, "Destination Addr", "DestAddr", "Foreign Addr", default=""),
                "dest_port": _get(row, "Destination Port", "DestPort", "Foreign Port", default=""),
                "state": _get(row, "State", default=""),
            }
            for row in sock_by_pid.get(pid, [])
        ]
        profiles.append({
            "pid": pid,
            "bash_history": commands,
            "network_connections": connections,
            "has_corroborating_activity": bool(commands or connections),
        })

    return {
        "profiled_count": len(profiles),
        "profiles": profiles,
    }