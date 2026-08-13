"""
Turns raw windows.netscan.NetScan rows into a short, structured summary
plus flagged anomalies. Same schema caveat as pstree.py applies.
"""

# Ports commonly associated with C2 frameworks / reverse shells / known
# malware defaults. Not authoritative — a hit here is a lead, not a verdict.
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 8443, 9001, 9999}

# Processes we generally expect to see making outbound network connections.
# Anything NOT in here making an external connection is worth a second look.
COMMON_NETWORK_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe",
    "explorer.exe", "outlook.exe", "teams.exe", "onedrive.exe",
    "system", "smartscreen.exe",
}


def _get(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


def _is_local(addr: str) -> bool:
    if not addr:
        return True
    return addr.startswith(("127.", "0.0.0.0", "::", "169.254."))


def analyze(rows: list[dict], evidence_map: dict[str, list[str]] = None) -> dict:
    evidence_map = evidence_map or {}
    anomalies = []

    for row in rows:
        proc = (_get(row, "Owner", "Process", default="") or "").strip()
        proc_lower = proc.lower()
        foreign_addr = _get(row, "ForeignAddr", "Foreign Addr", default="")
        foreign_port = _get(row, "ForeignPort", "Foreign Port")
        local_port = _get(row, "LocalPort", "Local Port")
        pid = _get(row, "Pid", "PID", "Owner PID")

        try:
            foreign_port = int(foreign_port) if foreign_port not in (None, "*", "") else None
        except (TypeError, ValueError):
            foreign_port = None
        try:
            local_port = int(local_port) if local_port not in (None, "*", "") else None
        except (TypeError, ValueError):
            local_port = None

        if foreign_port in SUSPICIOUS_PORTS or local_port in SUSPICIOUS_PORTS:
            anomalies.append({
                "type": "suspicious_port",
                "process": proc,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "local_port": local_port,
                "detail": "port commonly associated with C2/reverse-shell tooling",
                "evidence_ids": evidence_map.get(str(pid), []) if pid is not None else []
            })

        if not _is_local(foreign_addr) and proc_lower and proc_lower not in COMMON_NETWORK_PROCESSES:
            anomalies.append({
                "type": "uncommon_network_process",
                "process": proc,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "detail": f"'{proc}' is not in the common-network-process allowlist — "
                          f"worth checking whether it should be talking to {foreign_addr or 'this host'}",
                "evidence_ids": evidence_map.get(str(pid), []) if pid is not None else []
            })

    return {
        "connection_count": len(rows),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }
