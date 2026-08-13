"""
Linux network-connection heuristics, parallel to filters/netscan.py but
for linux.sockstat output. Field names assume Source/Destination Addr
and Port columns plus Pid/Comm — verify against your Volatility version.
"""

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 8443, 9001, 9999}

COMMON_NETWORK_PROCESSES = {
    "sshd", "systemd-resolve", "chronyd", "ntpd", "dockerd", "containerd",
    "curl", "wget", "apt", "apt-get", "dpkg", "python3", "nginx", "apache2",
    "docker-proxy",
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
        comm = (_get(row, "Comm", "COMM", default="") or "").strip()
        comm_lower = comm.lower()
        dest_addr = _get(row, "Destination Addr", "DestAddr", "Foreign Addr", default="")
        dest_port = _get(row, "Destination Port", "DestPort", "Foreign Port")
        source_port = _get(row, "Source Port", "SourcePort")
        pid = _get(row, "Pid", "PID")

        try:
            dest_port = int(dest_port) if dest_port not in (None, "*", "") else None
        except (TypeError, ValueError):
            dest_port = None
        try:
            source_port = int(source_port) if source_port not in (None, "*", "") else None
        except (TypeError, ValueError):
            source_port = None

        if dest_port in SUSPICIOUS_PORTS or source_port in SUSPICIOUS_PORTS:
            anomalies.append({
                "type": "suspicious_port",
                "process": comm,
                "dest_addr": dest_addr,
                "dest_port": dest_port,
                "source_port": source_port,
                "detail": "port commonly associated with C2/reverse-shell tooling",
                "evidence_ids": evidence_map.get(str(pid), []) if pid is not None else []
            })

        if not _is_local(dest_addr) and comm_lower and comm_lower not in COMMON_NETWORK_PROCESSES:
            anomalies.append({
                "type": "uncommon_network_process",
                "process": comm,
                "dest_addr": dest_addr,
                "dest_port": dest_port,
                "detail": f"'{comm}' is not in the common-network-process allowlist — "
                          f"worth checking whether it should be talking to {dest_addr or 'this host'}",
                "evidence_ids": evidence_map.get(str(pid), []) if pid is not None else []
            })

    return {
        "connection_count": len(rows),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }
