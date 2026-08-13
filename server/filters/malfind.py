def analyze(rows: list[dict], evidence_map: dict[str, list[str]]) -> dict:
    """
    Filter malfind output.
    Returns conservative observations without declaring definitive malware.
    """
    findings = []
    
    for row in rows:
        pid = row.get("PID", row.get("Pid"))
        if pid is None:
            pid_str = None
            ev_ids = []
        else:
            pid_str = str(pid)
            ev_ids = evidence_map.get(pid_str, [])
            
        process = row.get("Process", row.get("COMM", row.get("ImageFileName", "")))
        start_vpn = row.get("Start VPN", "")
        end_vpn = row.get("End VPN", "")
        protection = row.get("Protection", "")
        
        hexdump = row.get("Hexdump", "")
        disasm = row.get("Disasm", "")
        
        findings.append({
            "pid": pid,
            "process": process,
            "memory_region": f"{start_vpn} - {end_vpn}",
            "protection": protection,
            "suspicious_characteristics": ["Injected/unbacked executable memory region detected by malfind"],
            "disassembly_preview": disasm.split('\n')[:5] if disasm else [],
            "hexdump_preview": hexdump.split('\n')[:3] if hexdump else [],
            "evidence_ids": ev_ids,
            "analyst_note": "This is an indicator of potential injection, but must be manually verified. JIT compilers or security products can also produce such regions."
        })
        
    return {
        "finding_count": len(findings),
        "anomalies": findings,
        "anomaly_count": len(findings),
    }
