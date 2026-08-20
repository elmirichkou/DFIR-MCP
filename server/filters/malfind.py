def analyze(rows: list[dict], evidence_map: dict[str, list[str]], os_type: str = "unknown") -> dict:
    """
    Filter malfind output (windows and linux).
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
        
        # Windows typically outputs "Start VPN" and "End VPN"
        # Linux might output "Start", "End" or just "Address" (or similar)
        start_vpn = row.get("Start VPN", row.get("Start", ""))
        end_vpn = row.get("End VPN", row.get("End", ""))
        address = ""
        if start_vpn and end_vpn:
            address = f"{start_vpn} - {end_vpn}"
        elif start_vpn:
            address = str(start_vpn)
            
        protection = row.get("Protection", row.get("VMA Protection", ""))
        hexdump = row.get("Hexdump", "")
        disasm = row.get("Disasm", "")
        
        finding = {
            "platform": os_type,
            "evidence_ids": ev_ids,
            "reason": "suspicious_memory_region"
        }
        
        if pid is not None:
            finding["pid"] = pid
        if process is not None and process != "":
            finding["process"] = process
        if address:
            finding["address"] = address
        if protection:
            finding["protection"] = protection
            
        # Add hexdump and disassembly if available, keeping only a preview to avoid huge payloads
        if hexdump:
            finding["hexdump"] = "\n".join(hexdump.split('\n')[:3])
        if disasm:
            finding["disassembly"] = "\n".join(disasm.split('\n')[:5])
            
        # Handle optional linux/windows specific fields like mapping or file
        mapping_val = row.get("Mapping", row.get("File", row.get("Name", "")))
        if mapping_val:
            finding["mapping"] = mapping_val
            
        findings.append(finding)
        
    return {
        "finding_count": len(findings),
        "anomalies": findings,
        "anomaly_count": len(findings),
    }
