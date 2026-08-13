def analyze(rows: list[dict], evidence_map: dict[str, list[str]] = None) -> dict:
    """
    Filter windows.ssdt.SSDT output.
    Returns observed SSDT entries and separates potential hooks.
    """
    evidence_map = evidence_map or {}
    anomalies = []
    observed = []

    for row in rows:
        table = row.get("Table", "")
        index = row.get("Index")
        offset = row.get("Offset")
        symbol = row.get("Symbol", "")

        # Map to stable identifiers for evidence mapping
        entity_id = str(index) if index is not None else (str(offset) if offset is not None else None)
        ev_ids = evidence_map.get(entity_id, []) if entity_id is not None else []

        entry_info = {
            "table": table,
            "index": index,
            "offset": hex(offset) if isinstance(offset, int) else str(offset),
            "symbol": symbol,
            "evidence_ids": ev_ids
        }
        observed.append(entry_info)

        # Conservative SSDT hook detection heuristic:
        # KiServiceTable (core kernel functions) is expected to point within ntoskrnl.exe
        # W32pServiceTable (GUI functions) is expected to point within win32k.sys
        is_suspicious = False
        reason = ""

        symbol_lower = symbol.lower()
        table_lower = table.lower()

        if symbol:
            if "kiservicetable" in table_lower and "ntoskrnl" not in symbol_lower:
                is_suspicious = True
                reason = f"SSDT entry points to module/symbol '{symbol}' instead of expected 'ntoskrnl'"
            elif "w32pservicetable" in table_lower and "win32k" not in symbol_lower:
                is_suspicious = True
                reason = f"W32pServiceTable entry points to module/symbol '{symbol}' instead of expected 'win32k'"
        else:
            # SSDT entries with no symbol might point to unbacked memory or unexported driver code.
            # While this could be a hook, it might also be a legitimate driver without symbols.
            is_suspicious = True
            reason = "SSDT entry has no resolved symbol (possible hook or unexported module pointer)"

        if is_suspicious:
            anomalies.append({
                **entry_info,
                "detail": reason,
                "type": "potential_ssdt_hook",
                "analyst_note": "This is an indicator of potential SSDT modification, but is not definitive proof. Verify the target offset and cross-reference with loaded drivers."
            })

    return {
        "entry_count": len(rows),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "observed": observed
    }
