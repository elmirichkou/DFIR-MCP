def analyze(rows: list[dict], evidence_map: dict[str, list[str]]) -> dict:
    """
    Filter windows.modules.Modules output.
    Returns normalized observations of loaded kernel modules.
    Does not automatically classify modules as anomalies.
    """
    modules = []
    
    for row in rows:
        offset = row.get("Offset")
        if offset is None:
            entity_id = None
            ev_ids = []
        else:
            entity_id = str(offset)
            ev_ids = evidence_map.get(entity_id, [])
            
        name = row.get("Name", "")
        base = row.get("Base", "")
        size = row.get("Size", "")
        path = row.get("Path", row.get("File", ""))
        
        modules.append({
            "offset": offset,
            "name": name,
            "base_address": base,
            "size": size,
            "path": path,
            "evidence_ids": ev_ids
        })
        
    return {
        "module_count": len(modules),
        "modules": modules,
        "anomaly_count": 0,  # win_modules enumerates normally loaded modules
    }
