"""
dfir-mcp — Volatility 3 memory triage over MCP.

Tools exposed:
  session_create   start a new case against a memory image
  session_status    show the active case, plugins run, findings so far
  vol_pstree         run windows.pstree, return structured summary + anomalies
  vol_netscan        run windows.netscan, return structured summary + anomalies
  vol_timeline       unified chronological timeline from stored evidence
  finding_add        pin an analyst/LLM observation to the case
  finding_list       list pinned findings for the active case

Run with: python mcp_server.py
Requires the execution backend container to be up (see docker-compose.yml).
"""
import functools
import requests
from mcp.server.fastmcp import FastMCP
from filters import correlate as correlate_filter
import backend_client
import evidence_store
import session as case_session
import image_hasher
from pathlib import Path
from filters import hidden_modules as hidden_modules_filter
from filters import hidden_procs as hidden_procs_filter
from filters import linux_pstree as linux_pstree_filter
from filters import linux_sockstat as linux_sockstat_filter
from filters import malfind as malfind_filter
from filters import modules as win_modules_filter
from filters import netscan as win_netscan_filter
from filters import pstree as win_pstree_filter
from filters import ssdt as ssdt_filter
from filters import timeline as timeline_filter

mcp = FastMCP("dfir-mcp")


def _handle_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.ConnectionError:
            return {"error": "Could not connect to the DFIR execution backend. Is the container running?", "status": "unavailable"}
        except requests.exceptions.Timeout:
            return {"error": "Backend execution timed out.", "status": "backend_timeout"}
        except requests.exceptions.HTTPError as e:
            resp = e.response
            status_code = resp.status_code
            try:
                detail = resp.json().get("detail", str(e))
            except Exception:
                detail = resp.text or str(e)
                
            if status_code == 400:
                return {"error": f"Invalid request to backend: {detail}", "status": "invalid_request"}
            elif status_code == 403:
                return {"error": f"Access denied by backend: {detail}", "status": "unauthorized"}
            elif status_code == 404:
                return {"error": f"Resource not found on backend: {detail}", "status": "not_found"}
            elif status_code == 504:
                return {"error": f"Volatility plugin execution timed out: {detail}", "status": "backend_timeout"}
            else:
                return {"error": f"Backend execution failed ({status_code}): {detail}", "status": "backend_error"}
        except ValueError as e:
            # e.g. active session missing, path traversal, auth failure
            return {"error": str(e), "status": "invalid_request"}
        except Exception as e:
            return {"error": f"Internal error: {type(e).__name__}: {str(e)}", "status": "backend_error"}
    return wrapper


def _require_active_session() -> dict:
    active = case_session.get_active_session()
    if not active:
        raise ValueError("No active session. Call session_create first.")
    return active


def _run_plugin_with_evidence(
    session_id: str,
    image: str,
    plugin_key: str,
    tool_name: str,
    extra_args: list[str] | None = None,
) -> tuple[list[dict], int, str, dict[str, list[str]]]:
    """
    Central plugin-execution helper.

    Workflow
    --------
    Cache hit  → return stored rows + evidence map immediately; Volatility
                 is NOT re-invoked.
    Cache miss → run Volatility via backend_client, persist all raw rows to
                 the evidence store, cache the result, return everything.

    Return value
    ------------
    (rows, plugin_run_id, execution_status, entity_evidence_map)

    rows               — original raw Volatility dicts (never mutated)
    plugin_run_id      — SQLite id of the plugin_runs row (int)
    execution_status   — "cached" | "executed"
    entity_evidence_map — entity_id str → [evidence_id …] built from the
                          stored evidence records; empty dict if the plugin
                          has no recognised entity mapping

    Error behaviour
    ---------------
    If backend_client.run_plugin raises (HTTP error, timeout, …) the
    exception propagates unchanged.  No plugin_run row or evidence record
    is written in that case.
    """
    args_hash = evidence_store.hash_args(extra_args or [])
    
    images_dir = Path(__file__).parent.parent / "images"
    image_path = (images_dir / image).resolve()
    if not str(image_path).startswith(str(images_dir.resolve())):
        raise ValueError("Invalid image filename: path traversal detected")
        
    image_sha256 = image_hasher.get_image_hash(image_path)

    # ── Cache hit ────────────────────────────────────────────────────────────
    cached = evidence_store.get_cached_plugin_result(session_id, image, plugin_key, args_hash, image_sha256)
    if cached is not None:
        ev_map = evidence_store.get_entity_evidence_map(session_id, cached["plugin_run_id"])
        return cached["rows"], cached["plugin_run_id"], "cached", ev_map

    # ── Cache miss: execute Volatility ───────────────────────────────────────
    # backend_client.run_plugin raises on any error; nothing is persisted if it does.
    result = backend_client.run_plugin(plugin_key, image, extra_args or [])
    rows: list[dict] = result["rows"]

    # Record the plugin run first (anomaly_count starts at 0; callers may
    # update it via case_session.update_plugin_run_anomaly_count after filtering).
    plugin_run_id: int = case_session.record_plugin_run(
        session_id, plugin_key, result["row_count"], 0
    )

    # Persist raw rows to the evidence store and build the entity map.
    # store_plugin_evidence is idempotent on the same plugin_run_id.
    ev_map = evidence_store.store_plugin_evidence(
        session_id, plugin_run_id, plugin_key, tool_name, rows
    )

    # Cache the raw result so future calls (and vol_investigate_hidden) can
    # skip the Volatility execution entirely.
    evidence_store.store_plugin_cache(
        session_id, image, plugin_key, args_hash, image_sha256, rows, plugin_run_id
    )

    return rows, plugin_run_id, "executed", ev_map


@mcp.tool()
@_handle_errors
def session_create(name: str, image_filename: str, os: str) -> dict:
    """
    Start a new investigation case against a memory image.

    Args:
        name: short human-readable case name, e.g. "phantom-rootkit"
        image_filename: filename of the memory image, must already be
            placed in the project's ./images directory (mounted read-only
            into the backend container)
        os: "linux" or "windows" — determines which Volatility plugins
            and filter heuristics get used for this case
    """
    import os as builtin_os
    from pathlib import Path
    
    # Security: prevent path traversal and ensure the image is strictly within the images/ dir.
    images_dir = Path(__file__).parent.parent / "images"
    image_path = (images_dir / image_filename).resolve()
    
    if not str(image_path).startswith(str(images_dir.resolve())):
        raise ValueError("Invalid image filename: path traversal detected")
        
    session_id = case_session.create_session(name, image_filename, os)
    return {"session_id": session_id, "name": name, "image": image_filename, "os": os}


@mcp.tool()
@_handle_errors
def session_status() -> dict:
    """Show the active case: image, plugins already run, findings pinned so far."""
    active = _require_active_session()
    runs = case_session.list_plugin_runs(active["id"])
    findings = case_session.list_findings(active["id"])
    return {
        "session": active,
        "plugin_runs": runs,
        "findings": findings,
    }


@mcp.tool()
@_handle_errors
def vol_pstree() -> dict:
    """
    Run the process-tree plugin (windows.pstree or linux.pstree,
    depending on the active case's OS) against the memory image.
    Returns a structured process count plus a short list of flagged
    anomalies (unresolved parents, unexpected lineage, duplicate PIDs)
    rather than the full raw process tree.
    """
    active = _require_active_session()
    session_id = active["id"]
    image = active["image"]

    if active["os"] == "windows":
        rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
            session_id, image, "win_pstree", "vol_pstree"
        )
        analysis = win_pstree_filter.analyze(rows, ev_map)
    else:
        rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
            session_id, image, "linux_pstree", "vol_pstree"
        )
        analysis = linux_pstree_filter.analyze(rows, ev_map)

    case_session.update_plugin_run_anomaly_count(run_id, analysis["anomaly_count"])
    return {**analysis, "execution_status": exec_status}


@mcp.tool()
@_handle_errors
def vol_netscan() -> dict:
    """
    Run the network-connection plugin (windows.netscan or
    linux.sockstat, depending on the active case's OS) against the
    memory image. Returns connection count plus flagged anomalies
    (suspicious ports, processes not normally expected to make network
    connections) rather than the full raw connection table.
    """
    active = _require_active_session()
    session_id = active["id"]
    image = active["image"]

    if active["os"] == "windows":
        rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
            session_id, image, "win_netscan", "vol_netscan"
        )
        analysis = win_netscan_filter.analyze(rows, ev_map)
    else:
        rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
            session_id, image, "linux_sockstat", "vol_netscan"
        )
        analysis = linux_sockstat_filter.analyze(rows, ev_map)

    case_session.update_plugin_run_anomaly_count(run_id, analysis["anomaly_count"])
    return {**analysis, "execution_status": exec_status}


@mcp.tool()
@_handle_errors
def vol_malfind() -> dict:
    """
    Run the malfind plugin (windows.malfind.Malfind or linux.malfind.Malfind)
    to identify potentially injected or unbacked executable memory regions.
    Returns conservative observations without declaring definitive malware.
    """
    active = _require_active_session()
    session_id = active["id"]
    image = active["image"]
    os_type = active["os"]

    if os_type == "windows":
        plugin_key = "win_malfind"
    elif os_type == "linux":
        plugin_key = "linux_malfind"
    else:
        raise ValueError(f"vol_malfind is not implemented for os: {os_type}")

    rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
        session_id, image, plugin_key, "vol_malfind"
    )

    analysis = malfind_filter.analyze(rows, ev_map)
    case_session.update_plugin_run_anomaly_count(run_id, analysis["anomaly_count"])

    return {**analysis, "execution_status": exec_status}


@mcp.tool()
@_handle_errors
def vol_modules() -> dict:
    """
    Run the windows.modules.Modules plugin to enumerate loaded kernel modules.
    Only supported for Windows cases.
    """
    active = _require_active_session()
    os_type = active["os"]

    if os_type != "windows":
        raise ValueError(f"vol_modules is only implemented for Windows OS, got: {os_type}")

    session_id = active["id"]
    image = active["image"]

    rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
        session_id, image, "win_modules", "vol_modules"
    )

    analysis = win_modules_filter.analyze(rows, ev_map)
    case_session.update_plugin_run_anomaly_count(run_id, analysis["anomaly_count"])

    return {**analysis, "execution_status": exec_status}


@mcp.tool()
@_handle_errors
def vol_ssdt() -> dict:
    """
    Run the windows.ssdt.SSDT plugin to analyze the System Service Descriptor Table.
    Only supported for Windows cases.
    """
    active = _require_active_session()
    os_type = active["os"]

    if os_type != "windows":
        raise ValueError(f"vol_ssdt is only implemented for Windows OS, got: {os_type}")

    session_id = active["id"]
    image = active["image"]

    rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
        session_id, image, "win_ssdt", "vol_ssdt"
    )

    analysis = ssdt_filter.analyze(rows, ev_map)
    case_session.update_plugin_run_anomaly_count(run_id, analysis["anomaly_count"])

    return {**analysis, "execution_status": exec_status}



@mcp.tool()
@_handle_errors
def vol_bash() -> dict:
    """
    Run the linux.bash plugin to extract bash history from memory.
    Only supported for Linux cases.
    """
    active = _require_active_session()
    if active["os"] != "linux":
        raise ValueError("vol_bash is only implemented for linux cases")

    session_id = active["id"]
    image = active["image"]

    rows, run_id, exec_status, ev_map = _run_plugin_with_evidence(
        session_id, image, "linux_bash", "vol_bash"
    )

    # We do not have a dedicated bash anomaly filter, so we simply record
    # the run and return the command count. Evidence is preserved for correlation.
    case_session.update_plugin_run_anomaly_count(run_id, 0)

    return {
        "command_count": len(rows),
        "execution_status": exec_status
    }



@mcp.tool()
@_handle_errors
def vol_hidden_processes() -> dict:
    """
    Cross-reference the linked-list process walk (pslist/pstree) against
    a direct memory pool scan (psscan) to catch DKOM-hidden processes —
    a rootkit that unlinks itself from the process list a normal walk
    follows will still be visible to a pool scan. Any PID present in the
    scan but missing from the walk is flagged as likely hidden.
    """
    active = _require_active_session()
    session_id = active["id"]
    image = active["image"]

    if active["os"] == "windows":
        walk_plugin = "win_pstree"
        scan_plugin = "win_psscan"
    else:
        walk_plugin = "linux_pslist"
        scan_plugin = "linux_psscan"

    walk_rows, walk_run_id, walk_status, _ = _run_plugin_with_evidence(
        session_id, image, walk_plugin, "vol_hidden_processes"
    )
    scan_rows, scan_run_id, scan_status, scan_ev_map = _run_plugin_with_evidence(
        session_id, image, scan_plugin, "vol_hidden_processes"
    )

    analysis = hidden_procs_filter.analyze(
        walk_rows, scan_rows, psscan_evidence_map=scan_ev_map
    )

    # The pool scan is what reveals the hidden processes (they are present in the
    # scan but missing from the walk), so we attribute these anomalies to the scan run.
    case_session.update_plugin_run_anomaly_count(scan_run_id, analysis["hidden_count"])

    return {
        **analysis,
        "execution_status": {
            walk_plugin: walk_status,
            scan_plugin: scan_status,
        }
    }


@mcp.tool()
@_handle_errors
def vol_hidden_modules() -> dict:
    """
    Cross-reference the kernel module list (lsmod) against
    linux.check_modules to catch a self-hiding rootkit kernel module —
    the same technique used to uncover a hidden module in prior
    Sherlock-style memory forensics work. Linux cases only for now.
    """
    active = _require_active_session()
    if active["os"] != "linux":
        raise ValueError("vol_hidden_modules is currently only implemented for linux cases")
    
    session_id = active["id"]
    image = active["image"]
    
    lsmod_rows, lsmod_run_id, lsmod_status, _ = _run_plugin_with_evidence(
        session_id, image, "linux_lsmod", "vol_hidden_modules"
    )
    
    check_rows, check_run_id, check_status, check_ev_map = _run_plugin_with_evidence(
        session_id, image, "linux_check_modules", "vol_hidden_modules"
    )
    
    analysis = hidden_modules_filter.analyze(
        lsmod_rows, check_rows, check_modules_evidence_map=check_ev_map
    )
    
    # Assign the anomalies to the check_modules run, since it provides the actual flagged evidence.
    case_session.update_plugin_run_anomaly_count(check_run_id, analysis["flagged_count"])
    
    return {
        **analysis,
        "execution_status": {
            "linux_lsmod": lsmod_status,
            "linux_check_modules": check_status
        }
    }
@mcp.tool()
@_handle_errors
def vol_investigate_hidden() -> dict:
    """
    Investigates DKOM-hidden processes using ONLY existing stored evidence.
    Correlates hidden processes (found via pslist vs psscan discrepancy)
    with their stored network connections and bash history.
    Does not execute Volatility plugins directly; requires prerequisite evidence.
    """
    active = _require_active_session()
    if active["os"] != "linux":
        raise ValueError("vol_investigate_hidden is currently only implemented for linux cases")

    session_id = active["id"]

    # 1. Fetch prerequisite process evidence
    pslist_ev = evidence_store.search_evidence(session_id, plugin="linux_pslist")
    psscan_ev = evidence_store.search_evidence(session_id, plugin="linux_psscan")

    if not pslist_ev or not psscan_ev:
        return {
            "error": "Prerequisite evidence missing",
            "missing_evidence": [
                "linux_pslist (or equivalent)" if not pslist_ev else None,
                "linux_psscan (or equivalent)" if not psscan_ev else None
            ]
        }

    # 2. Re-discover hidden PIDs using existing evidence
    walk_rows = [e["raw"] for e in pslist_ev]
    scan_rows = [e["raw"] for e in psscan_ev]
    
    scan_ev_map = {}
    for e in psscan_ev:
        if e.get("entity_id"):
            scan_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])

    hidden = hidden_procs_filter.analyze(walk_rows, scan_rows, psscan_evidence_map=scan_ev_map)
    hidden_anomalies = hidden["anomalies"]

    if not hidden_anomalies:
        return {"hidden_count": 0, "profiles": [], "note": "No hidden processes found in the existing evidence."}

    # Fetch all potential correlation evidence for the session once
    network_ev = evidence_store.search_evidence(session_id, evidence_type="network_connection")
    bash_ev_all = evidence_store.search_evidence(session_id, plugin="linux_bash")
    bash_available = len(bash_ev_all) > 0

    profiles = []

    for anomaly in hidden_anomalies:
        pid = anomaly["pid"]
        pid_str = str(pid)

        # Process correlation
        process_info = {
            "name": anomaly["process"],
            "pid": pid,
            "ppid": anomaly["ppid"],
            "plugin_source": "linux_psscan",
            "evidence_ids": anomaly.get("evidence_ids", []),
        }

        # Network correlation
        net_conns = []
        net_ev_ids = []
        for e in network_ev:
            raw = e["raw"]
            # Match on entity_id or raw PID fields
            if e.get("entity_id") == pid_str or str(raw.get("Pid", "")) == pid_str or str(raw.get("PID", "")) == pid_str:
                net_conns.append({
                    "local_addr": correlate_filter._get(raw, "Source Addr", "SourceAddr", "Local Addr", "LocalAddr", default=""),
                    "local_port": correlate_filter._get(raw, "Source Port", "SourcePort", "Local Port", "LocalPort", default=""),
                    "remote_addr": correlate_filter._get(raw, "Destination Addr", "DestAddr", "Foreign Addr", default=""),
                    "remote_port": correlate_filter._get(raw, "Destination Port", "DestPort", "Foreign Port", default=""),
                    "protocol": correlate_filter._get(raw, "Protocol", "Proto", default=""),
                    "state": correlate_filter._get(raw, "State", default=""),
                })
                net_ev_ids.append(e["evidence_id"])

        # Bash correlation
        bash_cmds = []
        bash_ev_ids = []
        if bash_available:
            for e in bash_ev_all:
                raw = e["raw"]
                if e.get("entity_id") == pid_str or str(raw.get("Pid", "")) == pid_str or str(raw.get("PID", "")) == pid_str:
                    bash_cmds.append({
                        "command": correlate_filter._get(raw, "Command", "CommandLine", default=""),
                        "time": correlate_filter._get(raw, "CommandTime", "Command Time", default=""),
                    })
                    bash_ev_ids.append(e["evidence_id"])

        # Narrative generation
        observed = [f"PID {pid} appears in psscan evidence but is missing from the active process list (pslist)."]
        if net_conns:
            observed.append(f"PID {pid} has {len(net_conns)} network connection(s) recorded in evidence.")
        if bash_available and bash_cmds:
            observed.append(f"PID {pid} has {len(bash_cmds)} bash command(s) recorded in evidence.")
        elif not bash_available:
            observed.append("Bash history evidence is not available in the current session store.")
            
        inferred = []
        if net_conns or bash_cmds:
            inferred.append("The combination of DKOM unlinking and recorded network/bash activity strongly warrants further investigation.")
        else:
            inferred.append("DKOM unlinking was observed, but no network or bash activity was found in the stored evidence.")

        profiles.append({
            "pid": pid,
            "process": process_info,
            "network": {
                "connections": net_conns,
                "evidence_ids": net_ev_ids,
            },
            "bash": {
                "available": bash_available,
                "commands": bash_cmds,
                "evidence_ids": bash_ev_ids,
            },
            "narrative": {
                "observed": observed,
                "inferred": inferred,
            }
        })

    return {
        "profiled_count": len(profiles),
        "profiles": profiles
    }


@mcp.tool()
@_handle_errors
def vol_windows_investigate_hidden() -> dict:
    """
    Investigates Windows DKOM-hidden processes using ONLY existing stored evidence.
    Correlates hidden processes (found via win_pstree vs win_psscan discrepancy)
    with their stored network connections, malfind regions, kernel modules, and SSDT hooks.
    Does not execute Volatility plugins directly; requires prerequisite evidence.
    """
    active = _require_active_session()
    if active["os"] != "windows":
        raise ValueError("vol_windows_investigate_hidden is only implemented for Windows cases")

    session_id = active["id"]

    # 1. Fetch prerequisite process evidence
    pstree_ev = evidence_store.search_evidence(session_id, plugin="win_pstree")
    psscan_ev = evidence_store.search_evidence(session_id, plugin="win_psscan")

    if not pstree_ev or not psscan_ev:
        return {
            "error": "Prerequisite evidence missing",
            "missing_evidence": [
                "win_pstree" if not pstree_ev else None,
                "win_psscan" if not psscan_ev else None
            ]
        }

    # 2. Re-discover hidden PIDs using existing evidence
    walk_rows = [e["raw"] for e in pstree_ev]
    scan_rows = [e["raw"] for e in psscan_ev]

    scan_ev_map = {}
    for e in psscan_ev:
        if e.get("entity_id"):
            scan_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])

    hidden = hidden_procs_filter.analyze(walk_rows, scan_rows, psscan_evidence_map=scan_ev_map)
    hidden_anomalies = hidden["anomalies"]

    if not hidden_anomalies:
        return {"hidden_count": 0, "profiles": [], "note": "No hidden processes found in the existing evidence."}

    # Fetch optional evidence for the session once
    network_ev = evidence_store.search_evidence(session_id, plugin="win_netscan")
    malfind_ev = evidence_store.search_evidence(session_id, plugin="win_malfind")
    modules_ev = evidence_store.search_evidence(session_id, plugin="win_modules")
    ssdt_ev = evidence_store.search_evidence(session_id, plugin="win_ssdt")

    profiles = []

    for anomaly in hidden_anomalies:
        pid = anomaly["pid"]
        pid_str = str(pid)
        process_name = anomaly["process"]
        process_name_lower = process_name.lower() if process_name else ""

        # Process correlation
        process_info = {
            "name": process_name,
            "pid": pid,
            "ppid": anomaly["ppid"],
            "plugin_source": "win_psscan",
            "evidence_ids": anomaly.get("evidence_ids", []),
        }

        # Combine all evidence IDs associated with this profile
        all_profile_ev_ids = list(anomaly.get("evidence_ids", []))

        # Network correlation
        net_conns = []
        net_ev_ids = []
        for e in network_ev:
            raw = e["raw"]
            if e.get("entity_id") == pid_str or str(raw.get("Pid", "")) == pid_str or str(raw.get("PID", "")) == pid_str:
                net_conns.append({
                    "local_port": correlate_filter._get(raw, "LocalPort", "Local Port", default=""),
                    "foreign_addr": correlate_filter._get(raw, "ForeignAddr", "Foreign Addr", default=""),
                    "foreign_port": correlate_filter._get(raw, "ForeignPort", "Foreign Port", default=""),
                    "state": correlate_filter._get(raw, "State", default=""),
                })
                net_ev_ids.append(e["evidence_id"])
                all_profile_ev_ids.append(e["evidence_id"])

        # Malfind correlation
        malfind_regions = []
        malfind_ev_ids = []
        for e in malfind_ev:
            raw = e["raw"]
            if e.get("entity_id") == pid_str or str(raw.get("Pid", "")) == pid_str or str(raw.get("PID", "")) == pid_str:
                malfind_regions.append({
                    "start_vpn": correlate_filter._get(raw, "Start VPN", default=""),
                    "end_vpn": correlate_filter._get(raw, "End VPN", default=""),
                    "protection": correlate_filter._get(raw, "Protection", default=""),
                })
                malfind_ev_ids.append(e["evidence_id"])
                all_profile_ev_ids.append(e["evidence_id"])

        # Modules correlation (where entity mapping permits: match driver/module name to process name, if any)
        correlated_modules = []
        modules_ev_ids = []
        process_stem = process_name_lower.split(".")[0] if process_name_lower else ""
        for e in modules_ev:
            raw = e["raw"]
            mod_name = correlate_filter._get(raw, "Name", default="")
            mod_name_lower = mod_name.lower() if mod_name else ""
            if mod_name_lower and process_stem and (process_stem in mod_name_lower or mod_name_lower.split(".")[0] in process_stem):
                correlated_modules.append({
                    "name": mod_name,
                    "base": correlate_filter._get(raw, "Base", default=""),
                    "size": correlate_filter._get(raw, "Size", default=""),
                    "path": correlate_filter._get(raw, "Path", "File", default=""),
                })
                modules_ev_ids.append(e["evidence_id"])
                all_profile_ev_ids.append(e["evidence_id"])

        # SSDT correlation (where entity mapping permits: check if SSDT symbol contains process/module name)
        correlated_ssdt = []
        ssdt_ev_ids = []
        for e in ssdt_ev:
            raw = e["raw"]
            symbol = correlate_filter._get(raw, "Symbol", default="")
            symbol_lower = symbol.lower() if symbol else ""
            if process_name_lower and symbol_lower and process_name_lower.split(".")[0] in symbol_lower:
                correlated_ssdt.append({
                    "table": correlate_filter._get(raw, "Table", default=""),
                    "index": correlate_filter._get(raw, "Index", default=""),
                    "symbol": symbol,
                })
                ssdt_ev_ids.append(e["evidence_id"])
                all_profile_ev_ids.append(e["evidence_id"])

        # Narrative generation
        observed = [f"PID {pid} ({process_name}) appears in psscan but not pstree."]
        if net_conns:
            observed.append(f"PID {pid} has {len(net_conns)} network connection(s) recorded in evidence.")
        if malfind_regions:
            observed.append(f"PID {pid} has {len(malfind_regions)} suspicious memory region(s) detected by malfind.")
        if correlated_modules:
            observed.append(f"PID {pid} correlates to {len(correlated_modules)} kernel module(s) in evidence.")
        if correlated_ssdt:
            observed.append(f"PID {pid} correlates to {len(correlated_ssdt)} SSDT entry/hook(s) in evidence.")

        inferred = []
        if net_conns or malfind_regions or correlated_modules or correlated_ssdt:
            inferred.append("The combination of process unlinking with active network connections, injected memory regions, or driver hook presence strongly warrants further investigation.")
        else:
            inferred.append("Process unlinking (DKOM) was observed, but no network connections, malfind regions, or driver correlations were found in the stored evidence.")

        profiles.append({
            "pid": pid,
            "process_information": process_info,
            "network_observations": {
                "connections": net_conns,
                "evidence_ids": net_ev_ids,
            },
            "memory_injection_observations": {
                "regions": malfind_regions,
                "evidence_ids": malfind_ev_ids,
            },
            "kernel_rootkit_observations": {
                "modules": correlated_modules,
                "ssdt_entries": correlated_ssdt,
                "module_evidence_ids": modules_ev_ids,
                "ssdt_evidence_ids": ssdt_ev_ids,
            },
            "evidence_ids": list(set(all_profile_ev_ids)),
            "observed": observed,
            "inferred": inferred,
        })

    return {
        "profiled_count": len(profiles),
        "profiles": profiles
    }

@mcp.tool()
@_handle_errors
def finding_add(note: str, source: str = "") -> dict:
    """
    Pin an observation to the active case's findings log — use this to
    record conclusions worth keeping as the investigation progresses.

    Args:
        note: the observation, in plain language
        source: optional pointer to what produced it, e.g. "vol_pstree PID 4821"
    """
    active = _require_active_session()
    finding_id = case_session.add_finding(active["id"], note, source or None)
    return {"finding_id": finding_id, "note": note, "source": source}


@mcp.tool()
@_handle_errors
def finding_list() -> dict:
    """List all findings pinned to the active case, in the order they were added."""
    active = _require_active_session()
    return {"findings": case_session.list_findings(active["id"])}


@mcp.tool()
@_handle_errors
def evidence_get(evidence_id: str) -> dict:
    """
    Retrieve a complete evidence record by its ID.
    Includes the raw Volatility record, evidence provenance, and session metadata.
    """
    active = _require_active_session()
    
    record = evidence_store.get_evidence(evidence_id)
    if record is None or record.get("session_id") != active["id"]:
        return {"error": f"Evidence record not found: {evidence_id}", "status": "not_found"}
    return record


@mcp.tool()
@_handle_errors
def evidence_search(
    entity_type: str | None = None,
    entity_id: str | None = None,
    evidence_type: str | None = None,
    plugin: str | None = None,
    session_id: str | None = None,
    limit: int = 500,
) -> dict:
    """
    Search for evidence records matching the given filters.
    If session_id is omitted, searches the active case's session.
    Returns matched evidence records including their full raw Volatility output.
    """
    active = _require_active_session()
    
    if session_id is not None and session_id != active["id"]:
        return {
            "error": "Authorization error: supplied session_id does not match active session.",
            "status": "unauthorized"
        }
        
    target_session = active["id"]
    
    records = evidence_store.search_evidence(
        target_session,
        entity_type=entity_type,
        entity_id=entity_id,
        evidence_type=evidence_type,
        plugin=plugin,
        limit=limit,
    )
    
    return {
        "session_id": target_session,
        "match_count": len(records),
        "records": records,
    }


@mcp.tool()
@_handle_errors
def vol_timeline(
    entity_id: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 200,
) -> dict:
    """
    Build a unified chronological timeline from evidence already stored
    in the active investigation session.  Does NOT execute any Volatility
    plugins — it reads only from the evidence ledger.

    Use this after running acquisition tools (vol_pstree, vol_netscan,
    etc.) to see a combined, time-ordered view of everything collected
    so far.

    Args:
        entity_id:  optional PID or entity filter — only events for this
                    entity are returned
        start_time: optional ISO-8601 lower bound (inclusive)
        end_time:   optional ISO-8601 upper bound (inclusive)
        limit:      maximum events returned (default 200)
    """
    active = _require_active_session()
    session_id = active["id"]

    # Fetch all evidence for this session in a single query.
    records = evidence_store.search_evidence(
        session_id,
        entity_id=entity_id,
        limit=10000,  # fetch generously; timeline_filter.build_timeline applies its own limit
    )

    result = timeline_filter.build_timeline(
        records,
        entity_id=entity_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )

    return result


@mcp.tool()
@_handle_errors
def vol_report() -> dict:
    """
    Generate a structured DFIR investigation report from the active session's
    stored evidence, findings, plugin runs, and timeline.
    Does NOT execute any Volatility plugins.
    Every claim in the report is backed by evidence IDs or findings records.
    """
    active = _require_active_session()
    session_id = active["id"]

    # ── 1. Session metadata ──────────────────────────────────────────────────
    session_info = {
        "session_id": session_id,
        "case_name": active.get("name", ""),
        "memory_image": active.get("image", ""),
        "os": active.get("os", ""),
        "created_at": active.get("created_at", ""),
    }

    # ── 2. Plugin execution summary ──────────────────────────────────────────
    plugin_runs = case_session.list_plugin_runs(session_id)
    plugins_executed = [
        {
            "plugin": r["plugin"],
            "row_count": r["row_count"],
            "anomaly_count": r["anomaly_count"],
            "ran_at": r["ran_at"],
        }
        for r in plugin_runs
    ]
    total_anomalies = sum(r["anomaly_count"] for r in plugin_runs)

    # ── 3. Analyst findings ──────────────────────────────────────────────────
    findings_raw = case_session.list_findings(session_id)
    analyst_findings = [
        {
            "id": f["id"],
            "note": f["note"],
            "source": f.get("source"),
            "created_at": f["created_at"],
        }
        for f in findings_raw
    ]

    # ── 4. Evidence summary by category ──────────────────────────────────────
    all_evidence = evidence_store.search_evidence(session_id, limit=10000)
    total_evidence_records = len(all_evidence)

    # ── 5. Suspicious process indicators ─────────────────────────────────────
    # Re-derive hidden processes from stored evidence (no plugin execution)
    pstree_ev = evidence_store.search_evidence(session_id, plugin="win_pstree")
    psscan_ev = evidence_store.search_evidence(session_id, plugin="win_psscan")
    pslist_ev = evidence_store.search_evidence(session_id, plugin="linux_pslist")
    linux_psscan_ev = evidence_store.search_evidence(session_id, plugin="linux_psscan")

    suspicious_processes = []

    # Windows hidden processes
    if pstree_ev and psscan_ev:
        walk_rows = [e["raw"] for e in pstree_ev]
        scan_rows = [e["raw"] for e in psscan_ev]
        scan_ev_map = {}
        for e in psscan_ev:
            if e.get("entity_id"):
                scan_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])
        hidden = hidden_procs_filter.analyze(walk_rows, scan_rows, psscan_evidence_map=scan_ev_map)
        for a in hidden.get("anomalies", []):
            suspicious_processes.append({
                "pid": a["pid"],
                "name": a["process"],
                "ppid": a["ppid"],
                "reason": "present in psscan but absent from pstree (potential DKOM unlinking)",
                "evidence_ids": a.get("evidence_ids", []),
                "observed": True,
            })

    # Linux hidden processes
    if pslist_ev and linux_psscan_ev:
        walk_rows = [e["raw"] for e in pslist_ev]
        scan_rows = [e["raw"] for e in linux_psscan_ev]
        scan_ev_map = {}
        for e in linux_psscan_ev:
            if e.get("entity_id"):
                scan_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])
        hidden = hidden_procs_filter.analyze(walk_rows, scan_rows, psscan_evidence_map=scan_ev_map)
        for a in hidden.get("anomalies", []):
            suspicious_processes.append({
                "pid": a["pid"],
                "name": a["process"],
                "ppid": a["ppid"],
                "reason": "present in psscan but absent from pslist (potential DKOM unlinking)",
                "evidence_ids": a.get("evidence_ids", []),
                "observed": True,
            })

    # ── 6. Network indicators ─────────────────────────────────────────────────
    netscan_ev = evidence_store.search_evidence(session_id, plugin="win_netscan")
    sockstat_ev = evidence_store.search_evidence(session_id, plugin="linux_sockstat")
    all_net_ev = netscan_ev + sockstat_ev

    network_indicators = []
    if all_net_ev:
        net_rows = [e["raw"] for e in all_net_ev]
        combined_ev_map = {}
        for e in all_net_ev:
            if e.get("entity_id"):
                combined_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])
        net_analysis = win_netscan_filter.analyze(net_rows, combined_ev_map)
        for a in net_analysis.get("anomalies", []):
            network_indicators.append({
                "type": a.get("type"),
                "detail": a.get("detail"),
                "evidence_ids": a.get("evidence_ids", []),
            })
    net_available = len(all_net_ev) > 0

    # ── 7. Memory / injection indicators (malfind) ────────────────────────────
    malfind_ev = evidence_store.search_evidence(session_id, evidence_type="malware_indicator")
    injection_indicators = []
    for e in malfind_ev:
        raw = e["raw"]
        injection_indicators.append({
            "pid": raw.get("PID") or raw.get("Pid"),
            "process": raw.get("Process") or raw.get("ImageFileName") or raw.get("COMM"),
            "protection": raw.get("Protection", ""),
            "evidence_id": e["evidence_id"],
            "analyst_note": "Unbacked executable memory region detected. Requires manual triage — may be JIT or legitimate driver activity.",
        })
    malfind_available = len(malfind_ev) > 0

    # ── 8. Kernel / rootkit indicators (modules + SSDT) ───────────────────────
    kernel_indicators = []

    # Hidden kernel modules (linux)
    lsmod_ev = evidence_store.search_evidence(session_id, plugin="linux_lsmod")
    check_modules_ev = evidence_store.search_evidence(session_id, plugin="linux_check_modules")
    if lsmod_ev and check_modules_ev:
        lsmod_rows = [e["raw"] for e in lsmod_ev]
        check_rows = [e["raw"] for e in check_modules_ev]
        check_ev_map = {}
        for e in check_modules_ev:
            if e.get("entity_id"):
                check_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])
        mod_analysis = hidden_modules_filter.analyze(lsmod_rows, check_rows, check_modules_evidence_map=check_ev_map)
        for f in mod_analysis.get("flagged", []):
            kernel_indicators.append({
                "type": "hidden_kernel_module",
                "module": f.get("module"),
                "detail": f.get("detail", ""),
                "evidence_ids": f.get("evidence_ids", []),
            })

    # Windows SSDT hooks
    ssdt_ev = evidence_store.search_evidence(session_id, plugin="win_ssdt")
    if ssdt_ev:
        ssdt_rows = [e["raw"] for e in ssdt_ev]
        ssdt_ev_map = {}
        for e in ssdt_ev:
            if e.get("entity_id"):
                ssdt_ev_map.setdefault(e["entity_id"], []).append(e["evidence_id"])
        ssdt_analysis = ssdt_filter.analyze(ssdt_rows, ssdt_ev_map)
        for a in ssdt_analysis.get("anomalies", []):
            kernel_indicators.append({
                "type": "ssdt_hook",
                "symbol": a.get("symbol"),
                "detail": a.get("detail", ""),
                "analyst_note": a.get("analyst_note", ""),
                "evidence_ids": a.get("evidence_ids", []),
            })

    # ── 9. Timeline summary ────────────────────────────────────────────────────
    timeline_result = timeline_filter.build_timeline(all_evidence, limit=20)
    timeline_events = timeline_result.get("events", [])
    timeline_available = timeline_result.get("event_count", 0) > 0

    # ── 10. Data availability checklist ──────────────────────────────────────
    availability = {
        "process_listing": bool(pstree_ev or pslist_ev),
        "process_scan": bool(psscan_ev or linux_psscan_ev),
        "network_connections": net_available,
        "memory_injection_scan": malfind_available,
        "kernel_modules": bool(lsmod_ev or ssdt_ev),
        "analyst_findings": bool(analyst_findings),
        "timeline": timeline_available,
    }

    # ── 11. Limitations notice ────────────────────────────────────────────────
    limitations = [
        "This report is derived entirely from stored evidence in the current session. "
        "It does not reflect a live system state.",
        "Injection indicators (malfind) require manual analyst triage to distinguish "
        "legitimate JIT/security software from genuine malware.",
        "SSDT hook detection may produce false positives for security products and EDR agents.",
        "Hidden process detection compares list-walk vs pool-scan; advanced kernel manipulations "
        "that tamper with both may evade this heuristic.",
        "No attacker attribution is made in this report.",
    ]
    if not availability["process_scan"]:
        limitations.append("No memory pool scan evidence is available. Hidden process detection was not performed.")
    if not availability["network_connections"]:
        limitations.append("No network evidence is available. Network indicators could not be assessed.")

    return {
        "report_version": "1.0",
        "session": session_info,
        "execution_summary": {
            "plugins_executed": plugins_executed,
            "total_evidence_records": total_evidence_records,
            "total_anomalies_flagged": total_anomalies,
        },
        "analyst_findings": analyst_findings,
        "suspicious_processes": suspicious_processes,
        "network_indicators": network_indicators,
        "injection_indicators": injection_indicators,
        "kernel_rootkit_indicators": kernel_indicators,
        "timeline_preview": timeline_events,
        "data_availability": availability,
        "limitations": limitations,
        "provenance_note": (
            "Every indicator above contains evidence_ids linking back to the raw "
            "Volatility records in the evidence store. Use evidence_get(evidence_id) "
            "to retrieve full raw records."
        ),
    }


if __name__ == "__main__":
    mcp.run()
