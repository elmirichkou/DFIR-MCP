import pytest
import mcp_server
import session as case_session
import evidence_store
from unittest.mock import patch

def test_windows_investigate_hidden_missing_prereqs(temp_db, mock_active_session, mock_backend):
    """Verify it returns an error if win_pstree/win_psscan evidence is missing."""
    res = mcp_server.vol_windows_investigate_hidden()
    assert "error" in res
    assert "Prerequisite evidence missing" in res["error"]
    assert mock_backend.call_count == 0  # Verify backend is never called

def test_windows_investigate_hidden_complete(temp_db, mock_active_session, mock_backend):
    """Test correlation with complete evidence (pstree, psscan, netscan, malfind, modules, ssdt)."""
    session_id = mock_active_session.return_value["id"]
    
    # 1. Provide process evidence (999 is hidden: in psscan but not pstree)
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", len(pstree_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", len(psscan_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", psscan_rows)
    
    # 2. Provide network evidence
    net_rows = [{"Pid": 999, "ForeignAddr": "1.1.1.1", "ForeignPort": 4444, "LocalPort": 1234}]
    run_id3 = case_session.record_plugin_run(session_id, "win_netscan", len(net_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "win_netscan", "vol_netscan", net_rows)
    
    # 3. Provide malfind evidence
    malfind_rows = [{"PID": 999, "Process": "evil.exe", "Start VPN": "0x1000", "End VPN": "0x2000", "Protection": "PAGE_EXECUTE_READWRITE"}]
    run_id4 = case_session.record_plugin_run(session_id, "win_malfind", len(malfind_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id4, "win_malfind", "vol_malfind", malfind_rows)

    # 4. Provide modules evidence (correlated by matching name "evil")
    modules_rows = [{"Offset": 0x100000, "Name": "evil_driver.sys", "Base": "0xffd000", "Size": "0x1000", "Path": "C:\\evil.sys"}]
    run_id5 = case_session.record_plugin_run(session_id, "win_modules", len(modules_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id5, "win_modules", "vol_modules", modules_rows)

    # 5. Provide SSDT evidence (correlated by matching name "evil")
    ssdt_rows = [{"Table": "KiServiceTable", "Index": 5, "Offset": 0xfffff800, "Symbol": "evil_driver!HookedFunction"}]
    run_id6 = case_session.record_plugin_run(session_id, "win_ssdt", len(ssdt_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id6, "win_ssdt", "vol_ssdt", ssdt_rows)
    
    res = mcp_server.vol_windows_investigate_hidden()
    
    assert mock_backend.call_count == 0
    assert res["profiled_count"] == 1
    
    profile = res["profiles"][0]
    assert profile["pid"] == 999
    assert profile["process_information"]["name"] == "evil.exe"
    
    # Network correlation
    assert len(profile["network_observations"]["connections"]) == 1
    assert profile["network_observations"]["connections"][0]["foreign_addr"] == "1.1.1.1"
    
    # Malfind correlation
    assert len(profile["memory_injection_observations"]["regions"]) == 1
    assert profile["memory_injection_observations"]["regions"][0]["protection"] == "PAGE_EXECUTE_READWRITE"
    
    # Module correlation (matches "evil" in "evil_driver.sys" vs "evil.exe")
    assert len(profile["kernel_rootkit_observations"]["modules"]) == 1
    assert profile["kernel_rootkit_observations"]["modules"][0]["name"] == "evil_driver.sys"

    # SSDT correlation
    assert len(profile["kernel_rootkit_observations"]["ssdt_entries"]) == 1
    assert profile["kernel_rootkit_observations"]["ssdt_entries"][0]["symbol"] == "evil_driver!HookedFunction"

    # Check evidence ID provenance
    all_evs = evidence_store.search_evidence(session_id)
    assert len(all_evs) == 7 # 1 (pstree) + 2 (psscan) + 1 (netscan) + 1 (malfind) + 1 (modules) + 1 (ssdt)
    
    # Ensure evidence_ids are preserved — psscan(999) + netscan + malfind + module + ssdt = 5
    assert len(profile["evidence_ids"]) == 5
    for ev_id in profile["evidence_ids"]:
        assert ev_id.startswith("ev-")

def test_windows_investigate_hidden_no_additional_evidence(temp_db, mock_active_session, mock_backend):
    """Test correlation with hidden process but no network/malfind/driver evidence."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden", psscan_rows)
    
    res = mcp_server.vol_windows_investigate_hidden()
    assert res["profiled_count"] == 1
    profile = res["profiles"][0]
    
    assert len(profile["network_observations"]["connections"]) == 0
    assert len(profile["memory_injection_observations"]["regions"]) == 0
    assert len(profile["kernel_rootkit_observations"]["modules"]) == 0
    assert len(profile["kernel_rootkit_observations"]["ssdt_entries"]) == 0
    assert "Process unlinking (DKOM) was observed, but no network" in profile["inferred"][0]

def test_windows_investigate_hidden_session_isolation(temp_db, mock_backend):
    """Test correlation isolation across different active sessions."""
    s1 = case_session.create_session("s1", "m1.raw", "windows")
    s2 = case_session.create_session("s2", "m2.raw", "windows")
    
    # Store evidence for s1
    run1 = case_session.record_plugin_run(s1, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(s1, run1, "win_pstree", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}])
    run2 = case_session.record_plugin_run(s1, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(s1, run2, "win_psscan", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}, {"PID": 999, "ImageFileName": "evil.exe"}])
    
    # Store evidence for s2 (no hidden processes)
    run3 = case_session.record_plugin_run(s2, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(s2, run3, "win_pstree", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}])
    run4 = case_session.record_plugin_run(s2, "win_psscan", 1, 0)
    evidence_store.store_plugin_evidence(s2, run4, "win_psscan", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}])
    
    # Active is s2
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": s2, "image": "m2.raw", "os": "windows"}
        res = mcp_server.vol_windows_investigate_hidden()
        
    assert res.get("hidden_count", 0) == 0
