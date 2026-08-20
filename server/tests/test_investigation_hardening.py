import pytest
import mcp_server
import session as case_session
import evidence_store
from unittest.mock import patch

# --- LINUX TESTS ---

def test_linux_hidden_pid_detection(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 1, 3: Linux hidden PID detection & Correlation accuracy."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["profiled_count"] == 1
    assert res["profiles"][0]["pid"] == 999
    
def test_linux_malfind_correlation(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 7: Linux malfind correlation."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    malfind_rows = [{"PID": 999, "Process": "evil", "Start VPN": "0x1000", "End VPN": "0x2000", "Protection": "rwx"}]
    run_id3 = case_session.record_plugin_run(session_id, "linux_malfind", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "linux_malfind", "vol_malfind", malfind_rows)
    
    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["profiled_count"] == 1
    assert len(res["profiles"][0]["memory_injection_observations"]["regions"]) == 1
    assert res["profiles"][0]["memory_injection_observations"]["regions"][0]["protection"] == "rwx"

def test_linux_network_correlation(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 8: Linux network correlation."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    net_rows = [{"Pid": 999, "Destination Addr": "1.1.1.1", "Destination Port": 80, "Source Port": 123}]
    run_id3 = case_session.record_plugin_run(session_id, "linux_sockstat", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "linux_sockstat", "vol_netscan", net_rows)
    
    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert len(res["profiles"][0]["network"]["connections"]) == 1
    assert res["profiles"][0]["network"]["connections"][0]["remote_addr"] == "1.1.1.1"

def test_linux_bash_correlation(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 3: Linux bash correlation."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    bash_rows = [{"Pid": 999, "Command": "curl -O malware.sh", "CommandTime": "2026-08-13"}]
    run_id4 = case_session.record_plugin_run(session_id, "linux_bash", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id4, "linux_bash", "vol_bash", bash_rows)
    
    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert len(res["profiles"][0]["bash"]["commands"]) == 1
    assert res["profiles"][0]["bash"]["commands"][0]["command"] == "curl -O malware.sh"

def test_linux_missing_evidence_categories(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 5: Linux missing evidence categories."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["data_availability"]["network"] == False
    assert res["data_availability"]["bash"] == False
    assert res["data_availability"]["malfind"] == False

def test_linux_data_availability_metadata(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 5: Linux data_availability metadata."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    net_rows = [{"Pid": 999, "Destination Addr": "1.1.1.1", "Destination Port": 80, "Source Port": 123}]
    run_id3 = case_session.record_plugin_run(session_id, "linux_sockstat", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "linux_sockstat", "vol_netscan", net_rows)

    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["data_availability"]["network"] == True
    assert res["data_availability"]["bash"] == False
    assert res["data_availability"]["malfind"] == False

def test_linux_empty_case(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 12: Linux empty case."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["pslist"]) # using pslist to simulate no hidden
    
    res = mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["hidden_count"] == 0
    assert res["profiles"] == []
    assert res["data_availability"]["network"] == False

def test_linux_session_isolation(temp_db, mock_backend, sample_volatility_rows):
    """Req 2: Linux session isolation."""
    s1 = case_session.create_session("s1", "m1.raw", "linux")
    s2 = case_session.create_session("s2", "m2.raw", "linux")
    
    # Store evidence for s1 (hidden)
    run1 = case_session.record_plugin_run(s1, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(s1, run1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run2 = case_session.record_plugin_run(s1, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(s1, run2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    # Store evidence for s2 (no hidden)
    run3 = case_session.record_plugin_run(s2, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(s2, run3, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run4 = case_session.record_plugin_run(s2, "linux_psscan", 2, 0)
    evidence_store.store_plugin_evidence(s2, run4, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["pslist"])
    
    # Active is s2
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": s2, "image": "m2.raw", "os": "linux"}
        res = mcp_server.vol_investigate_hidden()
        
    assert res.get("hidden_count", 0) == 0

def test_linux_backend_never_called(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 1: Linux backend never called."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    mcp_server.vol_investigate_hidden()
    assert mock_backend.call_count == 0

def test_linux_evidence_get_provenance(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 6: Linux evidence_get provenance."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    res = mcp_server.vol_investigate_hidden()
    profile = res["profiles"][0]
    ev_ids = profile["evidence_ids"]
    assert len(ev_ids) > 0
    for ev_id in ev_ids:
        record = mcp_server.evidence_get(ev_id)
        assert record.get("evidence_id") == ev_id

def test_linux_deterministic_output(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 10: Linux deterministic output."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    res1 = mcp_server.vol_investigate_hidden()
    res2 = mcp_server.vol_investigate_hidden()
    assert res1 == res2

def test_linux_duplicate_prevention(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Req 11: Linux duplicate prevention."""
    session_id = mock_active_linux_session.return_value["id"]
    run_id1 = case_session.record_plugin_run(session_id, "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(session_id, "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    net_rows = [{"Pid": 999, "Destination Addr": "1.1.1.1", "Destination Port": 80, "Source Port": 123}]
    run_id3 = case_session.record_plugin_run(session_id, "linux_sockstat", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "linux_sockstat", "vol_netscan", net_rows)

    res = mcp_server.vol_investigate_hidden()
    profile = res["profiles"][0]
    ev_ids = profile["evidence_ids"]
    assert len(ev_ids) == len(set(ev_ids))


# --- WINDOWS TESTS ---

def test_windows_empty_case(temp_db, mock_active_session, mock_backend):
    """Req 12: Windows empty case."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", pstree_rows)
    
    res = mcp_server.vol_windows_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["hidden_count"] == 0
    assert res["profiles"] == []
    assert res["data_availability"]["network"] == False

def test_windows_data_availability_metadata(temp_db, mock_active_session, mock_backend):
    """Req 5: Windows data_availability metadata."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", psscan_rows)
    
    net_rows = [{"Pid": 999, "ForeignAddr": "1.1.1.1", "ForeignPort": 4444, "LocalPort": 1234}]
    run_id3 = case_session.record_plugin_run(session_id, "win_netscan", len(net_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "win_netscan", "vol_netscan", net_rows)

    res = mcp_server.vol_windows_investigate_hidden()
    assert mock_backend.call_count == 0
    assert res["data_availability"]["network"] == True
    assert res["data_availability"]["malfind"] == False

def test_windows_session_isolation(temp_db, mock_backend):
    """Req 2: Windows session isolation."""
    s1 = case_session.create_session("s1", "m1.raw", "windows")
    s2 = case_session.create_session("s2", "m2.raw", "windows")
    
    # Store evidence for s1 (hidden)
    run1 = case_session.record_plugin_run(s1, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(s1, run1, "win_pstree", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}])
    run2 = case_session.record_plugin_run(s1, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(s1, run2, "win_psscan", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}, {"PID": 999, "ImageFileName": "evil.exe"}])
    
    # Store evidence for s2 (no hidden)
    run3 = case_session.record_plugin_run(s2, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(s2, run3, "win_pstree", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}])
    run4 = case_session.record_plugin_run(s2, "win_psscan", 1, 0)
    evidence_store.store_plugin_evidence(s2, run4, "win_psscan", "vol_hidden", [{"PID": 4, "ImageFileName": "System"}])
    
    # Active is s2
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": s2, "image": "m2.raw", "os": "windows"}
        res = mcp_server.vol_windows_investigate_hidden()
        
    assert res.get("hidden_count", 0) == 0

def test_windows_evidence_get_provenance(temp_db, mock_active_session, mock_backend):
    """Req 6: Windows evidence_get provenance."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", psscan_rows)
    
    res = mcp_server.vol_windows_investigate_hidden()
    profile = res["profiles"][0]
    ev_ids = profile["evidence_ids"]
    assert len(ev_ids) > 0
    for ev_id in ev_ids:
        record = mcp_server.evidence_get(ev_id)
        assert record.get("evidence_id") == ev_id

def test_windows_deterministic_output(temp_db, mock_active_session, mock_backend):
    """Req 10: Windows deterministic output."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", psscan_rows)
    
    res1 = mcp_server.vol_windows_investigate_hidden()
    res2 = mcp_server.vol_windows_investigate_hidden()
    assert res1 == res2

def test_windows_duplicate_prevention(temp_db, mock_active_session, mock_backend):
    """Req 11: Windows duplicate prevention."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", psscan_rows)
    
    net_rows = [{"Pid": 999, "ForeignAddr": "1.1.1.1", "ForeignPort": 4444, "LocalPort": 1234}]
    run_id3 = case_session.record_plugin_run(session_id, "win_netscan", len(net_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run_id3, "win_netscan", "vol_netscan", net_rows)

    res = mcp_server.vol_windows_investigate_hidden()
    profile = res["profiles"][0]
    ev_ids = profile["evidence_ids"]
    assert len(ev_ids) == len(set(ev_ids))

def test_windows_backend_never_called(temp_db, mock_active_session, mock_backend):
    """Req 1: Windows backend never called."""
    session_id = mock_active_session.return_value["id"]
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run_id1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run_id1, "win_pstree", "vol_hidden_processes", pstree_rows)
    
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"}
    ]
    run_id2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run_id2, "win_psscan", "vol_hidden_processes", psscan_rows)
    
    mcp_server.vol_windows_investigate_hidden()
    assert mock_backend.call_count == 0

def test_structured_error_unsupported_os(temp_db, mock_backend):
    """Req 13: Structured error for unsupported OS."""
    with patch("mcp_server._require_active_session") as mock_req:
        # For Linux tool
        mock_req.return_value = {"id": "s1", "image": "m1.raw", "os": "windows"}
        res = mcp_server.vol_investigate_hidden()
        assert "error" in res
        
        # For Windows tool
        mock_req.return_value = {"id": "s2", "image": "m2.raw", "os": "linux"}
        res = mcp_server.vol_windows_investigate_hidden()
        assert "error" in res
