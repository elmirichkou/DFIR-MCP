import pytest
import mcp_server
import session as case_session
import evidence_store
from unittest.mock import patch

def test_investigate_hidden_missing_prereqs(temp_db, mock_active_linux_session, mock_backend):
    """Verify it returns an error if pslist/psscan evidence is missing."""
    res = mcp_server.vol_investigate_hidden()
    assert "error" in res
    assert "Prerequisite evidence missing" in res["error"]
    assert mock_backend.call_count == 0 # Verify it does NOT execute Volatility itself

def test_investigate_hidden_complete(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Test correlation with complete evidence (pslist, psscan, netscan, bash)."""
    # 1. Provide prereq evidence
    run_id1 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id1, "linux_pslist", "vol_hidden_processes", sample_volatility_rows["pslist"])
    
    run_id2 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id2, "linux_psscan", "vol_hidden_processes", sample_volatility_rows["psscan"])
    
    # 2. Provide network evidence
    net_rows = [{"Pid": 999, "Destination Addr": "1.1.1.1", "Destination Port": 80, "Source Port": 123}]
    run_id3 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_sockstat", 1, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id3, "linux_sockstat", "vol_netscan", net_rows)
    
    # 3. Provide bash evidence
    bash_rows = [{"Pid": 999, "Command": "curl -O malware.sh", "CommandTime": "2026-08-13"}]
    run_id4 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_bash", 1, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id4, "linux_bash", "vol_bash", bash_rows)
    
    # Execute correlation
    res = mcp_server.vol_investigate_hidden()
    
    assert mock_backend.call_count == 0
    assert res["profiled_count"] == 1
    
    profile = res["profiles"][0]
    assert profile["pid"] == 999
    assert len(profile["network"]["connections"]) == 1
    assert profile["network"]["connections"][0]["remote_addr"] == "1.1.1.1"
    
    assert profile["bash"]["available"] is True
    assert len(profile["bash"]["commands"]) == 1
    assert profile["bash"]["commands"][0]["command"] == "curl -O malware.sh"

def test_investigate_hidden_missing_bash(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Test correlation when bash history is missing."""
    run_id1 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id1, "linux_pslist", "vol_hidden", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id2, "linux_psscan", "vol_hidden", sample_volatility_rows["psscan"])
    
    # Network evidence present, but no bash
    net_rows = [{"Pid": 999, "Destination Addr": "1.1.1.1", "Destination Port": 80, "Source Port": 123}]
    run_id3 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_sockstat", 1, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id3, "linux_sockstat", "vol_netscan", net_rows)
    
    res = mcp_server.vol_investigate_hidden()
    assert res["profiled_count"] == 1
    profile = res["profiles"][0]
    
    assert profile["bash"]["available"] is False
    assert len(profile["bash"]["commands"]) == 0
    assert any("Bash history evidence is not available" in obs for obs in profile["narrative"]["observed"])

def test_investigate_hidden_missing_network(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Test correlation when network history is missing."""
    run_id1 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_pslist", 2, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id1, "linux_pslist", "vol_hidden", sample_volatility_rows["pslist"])
    run_id2 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_psscan", 3, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id2, "linux_psscan", "vol_hidden", sample_volatility_rows["psscan"])
    
    # Bash evidence present, but no network
    bash_rows = [{"Pid": 999, "Command": "curl -O malware.sh", "CommandTime": "2026-08-13"}]
    run_id4 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_bash", 1, 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id4, "linux_bash", "vol_bash", bash_rows)
    
    res = mcp_server.vol_investigate_hidden()
    profile = res["profiles"][0]
    
    assert len(profile["network"]["connections"]) == 0
    assert len(profile["bash"]["commands"]) == 1

def test_investigate_hidden_multiple_pids(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Test correlation with multiple hidden PIDs."""
    pslist_rows = sample_volatility_rows["pslist"]
    psscan_rows = list(sample_volatility_rows["psscan"])
    psscan_rows.append({"PID": 888, "PPID": 4, "COMM": "hidden2.exe"}) # Another hidden
    
    run_id1 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_pslist", len(pslist_rows), 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id1, "linux_pslist", "vol_hidden", pslist_rows)
    run_id2 = case_session.record_plugin_run(mock_active_linux_session.return_value["id"], "linux_psscan", len(psscan_rows), 0)
    evidence_store.store_plugin_evidence(mock_active_linux_session.return_value["id"], run_id2, "linux_psscan", "vol_hidden", psscan_rows)
    
    res = mcp_server.vol_investigate_hidden()
    assert res["profiled_count"] == 2
    assert {p["pid"] for p in res["profiles"]} == {888, 999}
