import pytest
from unittest.mock import patch
import mcp_server
import session as case_session
import evidence_store
from filters import timeline as timeline_filter

@pytest.fixture
def sample_bash_rows():
    return [
        {
            "Pid": 1234,
            "Process": "bash",
            "CommandTime": "2023-01-01 12:00:00",
            "Command": "ls -la",
            "Terminal": "pts/0"
        },
        {
            "Pid": 1234,
            "Process": "bash",
            "CommandTime": "2023-01-01 12:01:00",
            "Command": "cat /etc/shadow",
            "Terminal": "pts/0"
        }
    ]

def test_vol_bash_linux_execution(temp_db, mock_backend, sample_bash_rows):
    """Test standard Linux execution of vol_bash (Requirement 1)."""
    session_id = case_session.create_session("bash-test", "mem.raw", "linux")
    
    mock_backend.return_value = {
        "plugin": "linux_bash",
        "row_count": len(sample_bash_rows),
        "rows": sample_bash_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_bash()
        
    assert res["command_count"] == 2
    assert res["execution_status"] == "executed"
    assert "results" in res
    assert len(res["results"]) == 2
    
    assert res["results"][0]["command"] == "ls -la"
    assert res["results"][0]["pid"] == 1234
    assert res["results"][0]["process"] == "bash"
    assert res["results"][0]["terminal"] == "pts/0"
    
    # Requirement 4: Evidence IDs are correctly attached
    assert len(res["results"][0]["evidence_ids"]) >= 1
    ev_id = res["results"][0]["evidence_ids"][0]
    assert ev_id.startswith("ev-")
    
    # Verify backend called correctly
    mock_backend.assert_called_once_with("linux_bash", "mem.raw", [])
        
def test_vol_bash_windows_rejection(temp_db):
    """Test Windows OS rejection (Requirement 2)."""
    session_id = case_session.create_session("win-test", "mem.raw", "windows")
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_bash()
        
    assert res.get("status") == "invalid_request"
    assert "only implemented for linux cases" in res["error"]

def test_vol_bash_empty_output(temp_db, mock_backend):
    """Test execution when bash history is empty (Requirement 3)."""
    session_id = case_session.create_session("empty-test", "mem.raw", "linux")
    
    mock_backend.return_value = {
        "plugin": "linux_bash",
        "row_count": 0,
        "rows": []
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_bash()
        
    assert res["command_count"] == 0
    assert res["execution_status"] == "executed"
    assert len(res["results"]) == 0
    
def test_vol_bash_evidence_get(temp_db, mock_backend, sample_bash_rows):
    """Evidence can subsequently be retrieved with evidence_get (Requirement 5)."""
    session_id = case_session.create_session("evget-test", "mem.raw", "linux")
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": 1, "rows": [sample_bash_rows[0]]}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_bash()
    
    ev_id = res["results"][0]["evidence_ids"][0]
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        ev = mcp_server.evidence_get(ev_id)
        
    assert ev["evidence_id"] == ev_id
    assert ev["entity_id"] == "1234"
    assert ev["entity_name"] == "bash"
    assert ev["raw"]["Command"] == "ls -la"
    
def test_vol_bash_caching(temp_db, mock_backend, sample_bash_rows):
    """Test caching behavior (Requirements 6, 7)."""
    session_id = case_session.create_session("cache-test", "mem.raw", "linux")
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": len(sample_bash_rows), "rows": sample_bash_rows}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        
        # First run
        res1 = mcp_server.vol_bash()
        assert res1["execution_status"] == "executed"
        
        # Second run
        res2 = mcp_server.vol_bash()
        assert res2["execution_status"] == "cached"
        
    # Backend only called once (Requirement 7)
    assert mock_backend.call_count == 1
    
    # Exact same evidence IDs (Requirement 6)
    assert res1["results"][0]["evidence_ids"] == res2["results"][0]["evidence_ids"]

def test_vol_bash_session_isolation(temp_db, mock_backend, sample_bash_rows):
    """Different sessions cannot see each other's Bash evidence (Requirement 8)."""
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": len(sample_bash_rows), "rows": sample_bash_rows}
    
    session1 = case_session.create_session("s1", "mem.raw", "linux")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session1, "image": "mem.raw", "os": "linux"}
        res1 = mcp_server.vol_bash()
        
    session2 = case_session.create_session("s2", "mem.raw", "linux")
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": 0, "rows": []}
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session2, "image": "mem.raw", "os": "linux"}
        res2 = mcp_server.vol_bash()
        
    assert res1["command_count"] == 2
    assert res2["command_count"] == 0
    
def test_vol_bash_malformed_fields(temp_db, mock_backend):
    """Malformed/missing timestamp and optional fields do not crash (Requirements 9, 10)."""
    session_id = case_session.create_session("malformed-test", "mem.raw", "linux")
    
    malformed_rows = [
        {"Command": "whoami"}, # missing Pid, CommandTime, Process
        {"Pid": 999, "CommandTime": "not-a-timestamp", "Command": "id"}, # malformed time
        {"Pid": None, "CommandTime": None, "Command": None} # Nones
    ]
    
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": 3, "rows": malformed_rows}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_bash()
        
    assert res["command_count"] == 3
    
    whoami_res = next(r for r in res["results"] if r.get("command") == "whoami")
    assert "timestamp" not in whoami_res
    
    malformed_time_res = next(r for r in res["results"] if r.get("pid") == 999)
    assert malformed_time_res["timestamp"] == "not-a-timestamp"
    
    none_res = next(r for r in res["results"] if "command" not in r and "pid" not in r)
    assert "timestamp" not in none_res

def test_vol_bash_backend_errors(temp_db, mock_backend):
    """Backend errors are converted through existing structured error handling (Requirement 11)."""
    session_id = case_session.create_session("err-test", "mem.raw", "linux")
    
    # Force backend error
    import requests
    response = requests.Response()
    response.status_code = 504
    response._content = b'{"detail": "Volatility timeout"}'
    mock_backend.side_effect = requests.exceptions.HTTPError(response=response)
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_bash()
        
    assert res["status"] == "backend_timeout"
    assert "Volatility timeout" in res["error"]
    
def test_vol_bash_timeline_compatibility(temp_db, mock_backend, sample_bash_rows):
    """Test bash evidence enters the timeline correctly (Requirement 12)."""
    session_id = case_session.create_session("timeline-test", "mem.raw", "linux")
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": len(sample_bash_rows), "rows": sample_bash_rows}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        mcp_server.vol_bash()
        
    ev = evidence_store.search_evidence(session_id, plugin="linux_bash")
    timeline = timeline_filter.build_timeline(ev)
    
    assert timeline["event_count"] == 2
    assert timeline["temporal_count"] == 2
    assert "ls -la" in timeline["events"][0]["description"]

def test_vol_bash_evidence_store_mapping(temp_db, mock_backend, sample_bash_rows):
    """Regression test ensuring evidence mapping correctly extracts the process name."""
    session_id = case_session.create_session("mapping-test", "mem.raw", "linux")
    mock_backend.return_value = {"plugin": "linux_bash", "row_count": len(sample_bash_rows), "rows": sample_bash_rows}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        mcp_server.vol_bash()
        
    ev = evidence_store.search_evidence(session_id, plugin="linux_bash")
    assert ev[0]["entity_name"] == "bash"
    assert ev[0]["entity_id"] == "1234"
