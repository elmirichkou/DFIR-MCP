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
            "Command": "ls -la"
        },
        {
            "Pid": 1234,
            "Process": "bash",
            "CommandTime": "2023-01-01 12:01:00",
            "Command": "cat /etc/shadow"
        }
    ]

def test_vol_bash_linux_execution(temp_db, mock_backend, sample_bash_rows):
    """Test standard Linux execution of vol_bash."""
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
    
    # Verify backend called correctly
    mock_backend.assert_called_once_with("linux_bash", "mem.raw", [])
    
    # Verify evidence stored
    ev = evidence_store.search_evidence(session_id, plugin="linux_bash")
    assert len(ev) == 2
    
    # Verify provenance and IDs
    for e in ev:
        assert e["evidence_id"].startswith("ev-")
        assert e["evidence_type"] == "bash_history"
        assert e["entity_type"] == "process"
        assert e["entity_id"] == "1234"
        assert "command" in e["attributes"]
        assert "command_time" in e["attributes"]
        assert e["raw"]["Command"] in ("ls -la", "cat /etc/shadow")
        
def test_vol_bash_windows_rejection(temp_db):
    """Test Windows OS rejection."""
    session_id = case_session.create_session("win-test", "mem.raw", "windows")
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        
        res = mcp_server.vol_bash()
        
    assert res.get("status") == "invalid_request"
    assert "only implemented for linux cases" in res["error"]

def test_vol_bash_caching(temp_db, mock_backend, sample_bash_rows):
    """Test caching behavior."""
    session_id = case_session.create_session("cache-test", "mem.raw", "linux")
    
    mock_backend.return_value = {
        "plugin": "linux_bash",
        "row_count": len(sample_bash_rows),
        "rows": sample_bash_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        
        # First run
        res1 = mcp_server.vol_bash()
        assert res1["execution_status"] == "executed"
        
        # Second run (cache hit)
        res2 = mcp_server.vol_bash()
        assert res2["execution_status"] == "cached"
        
    assert mock_backend.call_count == 1
    
def test_vol_bash_timeline_compatibility(temp_db, mock_backend, sample_bash_rows):
    """Test bash evidence enters the timeline correctly."""
    session_id = case_session.create_session("timeline-test", "mem.raw", "linux")
    mock_backend.return_value = {
        "plugin": "linux_bash",
        "row_count": len(sample_bash_rows),
        "rows": sample_bash_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        mcp_server.vol_bash()
        
    ev = evidence_store.search_evidence(session_id, plugin="linux_bash")
    timeline = timeline_filter.build_timeline(ev)
    
    assert timeline["event_count"] == 2
    assert timeline["temporal_count"] == 2
    assert "ls -la" in timeline["events"][0]["description"]
    
def test_vol_bash_empty_output(temp_db, mock_backend):
    """Test execution when bash history is empty."""
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
    
    ev = evidence_store.search_evidence(session_id, plugin="linux_bash")
    assert len(ev) == 0
