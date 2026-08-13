import pytest
from unittest.mock import patch, Mock
from requests.exceptions import Timeout, ConnectionError

import mcp_server
import session as case_session
import evidence_store
from filters import malfind as malfind_filter

@pytest.fixture
def sample_malfind_rows():
    return [
        {
            "PID": 100,
            "Process": "svchost.exe",
            "Start VPN": "0x10000",
            "End VPN": "0x11000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Hexdump": "4d 5a 90 00 ...",
            "Disasm": "MOV EAX, 1\nRET"
        },
        {
            "PID": None,
            "Process": "unmappable",
            "Start VPN": "0x20000",
            "End VPN": "0x21000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Hexdump": "eb fe",
            "Disasm": "JMP 0"
        }
    ]

def test_vol_malfind_windows(temp_db, mock_backend, sample_malfind_rows):
    """Test windows malfind execution and provenance."""
    session_id = case_session.create_session("win-test", "mem.raw", "windows")
    
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_malfind_rows),
        "rows": sample_malfind_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()
        
    assert res["finding_count"] == 2
    assert res["execution_status"] == "executed"
    
    mock_backend.assert_called_once_with("win_malfind", "mem.raw", [])
    
    # Verify provenance
    ev = evidence_store.search_evidence(session_id, plugin="win_malfind")
    assert len(ev) == 2
    
    # PID mapping check
    mapped = next(e for e in ev if e["entity_id"] == "100")
    unmapped = next(e for e in ev if e["entity_id"] is None)
    
    assert mapped["evidence_id"].startswith("ev-")
    assert unmapped["evidence_id"].startswith("ev-")
    
    # Check that the anomaly result has evidence IDs mapped
    anomalies = res["anomalies"]
    mapped_anomaly = next(a for a in anomalies if a["pid"] == 100)
    unmapped_anomaly = next(a for a in anomalies if a["pid"] is None)
    
    assert mapped["evidence_id"] in mapped_anomaly["evidence_ids"]
    assert len(unmapped_anomaly["evidence_ids"]) == 0  # Unmappable gets empty array

def test_vol_malfind_linux(temp_db, mock_backend, sample_malfind_rows):
    """Test linux malfind execution."""
    session_id = case_session.create_session("lin-test", "mem.raw", "linux")
    
    mock_backend.return_value = {
        "plugin": "linux_malfind",
        "row_count": len(sample_malfind_rows),
        "rows": sample_malfind_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_malfind()
        
    assert res["finding_count"] == 2
    mock_backend.assert_called_once_with("linux_malfind", "mem.raw", [])

def test_vol_malfind_unsupported_os(temp_db, mock_backend):
    """Test unsupported OS rejection."""
    session_id = case_session.create_session("mac-test", "mem.raw", "linux")
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "mac"}
        res = mcp_server.vol_malfind()
        
    assert res.get("status") == "invalid_request"
    assert "not implemented for os" in res["error"].lower()
    mock_backend.assert_not_called()

def test_vol_malfind_no_findings(temp_db, mock_backend):
    """Test execution with no malfind rows."""
    session_id = case_session.create_session("win-test", "mem.raw", "windows")
    mock_backend.return_value = {"plugin": "win_malfind", "row_count": 0, "rows": []}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()
        
    assert res["finding_count"] == 0

def test_vol_malfind_caching_and_evidence_get(temp_db, mock_backend, sample_malfind_rows):
    """Test caching behavior and raw evidence retrieval."""
    session_id = case_session.create_session("cache-test", "mem.raw", "windows")
    
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_malfind_rows),
        "rows": sample_malfind_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        
        # First run
        res1 = mcp_server.vol_malfind()
        assert res1["execution_status"] == "executed"
        ev_id = res1["anomalies"][0]["evidence_ids"][0]
        
        # Second run
        res2 = mcp_server.vol_malfind()
        assert res2["execution_status"] == "cached"
        assert res2["anomalies"][0]["evidence_ids"][0] == ev_id
        
    assert mock_backend.call_count == 1
    
    # Test evidence_get
    ev_record = evidence_store.get_evidence(ev_id)
    assert ev_record is not None
    assert ev_record["raw"]["PID"] == 100
    assert ev_record["raw"]["Start VPN"] == "0x10000"

def test_vol_malfind_backend_failures(temp_db, active_session):
    """Test structured error handling for backend failures."""
    with patch("mcp_server.backend_client.run_plugin") as mock_run:
        mock_run.side_effect = Timeout("Backend timed out")
        
        with patch("mcp_server._require_active_session") as mock_req:
            mock_req.return_value = {"id": active_session, "image": "mem.raw", "os": "windows"}
            res = mcp_server.vol_malfind()
            
        assert res["status"] == "backend_timeout"
        assert "timed out" in res["error"].lower()

def test_vol_malfind_session_isolation(temp_db, mock_backend, sample_malfind_rows):
    """Test that evidence is isolated between sessions."""
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_malfind_rows),
        "rows": sample_malfind_rows
    }
    
    session1 = case_session.create_session("s1", "m1.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session1, "image": "m1.raw", "os": "windows"}
        mcp_server.vol_malfind()
        
    session2 = case_session.create_session("s2", "m2.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session2, "image": "m2.raw", "os": "windows"}
        mcp_server.vol_malfind()
        
    ev1 = evidence_store.search_evidence(session1, plugin="win_malfind")
    ev2 = evidence_store.search_evidence(session2, plugin="win_malfind")
    
    assert len(ev1) == 2
    assert len(ev2) == 2
    assert set(e["evidence_id"] for e in ev1).isdisjoint(set(e["evidence_id"] for e in ev2))
