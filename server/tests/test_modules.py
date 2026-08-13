import pytest
from unittest.mock import patch, Mock

import mcp_server
import session as case_session
import evidence_store
from filters import modules as win_modules_filter

@pytest.fixture
def sample_modules_rows():
    return [
        {
            "Offset": 12345,
            "Name": "ntoskrnl.exe",
            "Base": "0xfffff80000000000",
            "Size": "0x1000",
            "Path": "\\SystemRoot\\system32\\ntoskrnl.exe"
        },
        {
            "Offset": 67890,
            "Name": "tcpip.sys",
            "Base": "0xfffff80000001000",
            "Size": "0x2000",
            "File": "\\SystemRoot\\system32\\drivers\\tcpip.sys"
        },
        {
            "Offset": None,
            "Name": "unmappable.sys",
            "Base": "0xfffff80000003000",
            "Size": "0x500",
            "Path": "unknown"
        }
    ]

def test_vol_modules_windows(temp_db, mock_backend, sample_modules_rows):
    """Test standard Windows execution of vol_modules."""
    session_id = case_session.create_session("mod-test", "mem.raw", "windows")
    
    mock_backend.return_value = {
        "plugin": "win_modules",
        "row_count": len(sample_modules_rows),
        "rows": sample_modules_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_modules()
        
    assert res["module_count"] == 3
    assert res["execution_status"] == "executed"
    
    mock_backend.assert_called_once_with("win_modules", "mem.raw", [])
    
    # Verify provenance and mapping
    ev = evidence_store.search_evidence(session_id, plugin="win_modules")
    assert len(ev) == 3
    
    mapped_mod = next(m for m in res["modules"] if m["offset"] == 12345)
    unmapped_mod = next(m for m in res["modules"] if m["offset"] is None)
    
    assert len(mapped_mod["evidence_ids"]) == 1
    assert mapped_mod["evidence_ids"][0].startswith("ev-")
    assert len(unmapped_mod["evidence_ids"]) == 0
    
    # Verify exact ID preservation in evidence
    ev_record = evidence_store.get_evidence(mapped_mod["evidence_ids"][0])
    assert ev_record["raw"]["Name"] == "ntoskrnl.exe"
    assert ev_record["entity_id"] == "12345"

def test_vol_modules_linux_rejection(temp_db):
    """Test Linux OS rejection."""
    session_id = case_session.create_session("lin-test", "mem.raw", "linux")
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_modules()
        
    assert res.get("status") == "invalid_request"
    assert "only implemented for windows os" in res["error"].lower()

def test_vol_modules_caching(temp_db, mock_backend, sample_modules_rows):
    """Test caching behavior."""
    session_id = case_session.create_session("cache-test", "mem.raw", "windows")
    
    mock_backend.return_value = {
        "plugin": "win_modules",
        "row_count": len(sample_modules_rows),
        "rows": sample_modules_rows
    }
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        
        # First run
        res1 = mcp_server.vol_modules()
        assert res1["execution_status"] == "executed"
        
        # Second run
        res2 = mcp_server.vol_modules()
        assert res2["execution_status"] == "cached"
        assert res2["modules"][0]["evidence_ids"] == res1["modules"][0]["evidence_ids"]
        
    assert mock_backend.call_count == 1

def test_vol_modules_empty(temp_db, mock_backend):
    """Test execution with no rows."""
    session_id = case_session.create_session("empty-test", "mem.raw", "windows")
    mock_backend.return_value = {"plugin": "win_modules", "row_count": 0, "rows": []}
    
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_modules()
        
    assert res["module_count"] == 0

def test_vol_modules_session_isolation(temp_db, mock_backend, sample_modules_rows):
    """Test evidence isolation across sessions."""
    mock_backend.return_value = {
        "plugin": "win_modules",
        "row_count": len(sample_modules_rows),
        "rows": sample_modules_rows
    }
    
    session1 = case_session.create_session("s1", "m1.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session1, "image": "m1.raw", "os": "windows"}
        mcp_server.vol_modules()
        
    session2 = case_session.create_session("s2", "m2.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session2, "image": "m2.raw", "os": "windows"}
        mcp_server.vol_modules()
        
    ev1 = evidence_store.search_evidence(session1, plugin="win_modules")
    ev2 = evidence_store.search_evidence(session2, plugin="win_modules")
    
    assert len(ev1) == 3
    assert len(ev2) == 3
    assert set(e["evidence_id"] for e in ev1).isdisjoint(set(e["evidence_id"] for e in ev2))
