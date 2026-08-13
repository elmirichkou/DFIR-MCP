import pytest
from unittest.mock import patch, Mock

import mcp_server
import session as case_session
import evidence_store
from filters import ssdt as ssdt_filter

@pytest.fixture
def sample_ssdt_rows():
    return [
        {
            "Table": "KiServiceTable",
            "Index": 1,
            "Offset": 0xfffff80000001000,
            "Symbol": "ntoskrnl!NtCreateFile"
        },
        {
            "Table": "KiServiceTable",
            "Index": 2,
            "Offset": 0xfffff80000002000,
            "Symbol": "hooked_driver!NtOpenFile"
        },
        {
            "Table": "W32pServiceTable",
            "Index": 3,
            "Offset": 0xfffff90000003000,
            "Symbol": "win32k!NtUserCreateWindowEx"
        },
        {
            "Table": "KiServiceTable",
            "Index": 4,
            "Offset": 0xfffff80000004000,
            "Symbol": ""  # No symbol, potential hook
        }
    ]

def test_vol_ssdt_windows(temp_db, mock_backend, sample_ssdt_rows):
    """Test standard Windows execution of vol_ssdt and its analysis/provenance."""
    session_id = case_session.create_session("ssdt-win-test", "mem.raw", "windows")

    mock_backend.return_value = {
        "plugin": "win_ssdt",
        "row_count": len(sample_ssdt_rows),
        "rows": sample_ssdt_rows
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_ssdt()

    assert res["entry_count"] == 4
    assert res["anomaly_count"] == 2  # hooked_driver and empty symbol
    assert res["execution_status"] == "executed"

    mock_backend.assert_called_once_with("win_ssdt", "mem.raw", [])

    # Verify evidence stored in DB
    ev = evidence_store.search_evidence(session_id, plugin="win_ssdt")
    assert len(ev) == 4

    # Index mapping check
    mapped_entry_1 = next(e for e in res["observed"] if e["index"] == 1)
    mapped_entry_2 = next(e for e in res["observed"] if e["index"] == 2)
    mapped_entry_4 = next(e for e in res["observed"] if e["index"] == 4)

    assert len(mapped_entry_1["evidence_ids"]) == 1
    assert mapped_entry_1["evidence_ids"][0].startswith("ev-")

    # Verify exact ID preservation in evidence get
    ev_record = evidence_store.get_evidence(mapped_entry_1["evidence_ids"][0])
    assert ev_record["raw"]["Symbol"] == "ntoskrnl!NtCreateFile"
    assert ev_record["entity_id"] == "1"

    # Check anomalies
    anomalies = res["anomalies"]
    hooked_anomaly = next(a for a in anomalies if a["index"] == 2)
    no_symbol_anomaly = next(a for a in anomalies if a["index"] == 4)

    assert "hooked_driver" in hooked_anomaly["symbol"]
    assert "no resolved symbol" in no_symbol_anomaly["detail"]

def test_vol_ssdt_linux_rejection(temp_db):
    """Test Linux OS rejection for vol_ssdt."""
    session_id = case_session.create_session("ssdt-lin-test", "mem.raw", "linux")

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_ssdt()

    assert res.get("status") == "invalid_request"
    assert "only implemented for windows os" in res["error"].lower()

def test_vol_ssdt_caching(temp_db, mock_backend, sample_ssdt_rows):
    """Test caching behavior of vol_ssdt."""
    session_id = case_session.create_session("ssdt-cache-test", "mem.raw", "windows")

    mock_backend.return_value = {
        "plugin": "win_ssdt",
        "row_count": len(sample_ssdt_rows),
        "rows": sample_ssdt_rows
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}

        # First run: actual backend call
        res1 = mcp_server.vol_ssdt()
        assert res1["execution_status"] == "executed"

        # Second run: cache hit
        res2 = mcp_server.vol_ssdt()
        assert res2["execution_status"] == "cached"
        assert res2["observed"][0]["evidence_ids"] == res1["observed"][0]["evidence_ids"]

    assert mock_backend.call_count == 1

def test_vol_ssdt_empty(temp_db, mock_backend):
    """Test execution with empty SSDT rows."""
    session_id = case_session.create_session("ssdt-empty-test", "mem.raw", "windows")
    mock_backend.return_value = {"plugin": "win_ssdt", "row_count": 0, "rows": []}

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_ssdt()

    assert res["entry_count"] == 0
    assert res["anomaly_count"] == 0

def test_vol_ssdt_session_isolation(temp_db, mock_backend, sample_ssdt_rows):
    """Test SSDT evidence isolation across different sessions."""
    mock_backend.return_value = {
        "plugin": "win_ssdt",
        "row_count": len(sample_ssdt_rows),
        "rows": sample_ssdt_rows
    }

    session1 = case_session.create_session("s1", "m1.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session1, "image": "m1.raw", "os": "windows"}
        mcp_server.vol_ssdt()

    session2 = case_session.create_session("s2", "m2.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session2, "image": "m2.raw", "os": "windows"}
        mcp_server.vol_ssdt()

    ev1 = evidence_store.search_evidence(session1, plugin="win_ssdt")
    ev2 = evidence_store.search_evidence(session2, plugin="win_ssdt")

    assert len(ev1) == 4
    assert len(ev2) == 4
    assert set(e["evidence_id"] for e in ev1).isdisjoint(set(e["evidence_id"] for e in ev2))
