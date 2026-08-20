import pytest
import mcp_server
import session as case_session
import evidence_store
from unittest.mock import patch

# ─────────────────── helpers ──────────────────────────────────────────────

def _store_evidence(session_id, plugin, evidence_type, row, entity_id=None):
    """Persist a single evidence record and return its evidence_id."""
    run_id = case_session.record_plugin_run(session_id, plugin, 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        session_id, run_id, plugin, evidence_type, [row]
    )
    # the mapper might map by PID. Find the returned ev_id
    for k, v in ev_map.items():
        if v:
            return v
    return []

# ─────────────────── tests ────────────────────────────────────────────────

def test_timeline_backend_never_called(temp_db, mock_active_linux_session, mock_backend):
    """Req 1: vol_timeline must NEVER execute a Volatility plugin."""
    mock_backend.side_effect = AssertionError("Backend should never be called")
    sid = mock_active_linux_session.return_value["id"]
    _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 100, "Command": "test", "CommandTime": "2026-08-01 12:00:00"})
    
    res = mcp_server.vol_timeline()
    assert res["event_count"] == 1
    assert mock_backend.call_count == 0

def test_timeline_session_isolation(temp_db, mock_active_linux_session, mock_backend):
    """Req 2: Timeline events must only originate from the active session_id."""
    sid1 = mock_active_linux_session.return_value["id"]
    sid2 = case_session.create_session("other_case", "other.raw", "linux")
    
    _store_evidence(sid1, "linux_bash", "vol_bash", {"Pid": 100, "Command": "mine", "CommandTime": "2026-08-01 12:00:00"})
    _store_evidence(sid2, "linux_bash", "vol_bash", {"Pid": 200, "Command": "not_mine", "CommandTime": "2026-08-01 13:00:00"})
    
    res = mcp_server.vol_timeline()
    assert res["event_count"] == 1
    assert res["events"][0]["entity_id"] == "100"

def test_timeline_process_network_bash(temp_db, mock_active_linux_session, mock_backend):
    """Req 3, 4: Supported evidence includes process, network, bash."""
    sid = mock_active_linux_session.return_value["id"]
    
    _store_evidence(sid, "linux_pslist", "vol_pstree", {"PID": 100, "COMM": "bash", "StartTime": "2026-08-01 10:00:00"})
    _store_evidence(sid, "win_netscan", "vol_netscan", {"Pid": 200, "Owner": "chrome.exe", "Created": "2026-08-01 11:00:00", "LocalPort": 80, "ForeignAddr": "1.1.1.1", "ForeignPort": 443})
    _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 100, "Command": "curl", "CommandTime": "2026-08-01 12:00:00"})
    
    res = mcp_server.vol_timeline()
    assert res["temporal_count"] == 3
    
    times = [e["timestamp"] for e in res["events"] if e["is_temporal"]]
    assert times == ["2026-08-01 10:00:00", "2026-08-01 11:00:00", "2026-08-01 12:00:00"]
    assert all(e["classification"] == "observed" for e in res["events"])

def test_timeline_malfind_contextual(temp_db, mock_active_linux_session, mock_backend):
    """Req 3, 4: Malfind falls back to contextual since it lacks timestamps."""
    sid = mock_active_linux_session.return_value["id"]
    
    _store_evidence(sid, "linux_malfind", "vol_malfind", {"PID": 100, "Process": "evil", "Start VPN": "0x1000", "End VPN": "0x2000"})
    
    res = mcp_server.vol_timeline()
    assert res["temporal_count"] == 0
    assert res["contextual_count"] == 1
    assert res["events"][0]["classification"] == "observed"

def test_timeline_event_schema_and_provenance(temp_db, mock_active_linux_session, mock_backend):
    """Req 5, 6, 7: Stable event schema, classification, provenance, deduplication."""
    sid = mock_active_linux_session.return_value["id"]
    
    ev_ids = _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 100, "Command": "ls", "CommandTime": "2026-08-01 12:00:00"})
    
    res = mcp_server.vol_timeline()
    event = res["events"][0]
    
    assert "timestamp" in event
    assert "event_type" in event
    assert "description" in event
    assert "plugin" in event
    assert "entity_id" in event
    assert "evidence_ids" in event
    assert "classification" in event
    assert event["classification"] == "observed"
    
    # Provenance check
    assert event["evidence_ids"] == ev_ids
    assert len(event["evidence_ids"]) == len(set(event["evidence_ids"]))  # Deduplicated
    
    record = mcp_server.evidence_get(event["evidence_ids"][0])
    assert record is not None
    assert record["evidence_id"] == event["evidence_ids"][0]

def test_timeline_ordering_deterministic(temp_db, mock_active_linux_session, mock_backend):
    """Req 8: Timeline deterministic ordering."""
    sid = mock_active_linux_session.return_value["id"]
    
    _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 100, "Command": "A", "CommandTime": "2026-08-01 12:00:00"})
    _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 200, "Command": "B", "CommandTime": "2026-08-01 12:00:00"})
    
    res1 = mcp_server.vol_timeline()
    res2 = mcp_server.vol_timeline()
    
    assert res1["events"] == res2["events"]

def test_timeline_missing_malformed_timestamps(temp_db, mock_active_linux_session, mock_backend):
    """Req 4, 9: Missing or malformed timestamps become contextual, safely."""
    sid = mock_active_linux_session.return_value["id"]
    
    _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 100, "Command": "missing", "CommandTime": ""})
    _store_evidence(sid, "linux_bash", "vol_bash", {"Pid": 200, "Command": "malformed", "CommandTime": "NOT_A_TIME"})
    _store_evidence(sid, "linux_pslist", "vol_pstree", {"PID": 300, "COMM": "no_ts"})
    
    res = mcp_server.vol_timeline()
    assert res["temporal_count"] == 0
    assert res["contextual_count"] == 3
    
    # None of them should have the current time
    for e in res["events"]:
        assert e["timestamp_parsed"] is None

def test_timeline_empty_case(temp_db, mock_active_linux_session, mock_backend):
    """Req 11: Empty case behavior."""
    res = mcp_server.vol_timeline()
    assert res["event_count"] == 0
    assert res["events"] == []
    assert mock_backend.call_count == 0
