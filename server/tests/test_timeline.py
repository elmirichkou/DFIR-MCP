"""
Tests for vol_timeline — the evidence-only chronological timeline tool.

Covers:
  1.  Empty evidence store
  2.  Single timestamped evidence
  3.  Multiple sources, unified ordering
  4.  Identical timestamps
  5.  Missing timestamps (contextual)
  6.  Malformed timestamps
  7.  Entity filtering
  8.  Time-range filtering
  9.  Evidence provenance (evidence_ids)
  10. Multiple evidence records contributing to one event
  11. Session isolation
  12. Backend execution guard
  13. Limit parameter
  14. Cache independence
"""
import pytest
from unittest.mock import patch

import mcp_server
import evidence_store
import session as case_session


# ─────────────────── helpers ──────────────────────────────────────────────

def _store_bash(session_id, pid, command, timestamp):
    """Persist a single bash evidence record and return its evidence_id."""
    row = {"Pid": pid, "Command": command, "CommandTime": timestamp}
    run_id = case_session.record_plugin_run(session_id, "linux_bash", 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        session_id, run_id, "linux_bash", "vol_bash", [row]
    )
    return ev_map.get(str(pid), [])


def _store_process(session_id, pid, name, ppid=0):
    """Persist a single process evidence record and return its evidence_id."""
    row = {"PID": pid, "PPID": ppid, "COMM": name}
    run_id = case_session.record_plugin_run(session_id, "linux_pslist", 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        session_id, run_id, "linux_pslist", "vol_pstree", [row]
    )
    return ev_map.get(str(pid), [])


def _store_network(session_id, pid, dest_addr, dest_port):
    """Persist a single network evidence record and return its evidence_id."""
    row = {"Pid": pid, "Destination Addr": dest_addr, "Destination Port": dest_port, "Source Port": 12345}
    run_id = case_session.record_plugin_run(session_id, "linux_sockstat", 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        session_id, run_id, "linux_sockstat", "vol_netscan", [row]
    )
    return ev_map.get(str(pid), [])


# ─────────────────── 1. Empty evidence store ──────────────────────────────

def test_empty_timeline(temp_db, mock_active_linux_session, mock_backend):
    """Empty evidence store → clean empty timeline."""
    res = mcp_server.vol_timeline()
    assert res["event_count"] == 0
    assert res["events"] == []
    assert res["sources"] == []
    assert res["temporal_count"] == 0
    assert res["contextual_count"] == 0
    assert mock_backend.call_count == 0


# ─────────────────── 2. One timestamped evidence record ───────────────────

def test_single_timestamped_event(temp_db, mock_active_linux_session, mock_backend):
    """One bash history row with a valid CommandTime → exactly one temporal event."""
    sid = mock_active_linux_session.return_value["id"]
    ev_ids = _store_bash(sid, 100, "whoami", "2026-08-01 12:00:00")

    res = mcp_server.vol_timeline()
    assert res["event_count"] == 1
    assert res["temporal_count"] == 1
    assert res["contextual_count"] == 0

    event = res["events"][0]
    assert event["is_temporal"] is True
    assert event["timestamp"] == "2026-08-01 12:00:00"
    assert event["event_type"] == "bash_history"
    assert event["entity_id"] == "100"
    assert "whoami" in event["description"]
    assert event["evidence_ids"] == ev_ids
    assert mock_backend.call_count == 0


# ─────────────────── 3. Multiple evidence sources ─────────────────────────

def test_multiple_sources_unified_ordering(temp_db, mock_active_linux_session, mock_backend):
    """Bash + process + network evidence → unified timeline, temporal first."""
    sid = mock_active_linux_session.return_value["id"]

    _store_bash(sid, 100, "ls", "2026-08-01 14:00:00")
    _store_bash(sid, 100, "cat /etc/passwd", "2026-08-01 12:00:00")
    _store_process(sid, 100, "bash")
    _store_network(sid, 100, "1.2.3.4", 80)

    res = mcp_server.vol_timeline()
    assert res["event_count"] == 4

    # First two should be temporal (bash), sorted chronologically.
    assert res["events"][0]["is_temporal"] is True
    assert "cat /etc/passwd" in res["events"][0]["description"]  # 12:00
    assert res["events"][1]["is_temporal"] is True
    assert "ls" in res["events"][1]["description"]  # 14:00

    # Remaining are contextual (process, network).
    assert res["events"][2]["is_temporal"] is False
    assert res["events"][3]["is_temporal"] is False

    # Sources should list all plugins that contributed.
    assert "linux_bash" in res["sources"]
    assert "linux_pslist" in res["sources"]
    assert "linux_sockstat" in res["sources"]


# ─────────────────── 4. Same timestamp → deterministic ordering ───────────

def test_identical_timestamps(temp_db, mock_active_linux_session, mock_backend):
    """Two bash events at the exact same time → stable deterministic order."""
    sid = mock_active_linux_session.return_value["id"]

    _store_bash(sid, 100, "alpha", "2026-08-01 12:00:00")
    _store_bash(sid, 200, "beta", "2026-08-01 12:00:00")

    res1 = mcp_server.vol_timeline()
    res2 = mcp_server.vol_timeline()

    # Ordering must be identical across calls.
    descs1 = [e["description"] for e in res1["events"]]
    descs2 = [e["description"] for e in res2["events"]]
    assert descs1 == descs2
    assert res1["event_count"] == 2


# ─────────────────── 5. Missing timestamp → contextual ────────────────────

def test_missing_timestamp_contextual(temp_db, mock_active_linux_session, mock_backend):
    """Process records have no forensic timestamp → contextual events."""
    sid = mock_active_linux_session.return_value["id"]
    _store_process(sid, 100, "sshd")

    res = mcp_server.vol_timeline()
    assert res["event_count"] == 1
    assert res["temporal_count"] == 0
    assert res["contextual_count"] == 1

    event = res["events"][0]
    assert event["is_temporal"] is False
    assert event["timestamp"] is None
    assert event["timestamp_parsed"] is None


# ─────────────────── 6. Malformed timestamp ───────────────────────────────

def test_malformed_timestamp_no_crash(temp_db, mock_active_linux_session, mock_backend):
    """A bash row with garbage CommandTime → event treated as contextual, no crash."""
    sid = mock_active_linux_session.return_value["id"]
    _store_bash(sid, 100, "evil", "NOT_A_TIMESTAMP_!!!")

    res = mcp_server.vol_timeline()
    assert res["event_count"] == 1
    # Malformed timestamp → contextual.
    assert res["contextual_count"] == 1
    assert res["events"][0]["is_temporal"] is False
    assert res["events"][0]["timestamp"] == "NOT_A_TIMESTAMP_!!!"
    assert res["events"][0]["timestamp_parsed"] is None


# ─────────────────── 7. Entity filtering ──────────────────────────────────

def test_entity_filter(temp_db, mock_active_linux_session, mock_backend):
    """entity_id filter → only matching events."""
    sid = mock_active_linux_session.return_value["id"]

    _store_bash(sid, 100, "whoami", "2026-08-01 12:00:00")
    _store_bash(sid, 200, "id", "2026-08-01 13:00:00")
    _store_process(sid, 100, "bash")
    _store_process(sid, 200, "zsh")

    res = mcp_server.vol_timeline(entity_id="100")
    assert res["event_count"] == 2
    for event in res["events"]:
        assert event["entity_id"] == "100"


# ─────────────────── 8. Time-range filtering ──────────────────────────────

def test_time_range_filter(temp_db, mock_active_linux_session, mock_backend):
    """start_time/end_time → only events inside the requested range."""
    sid = mock_active_linux_session.return_value["id"]

    _store_bash(sid, 100, "early", "2026-08-01 10:00:00")
    _store_bash(sid, 100, "middle", "2026-08-01 14:00:00")
    _store_bash(sid, 100, "late", "2026-08-01 20:00:00")

    res = mcp_server.vol_timeline(
        start_time="2026-08-01 12:00:00",
        end_time="2026-08-01 18:00:00",
    )
    # Only "middle" is in range among temporal events.
    temporal_events = [e for e in res["events"] if e["is_temporal"]]
    assert len(temporal_events) == 1
    assert "middle" in temporal_events[0]["description"]


def test_time_range_invalid_input(temp_db, mock_active_linux_session, mock_backend):
    """Invalid start_time/end_time → treated as no filter, no crash."""
    sid = mock_active_linux_session.return_value["id"]
    _store_bash(sid, 100, "cmd", "2026-08-01 12:00:00")

    # Garbage time bounds → filter is effectively off.
    res = mcp_server.vol_timeline(
        start_time="GARBAGE",
        end_time="ALSO_GARBAGE",
    )
    # Should not crash; all temporal events pass through since bounds are None.
    assert res["event_count"] >= 1


# ─────────────────── 9. Evidence provenance ───────────────────────────────

def test_evidence_provenance(temp_db, mock_active_linux_session, mock_backend):
    """Every event has correct evidence_ids pointing to real SQLite records."""
    sid = mock_active_linux_session.return_value["id"]
    ev_ids = _store_bash(sid, 100, "whoami", "2026-08-01 12:00:00")

    res = mcp_server.vol_timeline()
    event = res["events"][0]

    # evidence_ids must exist and match.
    assert len(event["evidence_ids"]) == 1
    assert event["evidence_ids"] == ev_ids

    # Each ID must resolve to a real record.
    for eid in event["evidence_ids"]:
        record = evidence_store.get_evidence(eid)
        assert record is not None
        assert record["session_id"] == sid


# ─────────────────── 10. Multiple evidence records → one entity ───────────

def test_multiple_evidence_same_entity(temp_db, mock_active_linux_session, mock_backend):
    """Two bash commands from the same PID → two events, each with its own evidence_id."""
    sid = mock_active_linux_session.return_value["id"]

    ev1 = _store_bash(sid, 100, "ls", "2026-08-01 12:00:00")
    ev2 = _store_bash(sid, 100, "cat /etc/shadow", "2026-08-01 12:05:00")

    res = mcp_server.vol_timeline()
    pid_events = [e for e in res["events"] if e["entity_id"] == "100" and e["is_temporal"]]
    assert len(pid_events) == 2

    # Each event has exactly one evidence_id and they are different.
    all_ev_ids = [e["evidence_ids"][0] for e in pid_events]
    assert len(set(all_ev_ids)) == 2
    # All IDs are from ev1 + ev2.
    assert set(all_ev_ids) == set(ev1 + ev2)


# ─────────────────── 11. Session isolation ────────────────────────────────

def test_session_isolation(temp_db, mock_active_linux_session, mock_backend):
    """Evidence from another session never appears in the timeline."""
    sid = mock_active_linux_session.return_value["id"]
    _store_bash(sid, 100, "mine", "2026-08-01 12:00:00")

    # Create a second session and store evidence there.
    other_sid = case_session.create_session("other_case", "other.raw", "linux")
    _store_bash(other_sid, 200, "not_mine", "2026-08-01 13:00:00")

    res = mcp_server.vol_timeline()
    # Only the active session's event should appear.
    assert res["event_count"] == 1
    assert res["events"][0]["entity_id"] == "100"
    for event in res["events"]:
        for eid in event["evidence_ids"]:
            record = evidence_store.get_evidence(eid)
            assert record["session_id"] == sid


# ─────────────────── 12. Backend execution guard ─────────────────────────

def test_backend_never_called(temp_db, mock_active_linux_session, mock_backend):
    """vol_timeline must NEVER call backend_client.run_plugin."""
    sid = mock_active_linux_session.return_value["id"]
    _store_bash(sid, 100, "test", "2026-08-01 12:00:00")
    _store_process(sid, 200, "sshd")

    # Make mock raise if called.
    mock_backend.side_effect = AssertionError(
        "Volatility backend was invoked — vol_timeline must not execute plugins"
    )

    # This should not raise.
    res = mcp_server.vol_timeline()
    assert res["event_count"] == 2
    assert mock_backend.call_count == 0


# ─────────────────── 13. Limit parameter ──────────────────────────────────

def test_limit_parameter(temp_db, mock_active_linux_session, mock_backend):
    """Limit parameter caps the number of returned events."""
    sid = mock_active_linux_session.return_value["id"]

    for i in range(20):
        _store_bash(sid, 100, f"cmd_{i}", f"2026-08-01 12:{i:02d}:00")

    res = mcp_server.vol_timeline(limit=5)
    assert res["event_count"] == 5
    assert len(res["events"]) == 5


# ─────────────────── 14. Cache independence ───────────────────────────────

def test_cache_independence(temp_db, mock_active_linux_session, mock_backend):
    """vol_timeline must not create plugin_cache entries."""
    sid = mock_active_linux_session.return_value["id"]
    _store_bash(sid, 100, "test", "2026-08-01 12:00:00")

    # Count cache entries before.
    import sqlite3, json
    with evidence_store._conn() as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM plugin_cache WHERE session_id = ?", (sid,)
        ).fetchone()[0]

    mcp_server.vol_timeline()

    with evidence_store._conn() as conn:
        after = conn.execute(
            "SELECT COUNT(*) FROM plugin_cache WHERE session_id = ?", (sid,)
        ).fetchone()[0]

    assert after == before, "vol_timeline must not create plugin cache entries"
