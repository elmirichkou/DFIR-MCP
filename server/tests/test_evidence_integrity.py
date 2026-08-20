import pytest
import json
import sqlite3
import uuid
import evidence_store
import mcp_server
import session as case_session
from unittest.mock import patch


@pytest.fixture
def test_record_data():
    return {
        "plugin": "win_pstree",
        "evidence_type": "process_record",
        "entity_type": "process",
        "entity_id": "4",
        "entity_name": "System",
        "attributes": {"ppid": 0, "tid": 0},
        "raw": {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 120}
    }


def test_compute_evidence_hash_deterministic(test_record_data):
    """Test that dictionary key ordering and whitespace don't change the hash (canonical serialization)."""
    h1 = evidence_store.compute_evidence_hash(**test_record_data)

    # Reorder keys in raw
    d2 = test_record_data.copy()
    d2["raw"] = {"Threads": 120, "PPID": 0, "ImageFileName": "System", "PID": 4}
    h2 = evidence_store.compute_evidence_hash(**d2)

    assert h1 == h2

    # Different data produces different hash
    d3 = test_record_data.copy()
    d3["raw"] = {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 121}
    h3 = evidence_store.compute_evidence_hash(**d3)

    assert h1 != h3


def test_evidence_verify_valid(temp_db, active_session, test_record_data, mock_backend):
    """Test that newly stored evidence produces a verified status."""
    run_id = case_session.record_plugin_run(active_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        
    assert res["valid"] is True
    assert res["status"] == "verified"
    assert res["algorithm"] == "sha256"
    assert res["evidence_id"] == ev_id
    assert mock_backend.call_count == 0


def test_evidence_verify_tampered_raw(temp_db, active_session, test_record_data, mock_backend):
    """Test that modifying raw JSON in the database causes a verification failure."""
    run_id = case_session.record_plugin_run(active_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    # Tamper with the database
    with evidence_store._conn() as conn:
        conn.execute("UPDATE evidence SET raw = ? WHERE evidence_id = ?", ('{"PID": 4, "Tampered": true}', ev_id))

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        
    assert res["valid"] is False
    assert res["status"] == "integrity_failure"
    assert mock_backend.call_count == 0


def test_evidence_verify_tampered_attributes(temp_db, active_session, test_record_data, mock_backend):
    """Test that modifying derived attributes causes a verification failure."""
    run_id = case_session.record_plugin_run(active_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    # Tamper with the database
    with evidence_store._conn() as conn:
        conn.execute("UPDATE evidence SET attributes = ? WHERE evidence_id = ?", ('{"ppid": 9999}', ev_id))

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        
    assert res["valid"] is False
    assert res["status"] == "integrity_failure"


def test_evidence_verify_legacy_unverified(temp_db, active_session, test_record_data, mock_backend):
    """Test that legacy records with NULL integrity_hash return unverified."""
    run_id = case_session.record_plugin_run(active_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    # Simulate legacy record
    with evidence_store._conn() as conn:
        conn.execute("UPDATE evidence SET integrity_hash = NULL WHERE evidence_id = ?", (ev_id,))

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        
    assert res["valid"] is None
    assert res["status"] == "unverified"
    
    # Check evidence_get also exposes this
    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        get_res = mcp_server.evidence_get(ev_id)
    assert get_res["integrity_status"] == "unverified"
    assert get_res["integrity_hash"] is None


def test_evidence_verify_nonexistent(temp_db, active_session, mock_backend):
    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify("ev-doesnotexist")
        
    assert res["status"] == "not_found"
    assert "Evidence record not found" in res["error"]


def test_evidence_verify_cross_session(temp_db, active_session, test_record_data, mock_backend):
    """Test that a user cannot verify evidence from another session."""
    other_session = case_session.create_session("other", "other.raw", "windows")
    run_id = case_session.record_plugin_run(other_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        other_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        
    assert res["status"] == "not_found"
    assert "error" in res


def test_evidence_verify_no_active_session(temp_db, mock_backend):
    res = mcp_server.evidence_verify("ev-123")
    assert res["status"] == "invalid_request"
    assert "No active session" in res["error"]


def test_evidence_verify_complex_types(temp_db, active_session, mock_backend):
    """Test with unicode, empty dicts, and nested structures."""
    plugin = "linux_malfind"
    raw = {
        "PID": 1337,
        "Name": "e\u0301v\u00eel", # unicode
        "Hex": ["00", "FF"], # list
        "Empty": {} # empty dict
    }
    
    run_id = case_session.record_plugin_run(active_session, plugin, 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, plugin, "vol_malfind", [raw]
    )
    ev_id = ev_map["1337"][0]

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        get_res = mcp_server.evidence_get(ev_id)
        
    assert res["valid"] is True
    assert get_res["integrity_status"] == "hashed"


def test_repeated_verification_idempotent(temp_db, active_session, test_record_data, mock_backend):
    run_id = case_session.record_plugin_run(active_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res1 = mcp_server.evidence_verify(ev_id)
        res2 = mcp_server.evidence_verify(ev_id)
        
    assert res1 == res2


def test_evidence_verify_corrupted_json(temp_db, active_session, test_record_data, mock_backend):
    """Test that malformed JSON in DB causes an error instead of traceback."""
    run_id = case_session.record_plugin_run(active_session, test_record_data["plugin"], 1, 0)
    ev_map = evidence_store.store_plugin_evidence(
        active_session, run_id, test_record_data["plugin"], "vol_pstree", [test_record_data["raw"]]
    )
    ev_id = ev_map["4"][0]

    # Tamper with the database: invalid JSON
    with evidence_store._conn() as conn:
        conn.execute("UPDATE evidence SET raw = ? WHERE evidence_id = ?", ('{invalid_json:', ev_id))

    with patch("mcp_server._require_active_session", return_value={"id": active_session}):
        res = mcp_server.evidence_verify(ev_id)
        
    assert "error" in res
    assert res["status"] == "invalid_request"
