import pytest
import sqlite3
import session as case_session

def test_session_creation(temp_db):
    """Test creating a new session."""
    session_id = case_session.create_session("my_case", "image1.raw", "windows")
    assert session_id is not None
    assert isinstance(session_id, str)

def test_session_status(temp_db, active_session):
    """Test retrieving session status (get_active_session)."""
    active = case_session.get_active_session()
    assert active is not None
    assert active["id"] == active_session
    assert active["name"] == "test_case"
    assert active["image"] == "test.raw"
    assert active["os"] == "windows"

def test_record_plugin_run(temp_db, active_session):
    """Test recording a plugin run and updating anomalies."""
    run_id = case_session.record_plugin_run(active_session, "win_pstree", 100, 0)
    assert run_id > 0
    
    runs = case_session.list_plugin_runs(active_session)
    assert len(runs) == 1
    assert runs[0]["plugin"] == "win_pstree"
    assert runs[0]["row_count"] == 100
    assert runs[0]["anomaly_count"] == 0
    
    case_session.update_plugin_run_anomaly_count(run_id, 5)
    
    runs = case_session.list_plugin_runs(active_session)
    assert runs[0]["anomaly_count"] == 5

def test_findings(temp_db, active_session):
    """Test adding and listing findings."""
    finding_id1 = case_session.add_finding(active_session, "Suspicious process", "pstree")
    assert finding_id1 > 0
    
    finding_id2 = case_session.add_finding(active_session, "Unusual port", "netscan")
    assert finding_id2 > finding_id1
    
    findings = case_session.list_findings(active_session)
    assert len(findings) == 2
    assert findings[0]["note"] == "Suspicious process"
    assert findings[0]["source"] == "pstree"
    assert findings[1]["note"] == "Unusual port"
    assert findings[1]["source"] == "netscan"

def test_no_active_session(temp_db):
    """Test behavior when no active session exists."""
    active = case_session.get_active_session()
    assert active is None
