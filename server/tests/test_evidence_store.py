import pytest
import evidence_store
import session as case_session
import json

def test_store_raw_evidence(temp_db, active_session, sample_volatility_rows):
    """Test storing raw plugin evidence and generating evidence IDs."""
    rows = sample_volatility_rows["pstree"]
    run_id = case_session.record_plugin_run(active_session, "win_pstree", len(rows), 0)
    
    # Store evidence
    ev_map = evidence_store.store_plugin_evidence(active_session, run_id, "win_pstree", "vol_pstree", rows)
    
    assert isinstance(ev_map, dict)
    # The normal process PID 4 and anomaly svchost PID 100 should be mapped
    assert "4" in ev_map
    assert "100" in ev_map
    assert len(ev_map["4"]) == 1
    assert ev_map["4"][0].startswith("ev-")

def test_complete_raw_dictionary_preservation(temp_db, active_session, sample_volatility_rows):
    """Verify raw Volatility fields are NOT discarded."""
    rows = sample_volatility_rows["netscan"]
    run_id = case_session.record_plugin_run(active_session, "win_netscan", len(rows), 0)
    
    ev_map = evidence_store.store_plugin_evidence(active_session, run_id, "win_netscan", "vol_netscan", rows)
    
    ev_id_100 = ev_map["100"][0]
    
    record = evidence_store.get_evidence(ev_id_100)
    assert record is not None
    
    raw = record["raw"]
    assert raw["Pid"] == 100
    assert raw["Owner"] == "chrome.exe"
    assert raw["ForeignAddr"] == "8.8.8.8"
    assert raw["ForeignPort"] == 443
    assert raw["LocalPort"] == 12345

def test_evidence_get(temp_db, active_session, sample_volatility_rows):
    """Test retrieving evidence by ID."""
    rows = sample_volatility_rows["pstree"]
    run_id = case_session.record_plugin_run(active_session, "win_pstree", len(rows), 0)
    ev_map = evidence_store.store_plugin_evidence(active_session, run_id, "win_pstree", "vol_pstree", rows)
    
    ev_id = ev_map["100"][0]
    record = evidence_store.get_evidence(ev_id)
    assert record is not None
    assert record["evidence_id"] == ev_id
    assert record["session_id"] == active_session
    
    # Nonexistent evidence
    assert evidence_store.get_evidence("ev-doesnotexist") is None

def test_evidence_search_and_session_filtering(temp_db, active_session, sample_volatility_rows):
    """Test searching evidence and session filtering."""
    # Session 1
    run_id1 = case_session.record_plugin_run(active_session, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(active_session, run_id1, "win_pstree", "vol_pstree", [sample_volatility_rows["pstree"][1]])
    
    # Session 2
    session_id2 = case_session.create_session("other_case", "other.raw", "windows")
    run_id2 = case_session.record_plugin_run(session_id2, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id2, run_id2, "win_pstree", "vol_pstree", [sample_volatility_rows["pstree"][2]])
    
    # Search in session 1
    results1 = evidence_store.search_evidence(active_session, plugin="win_pstree")
    assert len(results1) == 1
    assert results1[0]["raw"]["PID"] == 100
    
    # Search in session 2
    results2 = evidence_store.search_evidence(session_id2, plugin="win_pstree")
    assert len(results2) == 1
    assert results2[0]["raw"]["PID"] == 200

def test_cache_storage_retrieval(temp_db, active_session, sample_volatility_rows):
    """Test caching plugin results and key generation."""
    rows = sample_volatility_rows["pstree"]
    args_hash = evidence_store.hash_args(["--test"])
    
    # Before cache
    cached = evidence_store.get_cached_plugin_result(active_session, "test.raw", "win_pstree", args_hash)
    assert cached is None
    
    # Store cache
    evidence_store.store_plugin_cache(active_session, "test.raw", "win_pstree", args_hash, rows, 1)
    
    # After cache
    cached = evidence_store.get_cached_plugin_result(active_session, "test.raw", "win_pstree", args_hash)
    assert cached is not None
    assert cached["plugin_run_id"] == 1
    assert cached["rows"] == rows

def test_entity_extraction_and_mapping(temp_db, active_session, sample_volatility_rows):
    """Verify entity extraction rules map processes accurately."""
    rows = sample_volatility_rows["pstree"]
    run_id = case_session.record_plugin_run(active_session, "win_pstree", len(rows), 0)
    
    # store_plugin_evidence runs _extract_entity
    ev_map = evidence_store.store_plugin_evidence(active_session, run_id, "win_pstree", "vol_pstree", rows)
    
    assert "4" in ev_map
    assert "100" in ev_map
    assert "200" in ev_map
    # PID None should not be mapped
    assert "None" not in ev_map
