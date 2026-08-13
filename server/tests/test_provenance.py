import pytest
import mcp_server
import evidence_store
from unittest.mock import patch

def test_pstree_provenance(temp_db, mock_active_session, mock_backend, sample_volatility_rows):
    """Test evidence_ids mapping for pstree anomalies."""
    rows = sample_volatility_rows["pstree"]
    mock_backend.return_value = {"rows": rows, "row_count": len(rows)}
    
    res = mcp_server.vol_pstree()
    
    anomalies = res["anomalies"]
    
    for anomaly in anomalies:
        if anomaly["pid"] == 100:
            # svchost with unexpected parent 4. Both exist.
            assert len(anomaly["evidence_ids"]) == 2
            for ev_id in anomaly["evidence_ids"]:
                # Ensure they actually exist in SQLite
                record = evidence_store.get_evidence(ev_id)
                assert record is not None
                assert record["raw"]["PID"] in (4, 100)
                
        elif anomaly["pid"] == 200:
            # Orphaned process, parent 500 doesn't exist, only PID 200's record mapped
            assert len(anomaly["evidence_ids"]) == 1
            record = evidence_store.get_evidence(anomaly["evidence_ids"][0])
            assert record["raw"]["PID"] == 200

def test_netscan_provenance(temp_db, mock_active_session, mock_backend, sample_volatility_rows):
    """Test evidence_ids mapping for netscan anomalies."""
    rows = sample_volatility_rows["netscan"]
    mock_backend.return_value = {"rows": rows, "row_count": len(rows)}
    
    res = mcp_server.vol_netscan()
    anomalies = res["anomalies"]
    
    for anomaly in anomalies:
        if anomaly["process"] == "evil.exe":
            assert len(anomaly["evidence_ids"]) == 1
            record = evidence_store.get_evidence(anomaly["evidence_ids"][0])
            assert record["raw"]["Pid"] == 200
        elif anomaly["process"] == "unmappable.exe":
            # unmappable entities produce [] rather than fabricated IDs
            assert anomaly["evidence_ids"] == []

def test_hidden_provenance(temp_db, mock_active_linux_session, mock_backend, sample_volatility_rows):
    """Test evidence_ids mapping for hidden anomalies."""
    pslist_rows = sample_volatility_rows["pslist"]
    psscan_rows = sample_volatility_rows["psscan"]
    
    mock_backend.side_effect = [
        {"rows": pslist_rows, "row_count": len(pslist_rows)},
        {"rows": psscan_rows, "row_count": len(psscan_rows)},
    ]
    
    res = mcp_server.vol_hidden_processes()
    anomalies = res["anomalies"]
    
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly["pid"] == 999
    
    # hidden process anomalies contain psscan evidence IDs
    assert len(anomaly["evidence_ids"]) == 1
    record = evidence_store.get_evidence(anomaly["evidence_ids"][0])
    assert record["plugin"] == "linux_psscan"
    assert record["raw"]["PID"] == 999

def test_cache_preserves_provenance(temp_db, mock_active_session, mock_backend, sample_volatility_rows):
    """Verify evidence_ids remain stable after cache hits."""
    rows = sample_volatility_rows["pstree"]
    mock_backend.return_value = {"rows": rows, "row_count": len(rows)}
    
    res1 = mcp_server.vol_pstree()
    ev_ids1 = [a["evidence_ids"] for a in res1["anomalies"]]
    
    res2 = mcp_server.vol_pstree()
    assert res2["execution_status"] == "cached"
    ev_ids2 = [a["evidence_ids"] for a in res2["anomalies"]]
    
    assert ev_ids1 == ev_ids2
