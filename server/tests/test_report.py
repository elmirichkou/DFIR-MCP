import pytest
from unittest.mock import patch
import mcp_server
import session as case_session
import evidence_store


def test_vol_report_empty_case(temp_db, mock_active_session, mock_backend):
    """Report on an empty case (no evidence, no findings)."""
    res = mcp_server.vol_report()

    assert res["report_version"] == "1.0"
    assert res["session"]["case_name"] == "test_case"
    assert res["session"]["memory_image"] == "test.raw"
    assert res["session"]["os"] == "windows"

    assert res["execution_summary"]["total_evidence_records"] == 0
    assert res["execution_summary"]["total_anomalies_flagged"] == 0
    assert res["execution_summary"]["plugins_executed"] == []

    assert res["analyst_findings"] == []
    assert res["suspicious_processes"] == []
    assert res["network_indicators"] == []
    assert res["injection_indicators"] == []
    assert res["kernel_rootkit_indicators"] == []

    # Backend NEVER called
    assert mock_backend.call_count == 0

    # Data availability should reflect absence
    assert res["data_availability"]["process_listing"] is False
    assert res["data_availability"]["network_connections"] is False

    # Limitations list must not be empty and must warn about no pool scan
    assert any("pool scan" in lim for lim in res["limitations"])


def test_vol_report_with_findings(temp_db, mock_active_session, mock_backend):
    """Report includes pinned analyst findings."""
    session_id = mock_active_session.return_value["id"]
    case_session.add_finding(session_id, "Suspicious process at PID 999", source="vol_pstree")

    res = mcp_server.vol_report()

    assert len(res["analyst_findings"]) == 1
    f = res["analyst_findings"][0]
    assert f["note"] == "Suspicious process at PID 999"
    assert f["source"] == "vol_pstree"
    assert "created_at" in f
    assert mock_backend.call_count == 0


def test_vol_report_with_process_evidence(temp_db, mock_active_session, mock_backend):
    """Report detects hidden processes from stored pstree/psscan evidence."""
    session_id = mock_active_session.return_value["id"]

    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_pstree", "vol_pstree", pstree_rows)

    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"},
    ]
    run2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run2, "win_psscan", "vol_pstree", psscan_rows)

    res = mcp_server.vol_report()
    assert mock_backend.call_count == 0

    assert res["execution_summary"]["total_evidence_records"] == 3  # 1+2
    assert res["data_availability"]["process_listing"] is True
    assert res["data_availability"]["process_scan"] is True

    assert len(res["suspicious_processes"]) == 1
    sp = res["suspicious_processes"][0]
    assert sp["pid"] == 999
    assert sp["name"] == "evil.exe"
    assert "psscan" in sp["reason"]
    assert sp["classification"] == "inferred"
    # Evidence IDs are preserved
    for ev_id in sp["evidence_ids"]:
        assert ev_id.startswith("ev-")
    assert len(sp["evidence_ids"]) == len(set(sp["evidence_ids"]))


def test_vol_report_with_network_indicators(temp_db, mock_active_session, mock_backend):
    """Report surfaces network anomalies from stored netscan evidence."""
    session_id = mock_active_session.return_value["id"]

    net_rows = [
        {"Pid": 100, "Owner": "svchost.exe", "ForeignAddr": "8.8.8.8", "ForeignPort": 443, "LocalPort": 1234},
        {"Pid": 200, "Owner": "rogue.exe", "ForeignAddr": "1.2.3.4", "ForeignPort": 4444, "LocalPort": 5678},
    ]
    run1 = case_session.record_plugin_run(session_id, "win_netscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_netscan", "vol_netscan", net_rows)

    res = mcp_server.vol_report()
    assert mock_backend.call_count == 0

    assert res["data_availability"]["network_connections"] is True
    assert len(res["network_indicators"]) > 0
    # All anomalies have evidence_ids list
    for ind in res["network_indicators"]:
        assert "evidence_ids" in ind
        assert "classification" in ind
        assert ind["classification"] == "observed"


def test_vol_report_with_malfind_evidence(temp_db, mock_active_session, mock_backend):
    """Report includes injection indicators from stored malfind evidence."""
    session_id = mock_active_session.return_value["id"]

    malfind_rows = [
        {"PID": 999, "Process": "evil.exe", "Protection": "PAGE_EXECUTE_READWRITE",
         "Start VPN": "0x1000", "End VPN": "0x2000"},
    ]
    run1 = case_session.record_plugin_run(session_id, "win_malfind", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_malfind", "vol_malfind", malfind_rows)

    res = mcp_server.vol_report()
    assert mock_backend.call_count == 0

    assert res["data_availability"]["memory_injection_scan"] is True
    assert len(res["injection_indicators"]) == 1
    ind = res["injection_indicators"][0]
    assert ind["pid"] == 999
    assert ind["protection"] == "PAGE_EXECUTE_READWRITE"
    assert ind["region"] == "0x1000-0x2000"
    assert isinstance(ind["evidence_ids"], list)
    assert ind["evidence_ids"][0].startswith("ev-")
    assert "triage" in ind["analyst_note"]


def test_vol_report_with_ssdt_evidence(temp_db, mock_active_session, mock_backend):
    """Report surfaces SSDT hook indicators from stored evidence."""
    session_id = mock_active_session.return_value["id"]

    ssdt_rows = [
        {"Table": "KiServiceTable", "Index": 5, "Offset": 0xfffff800,
         "Symbol": "NtOpenProcess"},
    ]
    run1 = case_session.record_plugin_run(session_id, "win_ssdt", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_ssdt", "vol_ssdt", ssdt_rows)

    res = mcp_server.vol_report()
    assert mock_backend.call_count == 0

    assert res["data_availability"]["kernel_modules"] is True
    assert len(res["kernel_rootkit_indicators"]) == 1
    ind = res["kernel_rootkit_indicators"][0]
    assert ind["type"] == "potential_kernel_anomaly"
    assert ind["symbol"] == "NtOpenProcess"
    assert ind["classification"] == "inferred"
    assert "evidence_ids" in ind


def test_vol_report_with_linux_bash(temp_db, mock_active_session, mock_backend):
    """Report surfaces bash history indicators."""
    session_id = mock_active_session.return_value["id"]
    bash_rows = [{"command": "rm -rf /", "user": "root"}]
    run1 = case_session.record_plugin_run(session_id, "linux_bash", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "linux_bash", "linux_bash", bash_rows)

    res = mcp_server.vol_report()
    assert res["data_availability"]["bash_history"] is True


def test_vol_report_backend_never_called(temp_db, mock_active_session, mock_backend):
    """Verify the backend is never invoked regardless of evidence state."""
    session_id = mock_active_session.return_value["id"]
    # Add various evidence types
    run1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_pstree", "vol_pstree",
                                         [{"PID": 4, "ImageFileName": "System"}])

    mcp_server.vol_report()
    assert mock_backend.call_count == 0


def test_vol_report_provenance_preserved(temp_db, mock_active_session, mock_backend):
    """Every suspicious process in the report has traceable evidence_ids."""
    session_id = mock_active_session.return_value["id"]

    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_pstree", "vol_pstree", pstree_rows)

    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 555, "PPID": 4, "ImageFileName": "spy.exe"},
    ]
    run2 = case_session.record_plugin_run(session_id, "win_psscan", 2, 0)
    evidence_store.store_plugin_evidence(session_id, run2, "win_psscan", "vol_pstree", psscan_rows)

    res = mcp_server.vol_report()

    assert len(res["suspicious_processes"]) == 1
    sp = res["suspicious_processes"][0]
    # Evidence ID must be a real stored record
    for ev_id in sp["evidence_ids"]:
        record = evidence_store.get_evidence(ev_id)
        assert record is not None
        assert record["session_id"] == session_id


def test_vol_report_session_isolation(temp_db, mock_backend):
    """Reports for different sessions contain only their own evidence."""
    s1 = case_session.create_session("case1", "m1.raw", "windows")
    s2 = case_session.create_session("case2", "m2.raw", "windows")

    # Add finding to s1
    case_session.add_finding(s1, "s1-finding", source="test")

    # Report for s2 should not see s1's findings
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": s2, "name": "case2", "image": "m2.raw",
                                 "os": "windows", "created_at": "2026-01-01"}
        res = mcp_server.vol_report()

    assert res["analyst_findings"] == []
    assert mock_backend.call_count == 0


def test_vol_report_determinism(temp_db, mock_active_session, mock_backend):
    """Running vol_report twice on the same data returns identical results."""
    session_id = mock_active_session.return_value["id"]
    case_session.add_finding(session_id, "consistent finding")
    run1 = case_session.record_plugin_run(session_id, "win_pstree", 1, 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_pstree", "vol_pstree",
                                         [{"PID": 4, "ImageFileName": "System"}])

    res1 = mcp_server.vol_report()
    res2 = mcp_server.vol_report()

    assert res1["analyst_findings"] == res2["analyst_findings"]
    assert res1["execution_summary"]["total_evidence_records"] == res2["execution_summary"]["total_evidence_records"]
    assert res1["data_availability"] == res2["data_availability"]
    assert mock_backend.call_count == 0


def test_vol_report_missing_evidence_flags_availability(temp_db, mock_active_session, mock_backend):
    """When evidence categories are missing, data_availability reflects False."""
    res = mcp_server.vol_report()

    assert res["data_availability"]["process_listing"] is False
    assert res["data_availability"]["process_scan"] is False
    assert res["data_availability"]["network_connections"] is False
    assert res["data_availability"]["memory_injection_scan"] is False
    assert res["data_availability"]["kernel_modules"] is False
    assert res["data_availability"]["analyst_findings"] is False
    # Limitation note should mention missing scan
    assert any("pool scan" in lim for lim in res["limitations"])
    assert any("network" in lim.lower() for lim in res["limitations"])


def test_vol_report_no_fabricated_evidence(temp_db, mock_active_session, mock_backend):
    """Report must not invent network connections or processes from thin air."""
    res = mcp_server.vol_report()

    # No processes, no network, no injection, no kernel indicators when there's no evidence
    assert res["suspicious_processes"] == []
    assert res["network_indicators"] == []
    assert res["injection_indicators"] == []
    assert res["kernel_rootkit_indicators"] == []
    assert res["timeline_preview"] == []
