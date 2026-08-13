import pytest
from unittest.mock import patch, Mock
import requests
import mcp_server

def test_backend_connection_error(temp_db, active_session):
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "unavailable"
        assert "Could not connect" in res["error"]

def test_backend_timeout(temp_db, active_session):
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.Timeout("Read timed out")):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "backend_timeout"
        assert "timed out" in res["error"]

def test_backend_http_400(temp_db, active_session):
    mock_resp = Mock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"detail": "Unknown plugin"}
    
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.HTTPError("400 Bad Request", response=mock_resp)):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "invalid_request"
        assert "Unknown plugin" in res["error"]

def test_backend_http_403(temp_db, active_session):
    mock_resp = Mock()
    mock_resp.status_code = 403
    mock_resp.json.return_value = {"detail": "Traversal detected"}
    
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.HTTPError("403 Forbidden", response=mock_resp)):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "unauthorized"
        assert "Traversal" in res["error"]

def test_backend_http_404(temp_db, active_session):
    mock_resp = Mock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {"detail": "Image not found"}
    
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.HTTPError("404 Not Found", response=mock_resp)):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "not_found"
        assert "Image not found" in res["error"]

def test_backend_http_500(temp_db, active_session):
    mock_resp = Mock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error from vol"
    mock_resp.json.side_effect = Exception("Not JSON")
    
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.HTTPError("500 Error", response=mock_resp)):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "backend_error"
        assert "Internal Server Error" in res["error"]
        
def test_backend_http_504(temp_db, active_session):
    mock_resp = Mock()
    mock_resp.status_code = 504
    mock_resp.json.return_value = {"detail": "Volatility timeout"}
    
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.HTTPError("504 Gateway Timeout", response=mock_resp)):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "backend_timeout"
        assert "Volatility timeout" in res["error"]

def test_unexpected_error(temp_db, active_session):
    with patch("backend_client.run_plugin", side_effect=RuntimeError("Something broke miserably")):
        res = mcp_server.vol_pstree()
        assert res.get("status") == "backend_error"
        assert "RuntimeError" in res["error"]
        assert "Something broke miserably" in res["error"]

def test_value_error(temp_db):
    # No active session
    res = mcp_server.vol_pstree()
    assert res.get("status") == "invalid_request"
    assert "No active session" in res["error"]

def test_clean_failure_leaves_no_trace(temp_db, active_session):
    """Ensure failed Volatility executions do NOT create misleading plugin_run/evidence/cache records."""
    import session as case_session
    import evidence_store
    
    runs_before = case_session.list_plugin_runs(active_session)
    ev_before = evidence_store.search_evidence(active_session, plugin="win_pstree")
    
    with patch("backend_client.run_plugin", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        res = mcp_server.vol_pstree()
        
    assert res.get("status") == "unavailable"
    
    runs_after = case_session.list_plugin_runs(active_session)
    ev_after = evidence_store.search_evidence(active_session, plugin="win_pstree")
    
    assert len(runs_before) == len(runs_after)
    assert len(ev_before) == len(ev_after)
