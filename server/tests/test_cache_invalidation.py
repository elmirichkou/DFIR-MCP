import json
import time
import pytest
from unittest.mock import patch
from pathlib import Path

import mcp_server
import evidence_store
import session as case_session
import image_hasher


@pytest.fixture
def test_image_dir(tmp_path):
    images_dir = tmp_path / "images"
    images_dir.mkdir()
    
    # Patch mcp_server's image dir to use our tmp_path
    with patch("mcp_server.Path") as mock_path:
        # We need Path(__file__).parent.parent / "images" to resolve to our temp dir.
        # But mocking Path globally in mcp_server is tricky, let's just create a custom patcher 
        # or we can write directly to the real images dir if this is an isolated test environment.
        pass
    
    return images_dir

@pytest.fixture
def mock_images_dir(monkeypatch, tmp_path):
    images_dir = tmp_path / "images"
    images_dir.mkdir()
    
    # Patch mcp_server so it looks here
    # We patch __file__ in mcp_server so it resolves relatively
    mcp_file = Path(mcp_server.__file__)
    # wait, the simplest is patching the code block in mcp_server that computes images_dir
    # images_dir = Path(__file__).parent.parent / "images"
    # Or just mock the resolve directly.
    return images_dir

# It's better to patch the resolution logic by overriding the Path dependency in mcp_server:
# Wait, a safer way to mock the images directory for testing without risking real file overwrites:
@pytest.fixture(autouse=True)
def mock_paths(monkeypatch, tmp_path):
    images_dir = tmp_path / "images"
    images_dir.mkdir()
    
    original_resolve = Path.resolve
    
    def mocked_resolve(self, *args, **kwargs):
        if self.name == "images" and self.parent.name == "dfir-mcp":
            return images_dir.resolve()
        # if they resolve an image file inside images_dir
        if self.parent.name == "images" and self.parent.parent.name == "dfir-mcp":
            return (images_dir / self.name).resolve()
        return original_resolve(self, *args, **kwargs)
        
    monkeypatch.setattr(Path, "resolve", mocked_resolve)
    
    # Also, clear the image_hasher cache before each test
    image_hasher._hash_cache.clear()
    
    return images_dir

@pytest.fixture
def mock_backend():
    with patch("backend_client.run_plugin") as mock_run:
        mock_run.return_value = {
            "rows": [{"PID": 1234, "COMM": "testproc"}],
            "row_count": 1
        }
        yield mock_run

def test_cache_hit_preserves_evidence(temp_db, mock_paths, mock_backend):
    """
    Requirements:
    A. Same image + same plugin + same args -> cache HIT.
    E. Cache hit preserves exact evidence_ids.
    H. The backend is not called on a valid cache hit.
    """
    image_file = mock_paths / "test.raw"
    image_file.write_bytes(b"dummy memory content")
    
    sess_id = case_session.create_session("Test Case", "test.raw", "windows")
    case_session.set_active_session(sess_id)
    
    # Run once - CACHE MISS
    rows1, run_id1, status1, ev_map1 = mcp_server._run_plugin_with_evidence(
        sess_id, "test.raw", "win_pstree", "vol_pstree"
    )
    assert status1 == "executed"
    assert mock_backend.call_count == 1
    
    # Run twice - CACHE HIT
    rows2, run_id2, status2, ev_map2 = mcp_server._run_plugin_with_evidence(
        sess_id, "test.raw", "win_pstree", "vol_pstree"
    )
    
    assert status2 == "cached"
    assert mock_backend.call_count == 1  # backend NOT called again (Requirement H)
    
    # Ev map must be strictly preserved (Requirement E)
    assert ev_map1 == ev_map2
    
def test_modified_image_contents_cache_miss(temp_db, mock_paths, mock_backend):
    """
    Requirement B: Same image filename + modified image contents -> cache MISS.
    """
    image_file = mock_paths / "test.raw"
    image_file.write_bytes(b"content 1")
    
    sess_id = case_session.create_session("Test Case", "test.raw", "windows")
    
    _, _, status1, _ = mcp_server._run_plugin_with_evidence(
        sess_id, "test.raw", "win_pstree", "vol_pstree"
    )
    assert status1 == "executed"
    assert mock_backend.call_count == 1
    
    # Sleep 0.1s to ensure mtime changes
    time.sleep(0.1)
    
    # Modify contents
    image_file.write_bytes(b"content 2")
    
    # Run again - Should MISS because hash changed
    _, _, status2, _ = mcp_server._run_plugin_with_evidence(
        sess_id, "test.raw", "win_pstree", "vol_pstree"
    )
    assert status2 == "executed"
    assert mock_backend.call_count == 2
    
def test_different_image_filename(temp_db, mock_paths, mock_backend):
    """
    Requirement C: Different image filename -> cache MISS.
    """
    img1 = mock_paths / "1.raw"
    img1.write_bytes(b"same content")
    img2 = mock_paths / "2.raw"
    img2.write_bytes(b"same content")
    
    sess_id = case_session.create_session("Test Case", "1.raw", "windows")
    
    mcp_server._run_plugin_with_evidence(sess_id, "1.raw", "win_pstree", "vol_pstree")
    assert mock_backend.call_count == 1
    
    # Query with img2
    _, _, status2, _ = mcp_server._run_plugin_with_evidence(
        sess_id, "2.raw", "win_pstree", "vol_pstree"
    )
    assert status2 == "executed"
    assert mock_backend.call_count == 2
    
def test_session_isolation(temp_db, mock_paths, mock_backend):
    """
    Requirement D: Same image contents in another session -> remains session-isolated.
    """
    img = mock_paths / "test.raw"
    img.write_bytes(b"data")
    
    sess1 = case_session.create_session("Case 1", "test.raw", "windows")
    sess2 = case_session.create_session("Case 2", "test.raw", "windows")
    
    mcp_server._run_plugin_with_evidence(sess1, "test.raw", "win_pstree", "vol_pstree")
    assert mock_backend.call_count == 1
    
    # Second session uses same image, but should miss due to session isolation
    _, _, status2, _ = mcp_server._run_plugin_with_evidence(
        sess2, "test.raw", "win_pstree", "vol_pstree"
    )
    assert status2 == "executed"
    assert mock_backend.call_count == 2
    
def test_legacy_cache_records_not_reused(temp_db, mock_paths, mock_backend):
    """
    Requirement F: Existing legacy cache records without image hash -> are not incorrectly reused.
    """
    img = mock_paths / "test.raw"
    img.write_bytes(b"data")
    
    sess_id = case_session.create_session("Legacy", "test.raw", "windows")
    
    # Inject a legacy cache record directly (image_sha256 = NULL)
    args_hash = evidence_store.hash_args([])
    with evidence_store._conn() as conn:
        conn.execute(
            "INSERT INTO plugin_cache (session_id, image, plugin, args_hash, image_sha256, plugin_run_id, rows_json, created_at) "
            "VALUES (?, ?, ?, ?, NULL, ?, ?, 'now')",
            (sess_id, "test.raw", "win_pstree", args_hash, 123, "[]")
        )
        
    # Running should result in a miss because the legacy record has a NULL hash
    _, _, status, _ = mcp_server._run_plugin_with_evidence(
        sess_id, "test.raw", "win_pstree", "vol_pstree"
    )
    
    assert status == "executed"
    assert mock_backend.call_count == 1
    
def test_image_hashing_failures(temp_db, mock_paths, mock_backend):
    """
    Requirement G: Image hashing failure produces a structured safe error.
    """
    sess_id = case_session.create_session("Err", "missing.raw", "windows")
    
    # Missing file
    with pytest.raises(ValueError, match="Image not found"):
        mcp_server._run_plugin_with_evidence(sess_id, "missing.raw", "win_pstree", "vol_pstree")
        
    # Empty file
    empty = mock_paths / "empty.raw"
    empty.write_bytes(b"")
    
    with pytest.raises(ValueError, match="Image is empty"):
        mcp_server._run_plugin_with_evidence(sess_id, "empty.raw", "win_pstree", "vol_pstree")

