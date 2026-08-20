import os
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

import evidence_store
import session as case_session

@pytest.fixture
def temp_db(tmp_path):
    """Provides a fresh, temporary SQLite database for each test."""
    db_path = tmp_path / f"cases_{uuid.uuid4().hex}.db"
    
    # Patch the DB paths in both modules
    orig_ev_db = evidence_store.DB_PATH
    orig_sess_db = case_session.DB_PATH
    
    evidence_store.DB_PATH = db_path
    case_session.DB_PATH = db_path
    
    yield db_path
    
    evidence_store.DB_PATH = orig_ev_db
    case_session.DB_PATH = orig_sess_db
    
    if db_path.exists():
        try:
            db_path.unlink()
        except OSError:
            pass

@pytest.fixture
def temp_images_dir(tmp_path):
    """Provides a temporary images directory for testing security constraints."""
    images_dir = tmp_path / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a dummy valid image
    valid_image = images_dir / "valid_image.raw"
    valid_image.write_text("dummy")
    
    yield images_dir

@pytest.fixture
def active_session(temp_db):
    """Creates an active session and returns its ID."""
    session_id = case_session.create_session("test_case", "test.raw", "windows")
    return session_id

@pytest.fixture
def active_linux_session(temp_db):
    """Creates an active linux session and returns its ID."""
    session_id = case_session.create_session("test_linux", "linux.raw", "linux")
    return session_id

@pytest.fixture
def mock_backend():
    """Mocks backend_client.run_plugin to prevent actual Docker/backend execution."""
    with patch("mcp_server.backend_client.run_plugin") as mock_run:
        yield mock_run

@pytest.fixture(autouse=True)
def mock_image_hasher_except_in_cache_tests(request):
    if "test_cache_invalidation" in request.module.__name__:
        yield None
    else:
        with patch("mcp_server.image_hasher.get_image_hash", return_value="dummy_hash") as mock_hash:
            yield mock_hash

@pytest.fixture
def mock_active_session(active_session):
    """Mocks mcp_server._require_active_session to return our test session."""
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {
            "id": active_session,
            "name": "test_case",
            "image": "test.raw",
            "os": "windows"
        }
        yield mock_req

@pytest.fixture
def mock_active_linux_session(active_linux_session):
    """Mocks mcp_server._require_active_session to return our linux test session."""
    with patch("mcp_server._require_active_session") as mock_req:
        mock_req.return_value = {
            "id": active_linux_session,
            "name": "test_linux",
            "image": "linux.raw",
            "os": "linux"
        }
        yield mock_req

@pytest.fixture
def sample_volatility_rows():
    """Provides reusable Volatility rows for different plugins."""
    return {
        "pstree": [
            {"PID": 4, "PPID": 0, "ImageFileName": "System"},
            {"PID": 100, "PPID": 4, "ImageFileName": "svchost.exe"},
            {"PID": 200, "PPID": 500, "ImageFileName": "orphaned.exe"},
            {"PID": None, "PPID": 4, "ImageFileName": "unmappable.exe"}
        ],
        "netscan": [
            {"Pid": 100, "Owner": "chrome.exe", "ForeignAddr": "8.8.8.8", "ForeignPort": 443, "LocalPort": 12345},
            {"Pid": 200, "Owner": "evil.exe", "ForeignAddr": "1.2.3.4", "ForeignPort": 4444, "LocalPort": 12345},
            {"Pid": None, "Owner": "unmappable.exe", "ForeignAddr": "1.2.3.4", "ForeignPort": 4444, "LocalPort": 12345},
        ],
        "pslist": [
            {"PID": 4, "PPID": 0, "COMM": "System"},
            {"PID": 100, "PPID": 4, "COMM": "svchost.exe"},
        ],
        "psscan": [
            {"PID": 4, "PPID": 0, "COMM": "System"},
            {"PID": 100, "PPID": 4, "COMM": "svchost.exe"},
            {"PID": 999, "PPID": 4, "COMM": "hidden.exe"}, # hidden process
        ],
        "lsmod": [
            {"Module Name": "ext4", "Size": 1234},
            {"Module Name": "evil_mod", "Size": 666},
        ],
        "check_modules": [
            {"Module Name": "ext4", "Size": 1234},
            # evil_mod is hidden from check_modules maybe? Or lsmod vs check_modules depending on how hidden_modules works.
            # wait, hidden_modules checks if module is in lsmod but NOT in check_modules? No, check_modules bypasses the list.
            # So a hidden module is missing from lsmod, but present in check_modules!
            {"Module Name": "evil_mod", "Size": 666},
        ]
    }
