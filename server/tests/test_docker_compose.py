import pytest
from pathlib import Path

def test_docker_compose_binding():
    """Verify backend container does not expose port 8000 to the LAN."""
    compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
    
    with open(compose_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert '"127.0.0.1:8000:8000"' in content, "Backend port exposed without localhost binding in docker-compose.yml"
    assert '"8000:8000"' not in content, "Backend port exposed to 0.0.0.0 in docker-compose.yml"
