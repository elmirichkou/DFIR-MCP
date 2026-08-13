"""
Talks to the execution backend container over HTTP. The MCP server
never touches Volatility or the raw memory image directly — it only
ever calls this client, which calls the container.
"""
import os

import requests

BACKEND_URL = os.environ.get("DFIR_BACKEND_URL", "http://localhost:8000")


def run_plugin(plugin: str, image: str, extra_args: list[str] | None = None) -> dict:
    resp = requests.post(
        f"{BACKEND_URL}/run",
        json={"plugin": plugin, "image": image, "extra_args": extra_args or []},
        timeout=630,
    )
    resp.raise_for_status()
    return resp.json()
