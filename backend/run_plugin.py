"""
Runs inside the Docker container. Exposes a tiny HTTP API that the MCP
server (running on the host) calls to execute Volatility 3 plugins
against a memory image and get structured JSON back.

This process never talks to the LLM directly — it only knows how to
run `vol` and hand back rows. All interpretation happens in the
filter layer on the server side.
"""
import json
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="dfir-mcp execution backend")

IMAGES_DIR = Path("/images")
SYMBOLS_DIR = Path("/symbols")

# Only plugins explicitly listed here can be run. This is the backend's
# own allowlist — a second layer of safety independent of whatever the
# MCP server does, since this container is the thing with real subprocess
# access to evidence.
#
# Keys are OS-prefixed because Windows and Linux images need entirely
# different plugin classes. Verify these class paths against your own
# Volatility 3 version with `vol -h` — plugin names shift between
# releases, especially on the Linux side.
ALLOWED_PLUGINS = {
    # Windows
    "win_pstree": "windows.pstree.PsTree",
    "win_psscan": "windows.psscan.PsScan",       # pool scan — sees unlinked/hidden processes
    "win_netscan": "windows.netscan.NetScan",
    "win_malfind": "windows.malfind.Malfind",
    "win_modules": "windows.modules.Modules",
    "win_ssdt": "windows.ssdt.SSDT",

    # Linux
    "linux_pslist": "linux.pslist.PsList",       # walks the task linked list — DKOM can hide from this
    "linux_psscan": "linux.psscan.PsScan",        # scans memory directly — sees what pslist can't
    "linux_pstree": "linux.pstree.PsTree",
    "linux_bash": "linux.bash.Bash",
    "linux_lsmod": "linux.lsmod.Lsmod",           # reads the module list — a hidden module can omit itself
    "linux_check_modules": "linux.check_modules.Check_modules",  # cross-references sysfs vs lsmod
    "linux_sockstat": "linux.sockstat.Sockstat",
    "linux_malfind": "linux.malfind.Malfind",
}


class RunRequest(BaseModel):
    plugin: str          # key from ALLOWED_PLUGINS, e.g. "pstree"
    image: str            # filename under /images
    extra_args: list[str] = []


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/run")
def run_plugin(req: RunRequest):
    if req.plugin not in ALLOWED_PLUGINS:
        raise HTTPException(400, f"Unknown or disallowed plugin: {req.plugin}")

    try:
        image_path = (IMAGES_DIR / req.image).resolve(strict=False)
        images_dir_resolved = IMAGES_DIR.resolve(strict=False)
    except Exception:
        raise HTTPException(400, "Malformed image path")

    if not image_path.is_relative_to(images_dir_resolved):
        raise HTTPException(403, "Invalid image path: Traversal outside IMAGES_DIR is forbidden")

    if not image_path.is_file():
        raise HTTPException(404, f"Image not found: {req.image}")

    plugin_fqn = ALLOWED_PLUGINS[req.plugin]

    cmd = [
        "vol",
        "-q",
        "-f", str(image_path),
        "-r", "json",
    ]
    if SYMBOLS_DIR.exists() and any(SYMBOLS_DIR.iterdir()):
        cmd += ["--symbol-dirs", str(SYMBOLS_DIR)]
    cmd += [plugin_fqn, *req.extra_args]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Volatility plugin timed out after 600s")

    if result.returncode != 0:
        raise HTTPException(500, f"vol exited {result.returncode}: {result.stderr[-2000:]}")

    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, "Volatility did not return valid JSON")

    return {"plugin": req.plugin, "row_count": len(rows), "rows": rows}
