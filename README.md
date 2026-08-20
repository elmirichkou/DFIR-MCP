# dfir-mcp

Volatility 3 memory-forensics triage exposed as MCP tools, so an LLM can
drive a first-pass investigation of a memory image and flag anomalies
instead of you reading raw plugin output line by line.

Phase 1 (this scaffold): Volatility 3 only — `pstree` and `netscan`,
with a filter layer that turns raw rows into short, structured anomaly
summaries. Designed to extend later with Eric Zimmerman's tools (disk
artifacts) and oletools (malicious documents) as separate tool families,
without touching this code.

## Architecture

```
Claude (MCP client)
       |
       v
MCP server (server/mcp_server.py)   <- session state (SQLite), filter layer
       |  HTTP
       v
Execution backend (Docker)          <- Volatility 3, runs against /images
```

The MCP server never touches the memory image or runs Volatility
directly — it only calls the backend container over HTTP. The backend
container is the only thing with filesystem access to evidence, mounted
read-only.

## Setup

### 1. Start the execution backend

```bash
docker compose up -d --build
curl localhost:8000/health   # should return {"status": "ok"}
```

### 2. Add a memory image

Drop your `.raw` / `.mem` / `.vmem` file into `./images/`. It's mounted
read-only into the container — nothing here modifies evidence.

### 3. (Optional) Add a custom symbol table

If you built a custom ISF symbol table for the image (as with a Linux
image, or a Windows build Volatility doesn't recognize out of the box),
drop it into `./symbols/`. The backend passes `--symbol-dirs /symbols`
automatically when the directory isn't empty.

### 4. Install and run the MCP server

```bash
cd server
pip install -r requirements.txt
python mcp_server.py
```

### 5. Point Claude Desktop / Claude Code at it

Add to your MCP client config:

```json
{
  "mcpServers": {
    "dfir-mcp": {
      "command": "python",
      "args": ["/absolute/path/to/dfir-mcp/server/mcp_server.py"]
    }
  }
}
```

## Usage

Once connected, in chat:

```
Start a session called "phantom" for image dump_srv.mem, os linux
Run pstree and tell me what looks off
Run netscan too
Check for hidden processes
Check for hidden kernel modules
Pin a finding about anything you found
```

Both Windows and Linux images are supported — `session_create` takes an
`os` argument ("linux" or "windows") that determines which Volatility
plugins and filter heuristics get used underneath. The tool names stay
the same either way (`vol_pstree`, `vol_netscan`); the dispatch to the
right OS-specific plugin happens inside `mcp_server.py`.

`vol_hidden_processes` and `vol_hidden_modules` go beyond a single
plugin call — they cross-reference a linked-list walk (which a rootkit
can unlink itself from) against a direct memory scan (which can't be
fooled that way). This is the same class of technique used to find a
DKOM-hidden process and a self-hiding kernel module in prior memory
forensics work — it's worth running these on any case where something
in `pstree`/`netscan` doesn't add up.

## Verifying the Volatility JSON schema

Volatility 3's JSON field names can shift slightly between versions.
Before trusting the filter heuristics on a new setup, run a plugin once
and inspect the raw output:

```bash
curl -X POST localhost:8000/run \
  -H "Content-Type: application/json" \
  -d '{"plugin": "pstree", "image": "phantom.raw"}' | python -m json.tool | head -50
```

Check that `rows[0].keys()` matches what `filters/pstree.py` expects
(`PID`, `PPID`, `ImageFileName`) — adjust the `.get()` aliases in the
filter modules if your Volatility version names them differently.

## vol_timeline — Evidence-based chronological timeline

`vol_timeline` builds a unified chronological timeline from evidence
already stored in the active investigation session.  It does **not**
execute any Volatility plugins — it reads only from the evidence ledger,
demonstrating that the evidence store supports higher-level forensic
analysis without re-running acquisition.

### How it works

After running acquisition tools (`vol_pstree`, `vol_netscan`, etc.),
call `vol_timeline` to see a combined, time-ordered view of everything
collected so far.  Evidence records that contain a genuine forensic
timestamp (currently only `linux_bash` via its `CommandTime` field)
produce **temporal events** sorted chronologically.  All other evidence
sources (process records, network connections, kernel modules) produce
**contextual events** — they carry forensic value but cannot be placed
on a timeline, so they appear after temporal events in a deterministic
order.

### Supported evidence sources

| Plugin              | Evidence type        | Temporal? | Timestamp field             |
|---------------------|----------------------|-----------|-----------------------------|
| `linux_bash`        | bash_history         | Yes       | `CommandTime` / `Command Time` |
| `linux_pslist`      | process_record       | No        | —                           |
| `linux_psscan`      | process_record       | No        | —                           |
| `linux_pstree`      | process_record       | No        | —                           |
| `win_pstree`        | process_record       | No        | —                           |
| `win_psscan`        | process_record       | No        | —                           |
| `linux_sockstat`    | network_connection   | No        | —                           |
| `win_netscan`       | network_connection   | No        | —                           |
| `linux_lsmod`       | kernel_module        | No        | —                           |
| `linux_check_modules` | suspicious_module  | No        | —                           |

### Filtering options

- **entity_id** — filter to a specific PID or entity
- **start_time / end_time** — ISO-8601 time bounds (only temporal events filtered)
- **limit** — maximum events returned (default 200)

### Ordering rules

1. Temporal events sorted chronologically by parsed timestamp.
2. Identical timestamps: stable secondary sort by (plugin, entity_id, evidence_id).
3. Contextual events grouped after all temporal events, deterministic sort.
4. Malformed timestamps treated as missing — event becomes contextual.

### Evidence provenance

Every timeline event contains an `evidence_ids` array pointing to the
exact underlying SQLite evidence records.  No IDs are fabricated — if a
mapping cannot be established, the array is empty.

## vol_bash — Linux Bash history acquisition

`vol_bash` runs the Volatility 3 `linux.bash.Bash` plugin to extract bash history from memory.
Only supported for Linux cases.

It retrieves Bash history that is resident in memory, stores raw evidence in the evidence ledger, preserves `evidence_ids` for provenance, and integrates seamlessly with `vol_timeline` and `vol_investigate_hidden`. Cached executions do not rerun Volatility.

**Important Forensic Limitation:**
Bash history is memory-resident evidence. An empty result does NOT necessarily prove that no commands were executed. History may have been cleared, disabled, unavailable, or simply no longer resident in the captured memory image. An empty list is observed evidence, not proof of absence.

## vol_malfind — Memory injection detection

`vol_malfind` runs the Volatility 3 `malfind` plugin (supporting both Windows and Linux). It identifies potentially injected or unbacked executable memory regions (such as those created by hollowed processes or injected shellcode).

**Important Forensic Limitation:**
Malfind indicators are *not* by themselves proof of malicious activity. JIT compilers (like Java or browsers) and security products often allocate unbacked executable memory regions that look identical to injection. The results of `vol_malfind` are **indicators requiring manual investigation**, not automatic proof of malware.

The output will contain:
- PID and Process name
- The memory region (Start VPN - End VPN)
- The memory protection (e.g. PAGE_EXECUTE_READWRITE)
- Disassembly and Hexdump previews of the region

## vol_modules — Windows kernel module enumeration

`vol_modules` runs the Volatility 3 `windows.modules.Modules` plugin. It enumerates the natively loaded kernel modules and drivers. This tool provides a baseline observed state. (For detecting hidden modules, use `vol_hidden_modules` instead).

The output will contain:
- Module name
- Base address
- Size
- Path/File

## vol_ssdt — Windows SSDT analysis

`vol_ssdt` runs the Volatility 3 `windows.ssdt.SSDT` plugin. It lists the System Service Descriptor Table (SSDT) entries to identify potential kernel-mode hooks.

**What constitutes a suspicious indicator:**
- entries in `KiServiceTable` that point outside of the expected kernel image (`ntoskrnl.exe`).
- entries in `W32pServiceTable` that point outside of `win32k.sys`.
- entries pointing to unknown modules or memory regions without resolved symbols.

**Limitations and False-Positive Considerations:**
- Antivirus, host protection systems (EDR), and virtualization/sandbox solutions legitimately hook the SSDT to monitor system activity.
- The presence of an SSDT hook is *not* immediate proof of a rootkit or malware. It simply indicates kernel interception. Each hook must be manually triaged by cross-referencing the offset against known drivers.

## vol_windows_investigate_hidden — Windows correlation tool

`vol_windows_investigate_hidden` correlates Windows hidden processes (found via the walk vs scan discrepancy) with other existing evidence (network connections, malfind regions, kernel modules, SSDT hooks).

It operates **entirely on stored evidence** in the active session and does not trigger new Volatility plugin runs, preserving the forensic audit log.

## vol_report — Structured investigation report

`vol_report` compiles a complete DFIR case report from all evidence and findings stored in the active session. It does **not** execute any Volatility plugins — it reads only from the SQLite evidence ledger, findings log, and plugin run history.

### Report schema

```json
{
  "report_version": "1.0",
  "session": {
    "session_id": "<id>",
    "case_name": "phantom-srv",
    "memory_image": "dump_srv.mem",
    "os": "windows",
    "created_at": "2026-08-13T10:00:00Z"
  },
  "execution_summary": {
    "plugins_executed": [
      {"plugin": "win_pstree", "row_count": 42, "anomaly_count": 0, "ran_at": "..."}
    ],
    "total_evidence_records": 87,
    "total_anomalies_flagged": 3
  },
  "analyst_findings": [
    {"id": 1, "note": "PID 999 absent from pstree", "source": "vol_hidden_processes", "created_at": "..."}
  ],
  "suspicious_processes": [
    {
      "pid": 999,
      "name": "evil.exe",
      "ppid": 4,
      "reason": "present in psscan but absent from pstree (potential DKOM unlinking)",
      "evidence_ids": ["ev-abc123"],
      "observed": true
    }
  ],
  "network_indicators": [
    {
      "type": "suspicious_port",
      "detail": "Connection to 1.2.3.4:4444 by rogue.exe (PID 999)",
      "evidence_ids": ["ev-def456"]
    }
  ],
  "injection_indicators": [
    {
      "pid": 999,
      "process": "evil.exe",
      "protection": "PAGE_EXECUTE_READWRITE",
      "evidence_id": "ev-ghi789",
      "analyst_note": "Unbacked executable memory region detected. Requires manual triage."
    }
  ],
  "kernel_rootkit_indicators": [
    {
      "type": "ssdt_hook",
      "symbol": "evil_driver!NtCreateFile",
      "detail": "SSDT entry points outside ntoskrnl.exe",
      "analyst_note": "May be a legitimate security product — requires triage.",
      "evidence_ids": ["ev-jkl012"]
    }
  ],
  "timeline_preview": [ "...up to 20 most recent events..." ],
  "data_availability": {
    "process_listing": true,
    "process_scan": true,
    "network_connections": true,
    "memory_injection_scan": false,
    "kernel_modules": false,
    "analyst_findings": true,
    "timeline": true
  },
  "limitations": [
    "This report is derived entirely from stored evidence in the current session.",
    "Injection indicators require manual triage.",
    "No attacker attribution is made in this report."
  ],
  "provenance_note": "Every indicator contains evidence_ids. Use evidence_get(evidence_id) to retrieve full raw records."
}
```

### Provenance strategy

- **No fabrication rule**: only data actually stored in the evidence ledger appears in the report.
- **`evidence_ids` in every indicator**: each `suspicious_processes`, `network_indicators`,
  `injection_indicators`, and `kernel_rootkit_indicators` entry carries the exact `ev-*` ID(s)
  of the underlying Volatility row(s). Use `evidence_get()` to drill down.
- **Observed vs inferred**: fields are labelled `"observed": true` for raw Volatility data;
  inferences (like "potential DKOM") appear in `reason` / `analyst_note` prose, not facts.
- **Data availability checklist**: if a category of evidence was never collected,
  `data_availability.<category>` is `false` and a corresponding entry appears in `limitations`
  rather than fabricating an empty list silently.
- **Analyst findings** are distinct from observed indicators — they represent the analyst's
  (or LLM's) pinned conclusions, surfaced with their original `source` annotation.

### What `vol_report` does NOT do

- Does not execute Volatility plugins.
- Does not make attacker attribution claims.
- Does not classify processes as malware — it flags indicators and leaves triage to the analyst.
- Does not invent timestamps, PIDs, addresses, or connections.

## Roadmap

- [x] Phase 1: `pstree`, `netscan`, session management, findings log — Linux and Windows
- [x] Phase 1.5: `vol_hidden_processes` (pslist/pstree vs psscan), `vol_hidden_modules`
      (lsmod vs check_modules) — DKOM and self-hiding-module detection
- [x] Phase 1.6: `vol_timeline` — evidence-based chronological timeline
- [x] Phase 2: `malfind` wired into a tool — memory injection detection
- [x] Phase 2.5: `modules` wired into a tool — Windows kernel module enumeration
- [x] Phase 2.6: `ssdt` wired into a tool — Windows SSDT hook analysis
- [x] Phase 2.7: `vol_windows_investigate_hidden` — Windows hidden process correlation
- [x] Phase 3: `vol_report` — structured JSON case report from stored evidence
- [ ] Phase 4: Eric Zimmerman tools (MFTECmd, AmcacheParser, PECmd) as a
      second tool family for disk artifacts — separate backend image
      stage (.NET runtime), separate `filters/` modules, separate MCP
      tools. No changes needed to the Volatility code above.
- [ ] Phase 5: oletools for malicious-document triage

## Safety notes

- Images and symbol tables are mounted read-only; nothing here writes
  to evidence.
- The backend has its own plugin allowlist (`ALLOWED_PLUGINS` in
  `backend/run_plugin.py`) independent of whatever tools the MCP server
  exposes — a compromised or buggy MCP layer still can't run arbitrary
  Volatility plugins or shell commands against the container.
- This is for authorized forensic work on images you own or are
  authorized to analyze (e.g. CTF/Sherlock challenges, your own lab).
