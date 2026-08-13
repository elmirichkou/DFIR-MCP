"""
linux.lsmod reads the kernel's module list directly — a rootkit that
hides its own module (as with the 'singularity' module in the Phantom
case) can unlink itself from that list. linux.check_modules
cross-references against other kernel structures (sysfs) and reports
modules that are inconsistent between the two — which is where a
self-hiding module shows up.

Volatility's linux.check_modules plugin is intentionally the source of
truth here: rather than reimplementing its cross-reference logic, this
just surfaces whatever discrepancies it already found, plus the total
lsmod count for context. Its exact output columns can vary by
Volatility version — verify field names with a raw call before relying
on this against a new case.
"""


def analyze(
    lsmod_rows: list[dict],
    check_modules_rows: list[dict],
    check_modules_evidence_map: dict[str, list[str]] | None = None,
) -> dict:
    ev_map = check_modules_evidence_map or {}

    anomalies = [
        {
            "type": "hidden_or_inconsistent_module",
            "detail": "flagged by linux.check_modules as inconsistent with sysfs — "
                      "possible self-hiding rootkit module",
            "raw": row,
            "evidence_ids": ev_map.get(str(row.get("Module Name")), []) if row.get("Module Name") is not None else [],
        }
        for row in check_modules_rows
    ]

    return {
        "lsmod_count": len(lsmod_rows),
        "flagged_count": len(anomalies),
        "anomalies": anomalies,
    }
