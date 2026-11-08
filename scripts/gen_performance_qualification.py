#!/usr/bin/env python3
"""Render the ZELNX Performance qualification report (GENERATED).

Source of truth: services/performance/performance/qualification_suite.py
over the SYNTHETIC corpus. The document is byte-stable: no timestamps,
no timings (they live in the suite's ``timings`` dict and are reported
separately). Regenerate:

    python scripts/gen_performance_qualification.py --write <path>
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "performance"))
sys.path.insert(0, str(ROOT / "shared" / "shared_models"))

from performance.qualification_suite import SCHEMA, run_suite  # noqa: E402


def render() -> str:
    result = run_suite()
    lines = [
        "# ZELNX Performance Intelligence — Qualification Report",
        "",
        "> **GENERATED — do not edit.** Source: "
        "`services/performance/performance/qualification_suite.py`.",
        "> Regenerate: `python scripts/gen_performance_qualification.py "
        "--write docs/performance/02_QUALIFICATION_REPORT.md`.",
        "",
        f"> **Status: SYNTHETIC QUALIFICATION.** Schema `{SCHEMA}`. Every",
        "> figure here comes from the deterministic SYNTHETIC corpus —",
        "> synthetic results never qualify a real-environment act. Timings",
        "> are reported separately and are never embedded in this document.",
        "",
        "## Checks",
        "",
    ]
    for check in result["checks"]:
        lines.append(f"- **{check['check']}** — {check['status']}: "
                     f"{check['detail']}")
        for finding in check.get("findings") or []:
            lines.append(f"  - {finding}")
    summary = result["summary"]
    lines += [
        "",
        f"**Summary: {summary['passed']}/{summary['total']} checks pass.**",
        "",
        "## External acts",
        "",
        "These are real-environment acts. The platform never marks them done",
        "from inside the repository:",
        "",
    ]
    for act in result["external_acts"]:
        lines.append(f"- **{act['act']}** — {act['status']}: {act['reason']}")
    lines += [
        "",
        "## Rules this harness holds",
        "",
        "- Missing telemetry is marked unknown or stale, never zero.",
        "- Metric ingestion is idempotent; recovery replays converge.",
        "- No cross-tenant metric access.",
        "- High-cardinality inputs are bounded.",
        "- Historical aggregates match raw measurements exactly for the",
        "  documented method.",
        "- Benchmark results are reproducible and never presented as",
        "  production traffic performance.",
        "- A retention plan is a projection — it never deletes originals.",
        "- Passwords, tokens and private keys are never metrics.",
        "",
        result["note"],
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--write":
        if len(args) < 2:
            print("usage: gen_performance_qualification.py --write <path>",
                  file=sys.stderr)
            return 2
        path = Path(args[1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(), encoding="utf-8")
        print(f"wrote {path}")
        return 0
    sys.stdout.write(render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
