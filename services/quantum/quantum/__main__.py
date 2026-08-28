"""CLI for quantum risk + PQC migration planning. DB-free.

    python -m quantum findings.json [--migration-years 3] [--systems systems.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from quantum.plan import build_migration_plan, mosca
from quantum.risk import analyze_quantum_risk


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Quantum risk scoring and PQC migration planning (offline)")
    parser.add_argument("path", help="JSON file: bare findings list or {'findings': [...], 'systems': [...]}")
    parser.add_argument("--systems", help="optional systems JSON file")
    parser.add_argument("--migration-years", type=float, help="estimated migration time y for Mosca's inequality")
    parser.add_argument("--retention-years", type=int, help="data shelf-life x for Mosca's inequality")
    parser.add_argument("-o", "--output", help="write the JSON result to this path")
    parser.add_argument("--plan", action="store_true", help="emit the migration plan instead of the risk report")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        findings = payload.get("findings") or []
        systems = payload.get("systems") or []
    else:
        findings, systems = payload, []
    if args.systems:
        systems = json.loads(Path(args.systems).read_text(encoding="utf-8"))

    if args.plan:
        result = build_migration_plan(findings, systems=systems, migration_years=args.migration_years)
    else:
        result = analyze_quantum_risk(findings, systems=systems)
    result["mosca"] = mosca(
        retention_years=args.retention_years, migration_years=args.migration_years
    )

    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    if "inventory" in result:
        inv = result["inventory"]
        print(
            f"# vulnerable={inv['vulnerable_sites']}/{inv['total_sites']} "
            f"workstreams={len(result['workstreams'])} wave1={result['waves']['1']['site_count']}",
            file=sys.stderr,
        )
    else:
        print(
            f"# vulnerable={result['vulnerable_count']}/{len(result['assets'])} "
            f"hndl={result['overall_hndl_risk']}",
            file=sys.stderr,
        )
    verdict = (result.get("mosca") or {}).get("verdict")
    if verdict:
        print(f"# mosca: {verdict} — {result['mosca']['inequality']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
