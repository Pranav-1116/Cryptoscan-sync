"""CLI for remediation suggestions + backlog. DB-free.

    python -m remediation findings.json [-o out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from remediation.engine import suggest_remediations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic remediation suggestions (offline)")
    parser.add_argument("path", help="JSON file: bare findings list or {'findings': [...]}")
    parser.add_argument("-o", "--output", help="write the JSON result to this path")
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
    findings = payload.get("findings") if isinstance(payload, dict) else payload
    result = suggest_remediations(findings or [])

    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    backlog = result["backlog"]
    print(
        f"# suggestions={result['count']} p0={result['by_priority']['P0']} "
        f"backlog_rules={backlog['total_rules']} wave1_sites={backlog['waves']['1']['site_count']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
