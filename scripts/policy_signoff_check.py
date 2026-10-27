#!/usr/bin/env python3
"""Policy sign-off readiness check — what still needs an owner's signature.

The SOC 2 policy pack (``docs/policies/``) is drafted with explicit
``[ORG: ...]`` placeholders wherever an organisational owner, name, date,
decision or sign-off is required. This script measures exactly what is
still unsigned: every open placeholder, per policy, with file and line.

It turns "the policies are written but unsigned" from a feeling into a
number the org can work down to zero:

    python scripts/policy_signoff_check.py          # human report
    python scripts/policy_signoff_check.py --json   # machine-readable
    python scripts/policy_signoff_check.py --strict # exit 1 while open

Exit codes: 0 = fully signed (no placeholders left), 1 = open items
remaining (or --strict with open items), 2 = error.

A placeholder is ``[ORG: ...]`` up to the first closing bracket; text may
span lines (e.g. a multi-line decision note). The compliance pack
(``scripts/compliance_pack.py``) embeds the JSON report so the auditor
sees the sign-off state inside the same artifact.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_RE = re.compile(r"\[ORG:[^\]]*\]", re.DOTALL)


def scan(policies_dir: Path) -> dict:
    files = sorted(p for p in policies_dir.glob("*.md") if p.is_file())
    if not files:
        raise SystemExit(f"error: no .md files in {policies_dir}")

    policies = []
    total = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        items = []
        for m in PLACEHOLDER_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = re.sub(r"\s+", " ", m.group(0)).strip()
            items.append({"line": line, "text": snippet})
        policies.append({
            "file": path.name,
            "open_items": len(items),
            "items": items,
        })
        total += len(items)

    return {
        "kind": "cryptoscan-policy-signoff",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy_dir": str(policies_dir),
        "policies": policies,
        "total_open": total,
        "signed": total == 0,
    }


def render_human(report: dict) -> str:
    lines = [
        "Policy sign-off readiness",
        "=" * 40,
        f"Policies scanned : {len(report['policies'])}",
        f"Open [ORG:] items: {report['total_open']}",
        f"Status           : {'FULLY SIGNED' if report['signed'] else 'AWAITING SIGN-OFF'}",
        "",
    ]
    if not report["signed"]:
        lines.append("Per policy:")
        for p in report["policies"]:
            if p["open_items"]:
                lines.append(f"  {p['file']}: {p['open_items']}")
        lines.append("")
        lines.append("Items (first 40):")
        shown = 0
        for p in report["policies"]:
            for it in p["items"]:
                if shown >= 40:
                    break
                lines.append(f"  {p['file']}:{it['line']}  {it['text'][:90]}")
                shown += 1
        if report["total_open"] > 40:
            lines.append(f"  … {report['total_open'] - 40} more — run with --json for all")
        lines.append("")
        lines.append("To close an item: replace the [ORG: ...] placeholder with the")
        lines.append("owner's decision and remove the marker, then re-run this check.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="zelnx policy-signoff-check",
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policies-dir", type=Path, default=ROOT / "docs" / "policies")
    ap.add_argument("--json", action="store_true", help="emit the JSON report")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 while any placeholder is open (gate mode)")
    args = ap.parse_args(argv)

    try:
        report = scan(args.policies_dir)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_human(report))

    if report["signed"]:
        return 0
    return 1 if args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
