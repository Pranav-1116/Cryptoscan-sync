#!/usr/bin/env python3
"""Org readiness check — measures the operational documents the auditor
will ask for first.

Same philosophy as the policy sign-off check: drafted-but-empty
documents are measured, not trusted. Scans the org artifacts and reports
per-document checks with pass/fail:

  compliance/risk-register.md          every risk: owner named, treatment
                                       valid, review date, unique IDs
  compliance/management-rep-letter.md  all 11 representations present,
                                       sign-off block complete
  compliance/quarterly-board-report.md required sections + sourced
                                       metrics
  org/training-and-awareness.md        every course: audience, cadence,
                                       owner; completion register exists
  org/joiner-mover-leaver.md           all 17 JML steps present;
                                       platform-enforced steps marked

A placeholder ``[ORG: ...]`` in an owner/signature field counts as
PENDING (the doc exists, the org hasn't filled it) — the report says
exactly which ones remain.

    python scripts/org_readiness_check.py            # human report
    python scripts/org_readiness_check.py --json     # machine-readable
    python scripts/org_readiness_check.py --strict   # exit 1 while not ready

The compliance pack embeds the JSON report (``org-readiness.json``).
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOCS = {
    "risk-register": "compliance/risk-register.md",
    "management-rep-letter": "compliance/management-rep-letter.md",
    "quarterly-board-report": "compliance/quarterly-board-report.md",
    "training-and-awareness": "org/training-and-awareness.md",
    "joiner-mover-leaver": "org/joiner-mover-leaver.md",
}

TREATMENTS = {"prevent", "detect", "respond", "transfer", "accept", "avoid"}

REPRESENTATIONS = (
    "Responsibility", "Understanding of requirements",
    "Completeness of information", "Effectiveness of controls",
    "No management override", "No fraud", "IT general controls",
    "Incidents", "Data protection", "Sub-services", "Subsequent events",
)

BOARD_SECTIONS = (
    "Executive summary", "Security posture", "Incidents",
    "Resilience & DR", "Compliance & evidence", "Forward look",
)

JML_STEPS = tuple(f"JML-J{i}" for i in range(1, 8)) \
    + tuple(f"JML-M{i}" for i in range(1, 5)) \
    + tuple(f"JML-L{i}" for i in range(1, 7))

_PLACEHOLDER = re.compile(r"\[ORG:")


def _table_rows(text: str, id_re: str) -> list[list[str]]:
    """Return the cells of every table row whose first cell matches id_re."""
    rows = []
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and re.fullmatch(id_re, cells[0]):
            rows.append(cells)
    return rows


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"name": name, "pass": bool(passed), "detail": detail}


def check_risk_register(text: str) -> list[dict]:
    rows = _table_rows(text, r"R-\d+")
    checks = [_check("has risks", len(rows) >= 5, f"{len(rows)} risks")]
    if rows:
        ids = [r[0] for r in rows]
        checks.append(_check("unique risk IDs", len(ids) == len(set(ids)),
                             f"{len(ids)} rows, {len(set(ids))} unique"))
        owned = sum(1 for r in rows if len(r) > 6
                    and r[6] and not _PLACEHOLDER.search(r[6]))
        checks.append(_check("every risk has a named owner",
                             owned == len(rows), f"{owned}/{len(rows)} named"))
        treated = sum(1 for r in rows if len(r) > 5
                      and r[5].lower() in TREATMENTS)
        checks.append(_check("every risk has a valid treatment",
                             treated == len(rows),
                             f"{treated}/{len(rows)} in {sorted(TREATMENTS)}"))
        reviewed = sum(1 for r in rows if len(r) > 8 and r[8])
        checks.append(_check("every risk has a review date",
                             reviewed == len(rows),
                             f"{reviewed}/{len(rows)} (placeholders count as set)"))
    return checks


def check_rep_letter(text: str) -> list[dict]:
    present = sum(1 for rep in REPRESENTATIONS
                  if re.search(rf"\b{re.escape(rep)}", text))
    checks = [_check("all representations present", present == len(REPRESENTATIONS),
                     f"{present}/{len(REPRESENTATIONS)}")]
    block = [ok for ok in ("CISO", "CEO", "Date") if ok in text]
    checks.append(_check("sign-off block complete",
                         len(block) == 3, f"present: {block}"))
    open_items = len(_PLACEHOLDER.findall(text))
    checks.append(_check("signed (no open placeholders)", open_items == 0,
                         f"{open_items} [ORG:] open"))
    return checks


def check_board_report(text: str) -> list[dict]:
    def _has(title: str) -> bool:
        return re.search(rf"^##\s+(?:\d+\.\s*)?{re.escape(title)}\b",
                         text, re.MULTILINE) is not None

    present = sum(1 for s in BOARD_SECTIONS if _has(s))
    checks = [_check("all sections present", present == len(BOARD_SECTIONS),
                     f"{present}/{len(BOARD_SECTIONS)}")]
    sourced = sum(1 for src in ("access-review", "risk-register", "drill")
                  if src in text)
    checks.append(_check("metrics carry named data sources",
                         sourced == 3, f"{sourced}/3 source refs"))
    return checks


def check_training(text: str) -> list[dict]:
    rows = _table_rows(text, r"T-\d+")
    checks = [_check("course matrix present", len(rows) >= 4,
                     f"{len(rows)} courses")]
    if rows:
        owned = sum(1 for r in rows if len(r) > 4
                    and r[4] and not _PLACEHOLDER.search(r[4]))
        checks.append(_check("every course has a named owner",
                             owned == len(rows), f"{owned}/{len(rows)} named"))
        full = sum(1 for r in rows if len(r) == 5 and all(r[1:5]))
        checks.append(_check("every course row complete (course/audience/cadence/owner)",
                             full == len(rows), f"{full}/{len(rows)}"))
    checks.append(_check("completion register present",
                         "Completion records" in text))
    return checks


def check_jml(text: str) -> list[dict]:
    missing = [s for s in JML_STEPS if s not in text]
    checks = [_check("all JML steps present", not missing,
                     f"{len(JML_STEPS) - len(missing)}/{len(JML_STEPS)}"
                     + (f" missing: {', '.join(missing)}" if missing else ""))]
    enforced = [s for s in ("JML-J4", "JML-L1")
                if re.search(rf"{s}.*\*\*Enforced", text)]
    checks.append(_check("platform-enforced steps marked",
                         len(enforced) == 2, f"enforced: {enforced}"))
    same_day = text.count("same day")
    checks.append(_check("leaver steps carry deadlines", same_day >= 3,
                         f"'same day' deadlines: {same_day}"))
    return checks


CHECKERS = {
    "risk-register": check_risk_register,
    "management-rep-letter": check_rep_letter,
    "quarterly-board-report": check_board_report,
    "training-and-awareness": check_training,
    "joiner-mover-leaver": check_jml,
}


def scan(docs_root: Path) -> dict:
    documents = []
    total = passed = 0
    for name, rel in DOCS.items():
        path = docs_root / rel
        if not path.exists():
            documents.append({
                "file": rel, "name": name, "status": "MISSING",
                "checks": [_check("file exists", False, str(path))],
            })
            total += 1
            continue
        checks = CHECKERS[name](path.read_text(encoding="utf-8"))
        ok = all(c["pass"] for c in checks)
        documents.append({
            "file": rel, "name": name,
            "status": "READY" if ok else "PENDING", "checks": checks,
        })
        total += len(checks)
        passed += sum(1 for c in checks if c["pass"])

    return {
        "kind": "cryptoscan-org-readiness",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "docs_root": str(docs_root),
        "documents": documents,
        "total_checks": total,
        "passed": passed,
        "failed": total - passed,
        "ready": total > 0 and passed == total,
    }


def render_human(report: dict) -> str:
    lines = [
        "Org readiness",
        "=" * 22,
        f"Checks: {report['passed']}/{report['total_checks']} passed",
        f"Status: {'READY' if report['ready'] else 'NOT READY'}",
        "",
    ]
    for d in report["documents"]:
        lines.append(f"{d['name']}  [{d['status']}]")
        for c in d["checks"]:
            mark = "ok  " if c["pass"] else "FAIL"
            lines.append(f"  [{mark}] {c['name']}" + (f" — {c['detail']}" if c["detail"] else ""))
        lines.append("")
    if not report["ready"]:
        lines.append("Close the FAIL lines (fill [ORG:] fields, name owners,")
        lines.append("sign the rep letter), then re-run this check.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="zelnx org-readiness-check",
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--docs-root", type=Path, default=ROOT / "docs")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 while any check fails (gate mode)")
    args = ap.parse_args(argv)

    report = scan(args.docs_root)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_human(report))
    return 1 if (args.strict and not report["ready"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
