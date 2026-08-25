"""Deterministic HTML / JSON compliance reports. Policy is the source of truth."""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable


def render_json(
    *,
    scan: dict[str, Any],
    findings: Iterable[dict[str, Any]],
    agility: dict[str, Any] | None = None,
    quantum: dict[str, Any] | None = None,
    gate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = list(findings)
    by_status = Counter(str(row.get("compliance_status") or "UNKNOWN").upper() for row in rows)
    by_standard: dict[str, dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0})
    for row in rows:
        for rule in (row.get("policy_evaluation") or {}).get("rules_evaluated") or []:
            key = rule.get("standard_reference") or rule.get("rule_id") or "Internal"
            if str(rule.get("evaluation_result") or "").upper() == "FAIL":
                by_standard[str(key)]["fail"] += 1
            elif str(rule.get("evaluation_result") or "").upper() == "PASS":
                by_standard[str(key)]["pass"] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": scan,
        "totals": {
            "findings": len(rows),
            "pass": by_status.get("PASS", 0),
            "fail": by_status.get("FAIL", 0),
            "warn": by_status.get("WARN", 0),
        },
        "by_standard": dict(by_standard),
        "agility": agility,
        "quantum": quantum,
        "gate": gate,
        "disclaimer": "Compliance status is determined only by the policy engine.",
    }


def render_html(report: dict[str, Any]) -> str:
    scan = report.get("scan") or {}
    totals = report.get("totals") or {}
    rows = []
    for name, counts in (report.get("by_standard") or {}).items():
        rows.append(
            f"<tr><td>{html.escape(str(name))}</td><td>{counts.get('pass', 0)}</td><td>{counts.get('fail', 0)}</td></tr>"
        )
    agility = report.get("agility") or {}
    quantum = report.get("quantum") or {}
    gate = report.get("gate") or {}
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CryptoScan compliance report</title>
<style>
body {{ font-family: ui-sans-serif, system-ui; background:#0b1020; color:#e8eefc; margin:32px; }}
table {{ border-collapse: collapse; width:100%; }}
td,th {{ border-bottom:1px solid #243154; padding:8px; text-align:left; }}
.muted {{ color:#8b97b8; }}
</style></head><body>
<h1>CryptoScan compliance report</h1>
<p class="muted">{html.escape(str(scan.get('target_location') or ''))} · {html.escape(str(report.get('generated_at') or ''))}</p>
<p>Findings {totals.get('findings', 0)} · Pass {totals.get('pass', 0)} · Fail {totals.get('fail', 0)} · Warn {totals.get('warn', 0)}</p>
<p>Agility {html.escape(str(agility.get('score', '—')))} · Gate {html.escape(str(gate.get('decision', '—')))} · Quantum HNDL {html.escape(str(quantum.get('overall_hndl_risk', '—')))}</p>
<table><thead><tr><th>Standard</th><th>Pass</th><th>Fail</th></tr></thead><tbody>
{''.join(rows) or '<tr><td colspan=3 class="muted">No evaluations</td></tr>'}
</tbody></table>
<p class="muted">{html.escape(str(report.get('disclaimer') or ''))}</p>
</body></html>"""
