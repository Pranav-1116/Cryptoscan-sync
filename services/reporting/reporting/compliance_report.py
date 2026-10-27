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
    template_id: str | None = None,
    selected_requirements: list[str] | None = None,
    policy_pack_hash: str | None = None,
    payment: dict[str, Any] | None = None,
    generated_at_iso: str | None = None,
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
    report = {
        # generated_at_iso anchors the wall clock to the scan (pin path):
        # two renderings of identical evidence must hash identically or
        # content addressing is meaningless — the same rule
        # normalize_for_snapshot applies to CBOM metadata timestamps.
        "generated_at": generated_at_iso or datetime.now(timezone.utc).isoformat(),
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
    if template_id:
        from reporting.report_templates import attestation_block, canonical_hash, evaluate_template

        payment_evidence = []
        if payment:
            # PAY-xxx findings become template evidence rows; the block itself
            # is attached verbatim so the HSM picture travels with the report
            for finding in payment.get("findings") or []:
                payment_evidence.append({
                    "rule_id": finding.get("rule_id"),
                    "standard_reference": f"Payment HSM ({finding.get('rule_id')})",
                    "result": "FAIL",
                    "file_path": f"payment-key:{finding.get('key_id') or '-'}",
                    "line_number": None,
                })
        report["template_evaluation"] = evaluate_template(
            rows, template_id, requirements=selected_requirements,
            extra_evidence=payment_evidence or None,
        )
        if payment:
            summary = dict(payment.get("summary") or {})
            summary["open_findings"] = len(payment.get("findings") or [])
            report["payment_crypto"] = summary
        report["attestation"] = attestation_block(
            scan=scan,
            policy_pack_hash=policy_pack_hash,
            evidence_count=len(rows),
        )
        # hash covers the body; re-deriving it must reproduce the same value
        report["report_hash"] = canonical_hash(
            {key: value for key, value in report.items() if key != "report_hash"}
        )
    return report


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
{_render_template_section(report)}
<p class="muted">{html.escape(str(report.get('disclaimer') or ''))}</p>
</body></html>"""


def _render_template_section(report: dict[str, Any]) -> str:
    evaluation = report.get("template_evaluation")
    if not evaluation:
        return ""
    meta = evaluation.get("template") or {}
    summary = evaluation.get("summary") or {}
    req_rows = []
    for requirement in evaluation.get("requirements") or []:
        status = str(requirement.get("status"))
        req_rows.append(
            f"<tr><td>{html.escape(str(requirement.get('id')))}</td>"
            f"<td>{html.escape(str(requirement.get('title')))}</td>"
            f"<td>{status}</td>"
            f"<td>{requirement.get('evaluated', 0)} rule results ({requirement.get('failing', 0)} failing)</td></tr>"
        )
    attestation = report.get("attestation") or {}
    return f"""
<h2>{html.escape(str(meta.get('name') or 'Template evaluation'))}</h2>
<p>{summary.get('pass', 0)}/{summary.get('total', 0)} requirements pass ·
{summary.get('fail', 0)} violations · {summary.get('not_evaluated', 0)} not evaluated ·
<strong>{summary.get('compliant_pct', 0)}% compliant</strong></p>
<table><thead><tr><th>Requirement</th><th>Title</th><th>Status</th><th>Evidence</th></tr></thead><tbody>
{''.join(req_rows)}
</tbody></table>
<p class="muted">Report hash (SHA-256, canonical JSON): <code>{html.escape(str(report.get('report_hash') or ''))}</code></p>
<p class="muted">Attestation: {html.escape(str(attestation.get('statement') or ''))}</p>
"""
