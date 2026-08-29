"""Email distribution of compliance reports (W55-56 item 8) — honest SMTP.

Sends the rendered report to the schedule's recipients through the configured
SMTP host. When SMTP is not configured the result says so — we never pretend a
report was delivered. Delivery against a real server is proven by the burn-in
harness (`scripts/burn_in.py --target smtp`), not by unit tests.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any, Mapping


def render_email(report: Mapping[str, Any], *, template_id: str, schedule_name: str) -> tuple[str, str]:
    """(subject, body) for a report distribution — deterministic, hash-bearing."""
    report_hash = str(report.get("report_hash") or "")
    totals = report.get("totals") or {}
    evaluation = report.get("template_evaluation") or {}
    summary = evaluation.get("summary") or {}
    signature = report.get("signature") or {}
    subject = (
        f"CryptoScan {template_id} report — {totals.get('findings', 0)} findings, "
        f"{summary.get('fail', 0)} violations (sha256 {report_hash[:12]}…)"
    )
    lines = [
        f"Scheduled report: {schedule_name} ({template_id})",
        "",
        f"Findings: {totals.get('findings', 0)} (pass {totals.get('pass', 0)}, "
        f"fail {totals.get('fail', 0)}, warn {totals.get('warn', 0)})",
        f"Template summary: {summary.get('pass', 0)} pass / {summary.get('fail', 0)} fail / "
        f"{summary.get('not_evaluated', 0)} not evaluated"
        f" — {summary.get('compliant_pct', 0.0)}% compliant",
        "",
        f"Report hash (SHA-256, canonical JSON): {report_hash}",
    ]
    if signature.get("value"):
        lines.append(f"PKI signature: {signature.get('alg')} (key {signature.get('key_id') or 'n/a'})")
    else:
        lines.append("PKI signature: none (no signing key configured)")
    lines += [
        "",
        "The full JSON report is attached to this message and stored immutably",
        "as a snapshot in CryptoScan (`GET /api/v1/report-snapshots/{{id}}`).",
        "Compliance status is determined only by the policy engine.",
    ]
    return subject, "\n".join(lines)


def email_report(
    *,
    report: Mapping[str, Any],
    template_id: str,
    schedule_name: str,
    recipients: list[str],
    smtp_host: str = "",
    smtp_port: int = 587,
    smtp_user: str = "",
    smtp_password: str = "",
    sender: str = "cryptoscan@noreply.local",
) -> dict[str, Any]:
    """Send one report to recipients. Returns an honest status dict."""
    import json

    if not recipients:
        return {"status": "SKIPPED_NO_RECIPIENTS", "detail": "schedule has no recipients"}
    if not (smtp_host or "").strip():
        return {"status": "SKIPPED_NO_SMTP", "detail": "SMTP_HOST not configured"}

    subject, body = render_email(report, template_id=template_id, schedule_name=schedule_name)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(body)
    message.add_attachment(
        json.dumps(report, indent=2, sort_keys=True, default=str).encode("utf-8"),
        maintype="application",
        subtype="json",
        filename=f"cryptoscan-report-{str(report.get('report_hash') or 'unsigned')[:12]}.json",
    )
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if smtp_user:
                server.starttls()
                server.login(smtp_user, smtp_password)
            server.send_message(message)
    except Exception as exc:  # delivery failures are reported, never swallowed
        return {"status": "FAILED", "detail": f"{type(exc).__name__}: {exc}"[:500]}
    return {"status": "SENT", "detail": f"delivered to {len(recipients)} recipient(s)"}
