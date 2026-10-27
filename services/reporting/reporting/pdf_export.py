"""Deterministic PDF export of a compliance report.

The report JSON produced by ``reporting.compliance_report.render_json`` is
rendered into a simple, deterministic A4 PDF (core Helvetica font, latin-1
sanitized). This is deliberately a *basic structured* PDF — the same content
as the JSON/HTML report, without branded layout — so the deliverable stays
reproducible and dependency-light. Signing still applies to the JSON report;
the PDF is a rendering of that signed source of truth.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:  # fpdf2 is an optional runtime dependency for PDF export only
    from fpdf import FPDF
except Exception:  # pragma: no cover - pdf export unavailable
    FPDF = None  # type: ignore[assignment]

_SAFE_ASCII = "".join(chr(c) for c in range(32, 127))

#: sentinel for reports with no parseable generated_at — deterministic and
#: visibly unanchored, rather than a wall clock that leaks the render
#: second into bytes that are supposed to be reproducible
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _creation_date(report: dict[str, Any]) -> datetime:
    """Anchor the PDF's /CreationDate to the report's OWN generated_at.

    fpdf2 otherwise stamps ``datetime.now()`` into the document info
    dict, so the SAME report content renders to different bytes on
    either side of a second boundary — re-rendering is then not
    reproducible and content addressing over rendered bytes is
    meaningless. The report's own timestamp is the honest anchor (the
    same discipline as the HBOM ``as_of`` and the CBOM scan-time
    anchoring); a report with no parseable ``generated_at`` renders
    with the epoch sentinel instead of a silently-varying wall clock.
    """
    raw = str((report or {}).get("generated_at") or "")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return _EPOCH
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe(text: Any, limit: int = 80) -> str:
    """Coerce to a latin-1-safe single-line string (PDF core fonts)."""
    value = str(text or "").replace("\n", " ").replace("\r", " ")
    return "".join(ch if ch in _SAFE_ASCII else "?" for ch in value)[:limit]


def _totals_lines(report: dict[str, Any]) -> list[tuple[str, str]]:
    totals = report.get("totals") or {}
    return [
        ("Findings", str(totals.get("findings", 0))),
        ("Pass", str(totals.get("pass", 0))),
        ("Warn", str(totals.get("warn", 0))),
        ("Fail", str(totals.get("fail", 0))),
    ]


def _finding_rows(report: dict[str, Any], limit: int = 500) -> list[tuple[str, str, str, str]]:
    rows = []
    for row in (report.get("findings") or [])[:limit]:
        algorithm = _safe(row.get("algorithm") or "UNKNOWN", 24)
        purpose = _safe(row.get("purpose") or "-", 20)
        status = _safe((row.get("compliance_status") or "UNKNOWN"), 10)
        location = _safe(row.get("file_path") or row.get("target_location") or "-", 44)
        rows.append((algorithm, purpose, status, location))
    return rows


def render_report_pdf(report: dict[str, Any]) -> bytes:
    """Render the compliance report dict to PDF bytes.

    Raises RuntimeError if fpdf2 is not installed (PDF export unavailable).
    """
    if FPDF is None:  # pragma: no cover - guarded import path
        raise RuntimeError("PDF export unavailable: install 'fpdf2'")

    pdf = FPDF(format="A4", unit="mm")
    # anchor before anything else: the document's own timestamp, never
    # the render wall clock (see _creation_date)
    pdf.set_creation_date(_creation_date(report))
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(16, 14, 16)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 9, "CryptoScan Compliance Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, _safe(f"Generated {report.get('generated_at') or ''}"), new_x="LMARGIN", new_y="NEXT")

    scan = report.get("scan") or {}
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Scan", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for key in ("scan_id", "target_location", "target_type", "operator", "status"):
        if scan.get(key):
            pdf.cell(0, 5, _safe(f"{key}: {scan[key]}", 120), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Totals", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for label, value in _totals_lines(report):
        pdf.cell(0, 5, _safe(f"{label}: {value}", 60), new_x="LMARGIN", new_y="NEXT")

    rows = _finding_rows(report)
    if rows:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(24, 6, "Algorithm", border=1)
        pdf.cell(22, 6, "Purpose", border=1)
        pdf.cell(16, 6, "Status", border=1)
        pdf.cell(0, 6, "Location", border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for algorithm, purpose, status, location in rows:
            pdf.cell(24, 5, algorithm, border=1)
            pdf.cell(22, 5, purpose, border=1)
            pdf.cell(16, 5, status, border=1)
            pdf.cell(0, 5, location, border=1, new_x="LMARGIN", new_y="NEXT")

    quantum = report.get("quantum") or {}
    if quantum:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "Quantum", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        for key in ("vulnerable_count", "pqc_ready_count", "total_sites", "overall_hndl_risk"):
            if quantum.get(key) is not None:
                pdf.cell(0, 5, _safe(f"{key}: {quantum[key]}", 80), new_x="LMARGIN", new_y="NEXT")

    gate = report.get("gate") or {}
    if gate.get("decision"):
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "Gate", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _safe(f"decision: {gate.get('decision')}", 80), new_x="LMARGIN", new_y="NEXT")

    if report.get("report_hash"):
        pdf.ln(2)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 5, _safe(f"report_hash: {report['report_hash']}", 110), new_x="LMARGIN", new_y="NEXT")

    return pdf.output()
