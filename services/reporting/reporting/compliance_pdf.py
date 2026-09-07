"""Dependency-free signed compliance PDF for SCHEDULED reports (unification).

The reporting scheduler already renders a template report (PCI-DSS 4.0, DORA,
NIST 800-131A, FIPS, SOC 2, ISO 27001, and the added NIST 800-53 / UAE PDPL)
with per-requirement pass/fail evidence and a canonical hash. This module turns
that evaluated report into a valid PDF 1.4 document using a minimal writer (no
reportlab/third-party dependency), and binds an HMAC-SHA256 signature over the
report's canonical body so the emitted PDF is deterministically verifiable.

`render_signed_pdf(report, *, signing_secret)` is the single entry point the
scheduler calls; the bytes are stable for identical inputs (useful for signing
and for not re-emailing identical artifacts).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import zlib
from typing import Any, Mapping


def _esc(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def report_signature(report: Mapping[str, Any], secret: str) -> str:
    """HMAC over the same canonical body the report hash is computed from."""
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()


def verify_report_signature(report: Mapping[str, Any], secret: str, signature: str) -> bool:
    return hmac.compare_digest(report_signature(report, secret), signature)


def _report_lines(report: Mapping[str, Any], signature: str) -> list[tuple[str, int]]:
    tmpl = report.get("template") or {}
    summary = report.get("summary") or {}
    att = report.get("attestation") or {}
    lines: list[tuple[str, int]] = []

    def line(text: str, size: int = 10, gap: bool = False):
        lines.append((text, size))
        if gap:
            lines.append(("", 6))

    line(f"CryptoScan — {tmpl.get('name', 'Compliance report')}", 16)
    line(f"Template: {tmpl.get('id', '')}    Source: {tmpl.get('source', '')}")
    scope = att.get("scope") or report.get("scope") or ""
    if scope:
        line(f"Scope: {scope}")
    if report.get("generated_at"):
        line(f"Generated: {report.get('generated_at')}")
    line(f"Compliance: {summary.get('compliant_pct', 0)}%   "
         f"PASS={summary.get('pass', 0)} FAIL={summary.get('fail', 0)} "
         f"NOT_EVALUATED={summary.get('not_evaluated', 0)}", 11, gap=True)
    if tmpl.get("mapping_note"):
        line(f"Mapping note: {tmpl['mapping_note']}", 8, gap=True)

    line("Requirement coverage and evidence", 13, gap=True)
    for req in report.get("requirements") or []:
        line(f"[{req.get('status','?'):>13}] {req.get('id',''):<14} {req.get('title','')}", 10)
        rules = ", ".join(req.get("rules") or []) or "—"
        line(f"        evidence={req.get('evaluated',0)} failing={req.get('failing',0)} rules: {rules[:80]}", 8)
        for loc in (req.get("failure_locations") or [])[:3]:
            line(f"        FAIL @ {loc}", 8)

    line("", 6)
    line(f"report_hash: {report.get('report_hash','')}", 8)
    line(f"signature (HMAC-SHA256): {signature[:32]}...", 8)
    line(att.get("statement", "")[:200], 8)
    return lines


def render_signed_pdf(report: Mapping[str, Any], *, signing_secret: str) -> bytes:
    """Produce a signed PDF 1.4 document from an evaluated template report."""
    signature = report_signature(report, signing_secret)
    lines = _report_lines(report, signature)
    pages = [lines[i:i + 46] for i in range(0, len(lines), 46)] or [[("", 10)]]
    return _build_pdf(pages, title=((report.get("template") or {}).get("name") or "Compliance"))


def _build_pdf(pages: list[list[tuple[str, int]]], *, title: str) -> bytes:
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    page_ids, content_ids, next_id = [], [], 4
    for _ in pages:
        page_ids.append(next_id); content_ids.append(next_id + 1); next_id += 2

    def stream_obj(data: bytes) -> bytes:
        comp = zlib.compress(data)
        return (b"<< /Length " + str(len(comp)).encode() + b" /Filter /FlateDecode >>\nstream\n"
                + comp + b"\nendstream")

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = b" ".join(f"{pid} 0 R".encode() for pid in page_ids)
    objects.append(b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(pages)).encode()
                   + b" /MediaBox [0 0 612 792] >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for idx, text_lines in enumerate(pages):
        pid, cid = page_ids[idx], content_ids[idx]
        content = _page_content(text_lines)
        objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       b"/Resources << /Font << /F1 3 0 R >> >> /Contents "
                       + f"{cid} 0 R".encode() + b" >>")
        objects.append(stream_obj(content.encode("latin-1", "replace")))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (b"trailer\n<< /Size " + str(len(objects)+1).encode() + b" /Root 1 0 R >>\n"
            b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n")
    return bytes(out)


def _page_content(text_lines: list[tuple[str, int]]) -> str:
    y = 740
    ops = ["BT"]
    for text, size in text_lines:
        ops.append(f"/F1 {size} Tf")
        ops.append(f"1 0 0 1 54 {y} Tm")
        ops.append(f"({_esc(text)}) Tj")
        y -= max(14, size + 4)
        if y < 60:
            break
    ops.append("ET")
    return "\n".join(ops)
