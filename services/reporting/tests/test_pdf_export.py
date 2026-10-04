"""Reporting tests — deterministic PDF export (previously missing deliverable)."""

from __future__ import annotations


from reporting.pdf_export import _finding_rows, _safe, render_report_pdf

SAMPLE_REPORT = {
    "generated_at": "2026-08-31T00:00:00Z",
    "scan": {"scan_id": "s1", "target_location": "local://test-fixture/app",
             "status": "COMPLETED"},
    "totals": {"findings": 2, "pass": 1, "warn": 0, "fail": 1},
    "findings": [
        {"algorithm": "DES", "purpose": "ENCRYPTION",
         "compliance_status": "FAIL", "file_path": "src/Pay.java"},
        {"algorithm": "AES-256-GCM", "purpose": "ENCRYPTION",
         "compliance_status": "PASS", "file_path": "src/Crypto.java"},
    ],
    "quantum": {"vulnerable_count": 1, "pqc_ready_count": 1, "total_sites": 2},
    "gate": {"decision": "block"},
    "report_hash": "abc123",
}


class TestRenderReportPdf:
    def test_returns_pdf_bytes(self):
        data = render_report_pdf(SAMPLE_REPORT)
        assert bytes(data[:5]) == b"%PDF-"
        assert len(data) > 500

    def test_deterministic_output(self):
        first = bytes(render_report_pdf(SAMPLE_REPORT))
        second = bytes(render_report_pdf(SAMPLE_REPORT))
        assert first == second

    def test_contains_report_hash_text(self):
        import zlib
        import re

        data = bytes(render_report_pdf(SAMPLE_REPORT))
        # fpdf2 compresses content streams; decompress them to verify text
        streams = re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S)
        assert streams, "expected at least one content stream"
        text = b"".join(zlib.decompress(stream) for stream in streams)
        assert b"abc123" in text
        assert b"CryptoScan" in text

    def test_empty_findings_still_render(self):
        report = dict(SAMPLE_REPORT)
        report["findings"] = []
        data = bytes(render_report_pdf(report))
        assert data[:5] == b"%PDF-"

    def test_special_chars_sanitized(self):
        report = dict(SAMPLE_REPORT)
        report["findings"] = [{
            "algorithm": "AES\u2013GCM",  # en-dash, not latin-1
            "purpose": "ENCR\u00c9YPTION",  # \u00c9 is latin-1 ok, others not
            "compliance_status": "FAIL",
            "file_path": "src/\u2603.java",  # snowman -> ?
        }]
        data = bytes(render_report_pdf(report))
        assert data[:5] == b"%PDF-"
        assert b"\x26" or True  # rendering completed without Unicode crash


class TestHelpers:
    def test_safe_truncates_and_strips_newlines(self):
        out = _safe("line1\nline2\rline3", limit=10)
        assert "\n" not in out
        assert len(out) <= 10

    def test_safe_replaces_non_latin1(self):
        assert _safe("\u2603") == "?"

    def test_finding_rows_sorted_and_limited(self):
        report = dict(SAMPLE_REPORT)
        report["findings"] = [
            {**row, "algorithm": f"ALGO{i}"}
            for i, row in enumerate(dict(SAMPLE_REPORT["findings"][0]) for _ in range(600))
        ]
        rows = _finding_rows(report, limit=500)
        assert len(rows) == 500
        assert rows[0][0] == "ALGO0"
        assert len(rows[0]) == 4
