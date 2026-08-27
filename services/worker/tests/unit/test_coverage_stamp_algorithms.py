"""Regression tests for coverage-stamp algorithm extraction.

Bug: PipelineRunner._stamp_coverage read a top-level ``algorithm`` key, but
the records it receives are RawFinding dumps (``crypto.algorithm``) or
EvidenceRecord dumps (``finding.crypto.algorithm``), so every component was
stamped as UNKNOWN (e.g. ``{"UNKNOWN": 14}`` on the system CBOM summary).
"""

from __future__ import annotations

from worker.pipeline.pipeline_runner import PipelineRunner


RAW_FINDING = {
    "finding_id": "f-1",
    "source": {"file_path": "A.java", "line_number": 3},
    "crypto": {"algorithm": "AES", "mode": "GCM"},
    "metadata": {},
}
EVIDENCE_RECORD = {
    "evidence_id": "e-1",
    "scan_id": "s-1",
    "content_hash": "x",
    "finding": RAW_FINDING,
    "created_at": "2026-01-01T00:00:00Z",
}
FLAT_RECORD = {"algorithm": "TLS", "host": "example.com"}


def test_raw_finding_dump_extracts_nested_crypto_algorithm():
    assert PipelineRunner._record_algorithm(RAW_FINDING) == "AES"


def test_evidence_record_dump_extracts_finding_crypto_algorithm():
    assert PipelineRunner._record_algorithm(EVIDENCE_RECORD) == "AES"


def test_flat_record_extracts_top_level_algorithm():
    assert PipelineRunner._record_algorithm(FLAT_RECORD) == "TLS"


def test_flat_finding_inside_evidence_record():
    record = {"finding": {"algorithm": "MD5"}, "evidence_id": "e-2"}
    assert PipelineRunner._record_algorithm(record) == "MD5"


def test_object_record_uses_attribute():
    class Obj:
        algorithm = "RSA"

    assert PipelineRunner._record_algorithm(Obj()) == "RSA"


def test_unrecognized_shapes_fall_back_to_unknown():
    assert PipelineRunner._record_algorithm({}) == "UNKNOWN"
    assert PipelineRunner._record_algorithm({"crypto": {}}) == "UNKNOWN"
    assert PipelineRunner._record_algorithm(None) == "UNKNOWN"
    assert PipelineRunner._record_algorithm({"finding": {"no": "algo"}}) == "UNKNOWN"
