"""Duplicate findings must not reach the evidence chain.

The AST and regex detection paths can both report the same crypto use on
the same line. Each emitted its own evidence record, so one observed fact
was stored twice -- and the inflated number reached finding totals,
compliance percentages and CBOM component counts, which are the figures a
bank reads off the report.

These tests pin the fix at the only place it is safe: before the hash
chain is built. The evidence table is a contiguous append-only chain, so
the obvious alternative (a unique index on scan_id + content_hash) would
abort a load mid-chain, and a duplicate already stored could not be
deleted afterwards without breaking the previous_hash links around it.
"""

from __future__ import annotations

import pytest

from evidence.core.pipeline import EvidencePipeline
from evidence.hashing.content_hasher import ContentHasher


def _finding(fid: str, line: int = 42, algorithm: str = "MD5") -> dict:
    return {
        "finding_id": fid,
        "file_path": "src/crypto/legacy.py",
        "line_number": line,
        "algorithm": algorithm,
        "severity": "HIGH",
    }


def test_identical_findings_from_two_detectors_are_stored_once():
    # Same fact, different finding_id -- which is exactly what the AST and
    # regex passes produce. finding_id is in the canonical serializer's
    # EXCLUDED_FIELDS, so both hash identically.
    pipeline = EvidencePipeline(scan_session_id="scan-dup-1")
    records = pipeline.process_findings([_finding("ast-1"), _finding("regex-1")])

    assert len(records) == 1
    assert pipeline.duplicates_collapsed == 1


def test_distinct_findings_are_all_kept():
    pipeline = EvidencePipeline(scan_session_id="scan-dup-2")
    records = pipeline.process_findings([
        _finding("a", line=10),
        _finding("b", line=11),
        _finding("c", line=10, algorithm="SHA1"),
    ])

    assert len(records) == 3
    assert pipeline.duplicates_collapsed == 0


def test_chain_stays_contiguous_and_verifies_after_collapsing():
    """The property that makes this safe: no gaps, no broken links.

    A dedupe applied after chain construction would leave a hole in
    chain_position and orphan the previous_hash of the following record.
    """
    pipeline = EvidencePipeline(scan_session_id="scan-dup-3")
    records = pipeline.process_findings([
        _finding("ast-1", line=10),
        _finding("regex-1", line=10),   # duplicate of the first
        _finding("ast-2", line=20),
        _finding("regex-2", line=20),   # duplicate of the third
        _finding("ast-3", line=30),
    ])

    assert len(records) == 3
    assert pipeline.duplicates_collapsed == 2

    # Positions are 0..n-1 with no gap left by the removed records.
    assert [r.chain_position for r in records] == [0, 1, 2]

    # Genesis has no predecessor; every later link points at the one before.
    assert records[0].previous_hash is None
    for earlier, later in zip(records, records[1:]):
        assert later.previous_hash == earlier.chain_hash

    ok, error = pipeline.verify_integrity()
    assert ok, error


def test_collapse_is_reported_not_silent():
    """A detector that starts double-reporting must be visible."""
    pipeline = EvidencePipeline(scan_session_id="scan-dup-4")
    pipeline.process_findings([_finding("a"), _finding("b"), _finding("c")])
    assert pipeline.duplicates_collapsed == 2

    # The counter reflects the latest call rather than accumulating.
    pipeline.process_findings([_finding("x", line=1)])
    assert pipeline.duplicates_collapsed == 0


def test_batch_hasher_refuses_conflicting_finding_ids():
    with pytest.raises(ValueError, match="conflicting findings share finding_id"):
        ContentHasher.compute_batch([_finding("same", line=10), _finding("same", line=11)])


def test_reused_finding_id_does_not_overwrite_a_distinct_observation():
    from evidence.hashing.content_hasher import ContentHasher

    pipeline = EvidencePipeline(scan_session_id="scan-reused-id")
    records = pipeline.process_findings([
        _finding("ot-host-protocol", line=10),
        _finding("ot-host-protocol", line=11),
    ])
    assert len(records) == 2
    assert records[0].content_hash != records[1].content_hash
    assert all(r.content_hash == ContentHasher.compute_hash(r.finding) for r in records)
    assert pipeline.verify_integrity() == (True, None)


def test_evidence_strips_nuls_before_hashing():
    from evidence.hashing.content_hasher import ContentHasher

    finding = {"source": {"file_path": "bad\x00path", "line_number": 1},
               "crypto": {"algorithm": "AES"}}
    record = EvidencePipeline(scan_session_id="scan-nul").process_findings([finding])[0]
    assert record.finding["source"]["file_path"] == "badpath"
    assert record.content_hash == ContentHasher.compute_hash(record.finding)


def test_evidence_sanitizes_raw_source_before_hashing():
    finding = {
        "finding_id": "secret-test",
        "scanner_id": "test-scanner",
        "source": {"file_path": "settings.yml", "line_number": 1,
                   "code_snippet": "jwt.secret: synthetic-value-only-for-test"},
        "crypto": {"algorithm": "JWT", "api_type": "HARDCODED_KEY",
                   "raw_transformation": "synthetic-value-only-for-test"},
        "metadata": {"confidence": "HIGH", "is_hardcoded_key": True,
                     "confidence_reason": "label synthetic-value-only-for-test"},
        "untrusted_extra": "synthetic-value-only-for-test",
    }
    pipeline = EvidencePipeline(scan_session_id="scan-secret")
    records = pipeline.process_findings([finding])

    assert "synthetic-value-only-for-test" not in str(records[0].finding)
    assert records[0].finding["source"]["file_path"] == "settings.yml"
    assert records[0].finding["crypto"]["algorithm"] == "JWT"
    assert pipeline.verify_integrity() == (True, None)
