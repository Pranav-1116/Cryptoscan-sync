"""Contract tests for normalized binary evidence and release identity."""
from __future__ import annotations

from devsecops.evidence_model import (
    compare_releases,
    enrich_record,
    normalize_evidence,
    provenance_graph,
    scan_state,
)


def _record(**overrides):
    record = {
        "format": "elf",
        "path": "bin/app",
        "parsed": True,
        "imports": ["SSL_read"],
        "exports": ["app_init"],
        "import_symbols": ["SSL_read"],
        "crypto": {
            "libraries": [{"library": "OpenSSL", "version": "3.0", "evidence_classes": ["import"]}],
            "algorithms": ["AES-GCM"],
            "algorithm_evidence": [{
                "name": "AES-GCM", "confidence": 0.92,
                "strongest_evidence": "IMPORT", "sources": ["SSL_read"],
                "verdict": "CONFIRMED_CRYPTO",
            }],
            "constants_found": [{"algorithm": "AES", "table": "aes_sbox"}],
        },
        "android": {"manifest": {"permissions": ["android.permission.INTERNET"]}},
        "embedded_keys": {"keys": [{
            "kind": "certificate", "format": "DER", "material_sha256": "a" * 64,
            "detail": {"subject": "CN=example", "secret": "must-not-escape"},
        }]},
        "sha256": "b" * 64,
    }
    record.update(overrides)
    return record


def test_normalized_evidence_has_kinds_provenance_and_runtime_caveat():
    rows = normalize_evidence(_record())
    kinds = {row["evidence_kind"] for row in rows}
    assert {"import", "export", "api", "library_match", "certificate", "manifest"} <= kinds
    assert all(row["runtime_behavior_proven"] is False for row in rows)
    assert all(row["location"]["file"] == "bin/app" for row in rows)
    assert "must-not-escape" not in str(rows)
    assert all(0 <= row["confidence"] <= 1 for row in rows)


def test_enrichment_attaches_identity_and_explicit_parser_state():
    row = enrich_record(_record())
    assert row["parser_state"] == "COMPLETE"
    assert row["identity"]["stable_id"].startswith("binary:")
    assert row["runtime_behavior_proven"] is False
    partial = enrich_record(_record(parsed=False, parse_error="truncated header"))
    assert partial["parser_state"] == "MALFORMED"
    assert any(item["evidence_kind"] == "unknown" for item in partial["evidence"])


def test_scan_state_is_partial_when_limits_or_parser_coverage_are_incomplete():
    complete = {"binaries": [_record()], "limits": {"truncated": False}}
    assert scan_state(complete) == "COMPLETE"
    limited = {"binaries": [_record()], "limits": {"budget_exhausted": True}}
    assert scan_state(limited) == "PARTIAL"
    malformed = {"binaries": [_record(parsed=False, parse_error="truncated")], "limits": {}}
    assert scan_state(malformed) == "PARTIAL"


def test_provenance_graph_has_stable_parent_child_edge():
    parent = _record(path="bundle.zip", format="zip", sha256="c" * 64)
    child = _record(path="bundle.zip!lib/app.so", derived_from="bundle.zip", depth=1,
                    sha256="d" * 64)
    enrich_record(parent)
    enrich_record(child)
    graph = provenance_graph({"binaries": [parent]})
    # The helper follows embedded records, which mirrors the scanner's nested output.
    parent["embedded"] = [child]
    graph = provenance_graph({"binaries": [parent]})
    assert len(graph["nodes"]) == 2
    assert graph["edges"][0]["relationship"] == "contains"
    assert graph["runtime_observed"] is False


def test_release_comparison_separates_crypto_changes_from_identity():
    before = enrich_record(_record())
    after = enrich_record(_record(sha256="e" * 64,
                                  crypto={"libraries": [{"library": "LibreSSL"}],
                                          "algorithms": ["ChaCha20"],
                                          "algorithm_evidence": []}))
    diff = compare_releases(before, after)
    assert diff["changed"] is True
    assert diff["changes"]["libraries"]["added"] == ["LibreSSL"]
    assert diff["changes"]["libraries"]["removed"] == ["OpenSSL"]
    assert diff["runtime_behavior_proven"] is False


def test_walk_budget_is_observable_and_not_reported_as_clean(tmp_path):
    from devsecops.binary_scan import scan_path

    (tmp_path / "blob.bin").write_bytes(b"not a recognized binary")
    result = scan_path(tmp_path, include_raw=True, max_total_bytes=1)
    assert result["result_state"] == "PARTIAL"
    assert result["limits"]["budget_exhausted"] is True
    assert result["limits"]["refused"][0]["reason"] == "global input-byte budget exhausted"
