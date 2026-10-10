"""Authority model tests (report 49 P0 — evidence authority hierarchy)."""

from __future__ import annotations

from normalization.authority import (
    AUTHORITY_TIERS,
    authority_preference,
    authority_tier,
)
from normalization.conflicts import (
    ALGORITHM_MISMATCH,
    detect_conflicts,
    detect_cross_scan_conflicts,
)


def _obs(algorithm: str, scanners: list[str], **extra) -> dict:
    return {
        "algorithm": algorithm,
        "key_size": 2048,
        "mode": None,
        "file_path": "src/crypto.py",
        "line_number": 10,
        "compliance_status": "FAIL",
        "scanner_ids": scanners,
        **extra,
    }


class TestAuthorityTier:
    def test_runtime_is_highest(self):
        result = authority_tier(_obs("RSA", ["live-tls-probe"]))
        assert result["tier"] == 1 and result["label"] == "RUNTIME"

    def test_runtime_via_source_dict(self):
        result = authority_tier({"source": {"type": "RUNTIME", "name": "probe"}})
        assert result["tier"] == 1 and result["label"] == "RUNTIME"

    def test_binary_ranked_below_runtime(self):
        result = authority_tier(_obs("RSA", ["binary-elf-scanner"]))
        assert result["tier"] == 2 and result["label"] == "BINARY"

    def test_static_ranked_below_binary(self):
        result = authority_tier(_obs("RSA", ["static-tree-sitter"]))
        assert result["tier"] == 3 and result["label"] == "STATIC"

    def test_declared_config(self):
        result = authority_tier(_obs("RSA", ["cloud-config-scanner"]))
        assert result["tier"] == 4 and result["label"] == "DECLARED"

    def test_manual_ranked_lowest_known(self):
        result = authority_tier(_obs("RSA", ["manual-import"]))
        assert result["tier"] == 5 and result["label"] == "MANUAL"

    def test_unknown_provenance_is_unranked_not_guessed(self):
        result = authority_tier({"algorithm": "RSA"})
        assert result["tier"] == 6 and result["label"] == "UNRANKED"

    def test_six_tiers_well_formed(self):
        assert sorted(AUTHORITY_TIERS) == [1, 2, 3, 4, 5, 6]
        assert AUTHORITY_TIERS[6] == "UNRANKED"

    def test_basis_reports_matched_signals(self):
        result = authority_tier(_obs("RSA", ["static-regex-scanner"]))
        assert any("static-regex-scanner" in b for b in result["basis"])


class TestAuthorityPreference:
    def test_runtime_beats_static_decisively(self):
        pref = authority_preference([
            _obs("RSA", ["live-tls-probe"]),
            _obs("ECDSA", ["static-tree-sitter"]),
        ])
        assert pref["decisive"] is True
        assert pref["label"] == "RUNTIME"
        assert pref["preferred"][0]["observer"] == "live-tls-probe"

    def test_tie_at_same_tier_is_not_decisive(self):
        pref = authority_preference([
            _obs("RSA", ["static-regex-scanner"]),
            _obs("ECDSA", ["static-tree-sitter"]),
        ])
        assert pref["decisive"] is False
        assert pref["label"] == "STATIC"
        assert "tie" in pref["note"]

    def test_all_unranked_is_not_decisive(self):
        pref = authority_preference([_obs("RSA", []), _obs("ECDSA", [])])
        assert pref["decisive"] is False
        assert pref["label"] == "UNRANKED"

    def test_empty_group(self):
        pref = authority_preference([])
        assert pref["decisive"] is False and pref["best_tier"] is None


class TestConflictAnnotation:
    def test_within_scan_conflict_carries_authority(self):
        conflicts = detect_conflicts([
            _obs("RSA", ["live-tls-probe"]),
            _obs("ECDSA", ["static-tree-sitter"]),
        ])
        assert len(conflicts) == 1
        c = conflicts[0]
        assert c["conflict_type"] == ALGORITHM_MISMATCH
        assert c["authority"]["decisive"] is True
        assert c["authority"]["preferred"][0]["label"] == "RUNTIME"

    def test_cross_scan_conflict_carries_authority(self):
        conflicts = detect_cross_scan_conflicts(
            [_obs("RSA", ["static-regex-scanner"])],
            [_obs("RSA-4096", ["binary-elf-scanner"], key_size=4096)],
            baseline_scan_id="s1",
            current_scan_id="s2",
        )
        assert conflicts, "key-size disagreement must be detected"
        pref = conflicts[0]["authority"]
        assert pref["decisive"] is True
        assert pref["label"] == "BINARY"
        assert conflicts[0]["baseline_scan_id"] == "s1"

    def test_observations_never_mutated(self):
        rows = [_obs("RSA", ["live-tls-probe"]), _obs("ECDSA", ["static-tree-sitter"])]
        before = [dict(r) for r in rows]
        detect_conflicts(rows)
        assert rows == before
