"""Cross-source corroboration (audit 49 P1#5, round 29).

Agreement across independent observers, tier-aware uplift, and the
annotate-never-rewrite contract.
"""

from __future__ import annotations

from normalization.corroboration import (corroborated_facts,
                                         corroboration_summary)


def _f(algorithm: str = "RSA", *, key_size=2048, scanner: str = "s1",
       file_path: str = "src/K.java", line: int = 3, **extra) -> dict:
    return {
        "algorithm": algorithm,
        "key_size": key_size,
        "mode": extra.get("mode"),
        "file_path": file_path,
        "line_number": line,
        "compliance_status": extra.get("compliance_status", "FAIL"),
        "scanner_ids": [scanner],
        **{k: v for k, v in extra.items()
           if k not in ("mode", "compliance_status")},
    }


def _fact(facts, file_path, line):
    return next(f for f in facts if f["file_path"] == file_path
                and f["line_number"] == line)


def test_two_independent_observers_corroborate():
    facts = corroborated_facts([
        _f(scanner="ast-scanner"), _f(scanner="regex-scanner")])
    assert len(facts) == 1
    fact = facts[0]
    assert fact["observer_count"] == 2
    assert sorted(fact["observers"]) == ["ast-scanner", "regex-scanner"]
    # both scanners are STATIC-tier names -> same-tier uplift
    assert fact["distinct_authority_tiers"] is False
    assert fact["suggested_confidence_uplift"] == 0.05


def test_same_scanner_twice_is_not_corroboration():
    assert corroborated_facts([_f(scanner="java-scanner"),
                               _f(scanner="java-scanner")]) == []


def test_single_observer_never_corroborates():
    assert corroborated_facts([_f(scanner="java-scanner")]) == []


def test_distinct_tiers_earn_the_higher_uplift():
    facts = corroborated_facts([
        _f(scanner="ast-scanner"),          # STATIC tier
        _f(scanner="runtime-probe"),        # RUNTIME tier
    ])
    fact = facts[0]
    assert fact["distinct_authority_tiers"] is True
    assert fact["suggested_confidence_uplift"] == 0.10
    assert fact["authority_tiers"] == [1, 3]


def test_three_observers_get_the_capped_uplift():
    facts = corroborated_facts([
        _f(scanner="a"), _f(scanner="b"), _f(scanner="c")])
    assert facts[0]["observer_count"] == 3
    assert facts[0]["suggested_confidence_uplift"] == 0.15


def test_partial_agreement_is_not_corroboration():
    # same algorithm, different key size: that is a conflict, and the
    # corroboration surface must not claim it
    assert corroborated_facts([
        _f(scanner="a", key_size=2048),
        _f(scanner="b", key_size=1024)]) == []
    # different algorithms likewise
    assert corroborated_facts([
        _f(algorithm="RSA", scanner="a"),
        _f(algorithm="ECDSA", key_size=256, scanner="b")]) == []


def test_agreement_and_conflict_coexist_per_site():
    # site with 3 observers: two agree, one disagrees -> the agreed pair
    # corroborates; the disagreeing observation is simply not part of it
    facts = corroborated_facts([
        _f(scanner="a"), _f(scanner="b"), _f(scanner="c", key_size=1024)])
    assert len(facts) == 1
    assert facts[0]["observer_count"] == 2


def test_algorithm_normalization_applies_to_agreement():
    # rsa vs RSA are the same agreed fact after normalization
    facts = corroborated_facts([
        _f(algorithm="rsa", scanner="a"), _f(algorithm="RSA", scanner="b")])
    assert len(facts) == 1
    assert facts[0]["algorithm"] == "RSA"


def test_unknown_observers_do_not_corroborate():
    # without scanner identity, independence cannot be established —
    # no uplift is suggested (never guessed)
    views = [
        {"algorithm": "RSA", "key_size": 2048, "file_path": "x", "line_number": 1},
        {"algorithm": "RSA", "key_size": 2048, "file_path": "x", "line_number": 1},
    ]
    assert corroborated_facts(views) == []


def test_summary_counts_and_method():
    summary = corroboration_summary([
        _f(scanner="ast-scanner"), _f(scanner="runtime-probe"),     # tier-spanned
        _f(scanner="a", file_path="y.java", line=1),
        _f(scanner="b", file_path="y.java", line=1),                # same tier
    ])
    assert summary["corroborated_count"] == 2
    assert summary["tier_spanned_count"] == 1
    assert summary["same_tier_count"] == 1
    assert summary["max_uplift"] == 0.10
    assert summary["uplift_schedule"]["cap"] == 0.15
    assert "never rewritten" in summary["method"]["contract"]
    assert "duplication" in summary["method"]["independence"]
