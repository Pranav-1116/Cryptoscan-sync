"""Correlating changes into patterns — and never into an incident verdict."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shared_models import attack_patterns

BASE = datetime(2026, 10, 29, 17, 0, tzinfo=timezone.utc)


def _event(index: int, minute: int, *changes: dict, severity: str = "WARNING") -> dict:
    return {
        "event_id": f"evt-{index}",
        "run_id": f"run-{index}",
        "verdict": "ESTATE_CHANGED",
        "severity": severity,
        "changes": list(changes),
        "first_detected_at": (BASE + timedelta(minutes=minute)).isoformat(),
        "last_detected_at": (BASE + timedelta(minutes=minute)).isoformat(),
    }


def _change(kind: str, subject: str, **extra) -> dict:
    return {"kind": kind, "severity": "WARNING", "subject": subject, "detail": f"{kind} on {subject}", **extra}


def test_an_empty_feed_is_not_a_clean_estate():
    result = attack_patterns.correlate([], now=BASE)

    assert result["count"] == 0
    assert result["highest_level"] == 0
    assert "not that the estate is safe" in result["note"]


def test_a_change_during_a_blind_window_is_unattributable():
    event = _event(
        1,
        3,
        _change("COVERAGE_DEGRADED", "Windows hosts"),
        _change("ASSET_ADDED", "host-77", after="HOST"),
    )
    result = attack_patterns.correlate([event], now=BASE + timedelta(minutes=10))

    pattern = next(item for item in result["patterns"] if item["name"] == "COLLECTION_BLIND_SPOT")
    assert pattern["level"] == 2
    assert pattern["level_name"] == "SUSPICIOUS_ACTIVITY"
    assert pattern["attributable"] is False
    assert any("blind window" in claim for claim in pattern["not_proven"])


def test_a_lost_plane_alone_is_a_measurement_failure_and_says_so():
    result = attack_patterns.correlate([_event(1, 1, _change("COVERAGE_DEGRADED", "Kubernetes"))], now=BASE + timedelta(minutes=2))

    pattern = result["patterns"][0]
    assert pattern["name"] == "COLLECTION_LOSS"
    assert pattern["level"] == 1
    assert "not an attack" in pattern["why"]


def test_evidence_weakening_in_two_places_is_suspicious():
    event = _event(
        1,
        5,
        _change("CRYPTO_DEMOTED", "payments-api"),
        _change("CRYPTO_DEMOTED", "auth-api"),
    )
    result = attack_patterns.correlate([event], now=BASE + timedelta(minutes=6))

    pattern = next(item for item in result["patterns"] if item["name"] == "CRYPTOGRAPHIC_REGRESSION")
    assert pattern["level"] == 2
    assert set(pattern["subjects"]) == {"payments-api", "auth-api"}


def test_one_weakened_artefact_stays_at_level_one():
    result = attack_patterns.correlate([_event(1, 5, _change("CRYPTO_DEMOTED", "payments-api"))], now=BASE + timedelta(minutes=6))
    names = {pattern["name"]: pattern for pattern in result["patterns"]}

    assert names["EVIDENCE_WEAKENED"]["level"] == 1
    assert "CRYPTOGRAPHIC_REGRESSION" not in names


def test_a_crypto_change_and_the_edge_that_reaches_it_is_a_trust_path_mutation():
    event = _event(
        1,
        2,
        _change("CRYPTO_ADDED", "payments-api"),
        _change("RELATIONSHIP_ESTABLISHED", "payments-api —uses→ hsm-01"),
    )
    result = attack_patterns.correlate([event], now=BASE + timedelta(minutes=3))

    pattern = next(item for item in result["patterns"] if item["name"] == "TRUST_PATH_MUTATION")
    assert pattern["level"] == 2


def test_new_code_plus_new_crypto_is_worth_investigating():
    event = _event(
        1,
        1,
        _change("ASSET_ADDED", "libcrypto-extra.so", after="LIBRARY"),
        _change("CRYPTO_ADDED", "host-12"),
    )
    result = attack_patterns.correlate([event], now=BASE + timedelta(minutes=2))

    pattern = next(item for item in result["patterns"] if item["name"] == "NEW_CRYPTO_SURFACE")
    assert pattern["level"] == 2
    assert any("execution" in claim for claim in pattern["not_proven"])


def test_several_change_kinds_within_minutes_is_a_burst():
    events = [
        _event(1, 0, _change("ASSET_ADDED", "host-9", after="HOST")),
        _event(2, 1, _change("CRYPTO_ADDED", "host-9")),
        _event(3, 2, _change("RELATIONSHIP_ESTABLISHED", "api —runs_on→ host-9")),
    ]
    result = attack_patterns.correlate(events, now=BASE + timedelta(minutes=5))

    pattern = next(item for item in result["patterns"] if item["name"] == "RAPID_CHANGE_BURST")
    assert pattern["level"] == 2
    assert pattern["span_seconds"] <= attack_patterns.BURST_WINDOW_SECONDS
    assert len(pattern["change_kinds"]) == 3


def test_two_independent_patterns_raise_priority_but_never_to_an_incident():
    events = [
        _event(
            1,
            0,
            _change("CRYPTO_DEMOTED", "payments-api"),
            _change("CRYPTO_DEMOTED", "auth-api"),
        ),
        _event(
            2,
            1,
            _change("CRYPTO_ADDED", "payments-api"),
            _change("RELATIONSHIP_ESTABLISHED", "payments-api —uses→ hsm-01"),
        ),
    ]
    result = attack_patterns.correlate(events, now=BASE + timedelta(minutes=3))

    correlated = next(item for item in result["patterns"] if item["name"] == "CORRELATED_ACTIVITY")
    assert correlated["level"] == 4
    assert result["highest_level"] == 4
    assert all(pattern["level"] != 3 for pattern in result["patterns"])
    assert "compromise" in correlated["not_proven"][0]


def test_the_window_is_stated_and_old_changes_are_excluded():
    old = _event(1, 0, _change("CRYPTO_DEMOTED", "a"), _change("CRYPTO_DEMOTED", "b"))
    result = attack_patterns.correlate([old], window_seconds=60, now=BASE + timedelta(hours=2))

    assert result["window_seconds"] == 60
    assert result["signals_considered"] == 0
    assert result["count"] == 0
    assert result["window"]["from"] < result["window"]["to"]


def test_a_change_without_a_timestamp_is_counted_as_undated_not_windowed():
    undated = {
        "event_id": "evt-x",
        "changes": [_change("CRYPTO_DEMOTED", "payments-api")],
    }
    result = attack_patterns.correlate([undated], now=BASE)

    assert result["undated_signals"] == 1
    assert result["signals_considered"] == 0


def test_the_same_events_always_produce_the_same_pattern_id():
    events = [
        _event(1, 0, _change("CRYPTO_DEMOTED", "payments-api"), _change("CRYPTO_DEMOTED", "auth-api")),
    ]
    first = attack_patterns.correlate(events, now=BASE + timedelta(minutes=1))
    second = attack_patterns.correlate(events, now=BASE + timedelta(minutes=2))

    assert [p["pattern_id"] for p in first["patterns"]] == [p["pattern_id"] for p in second["patterns"]]


def test_the_summary_counts_patterns_by_level_not_risk():
    events = [_event(1, 0, _change("COVERAGE_DEGRADED", "Linux hosts"))]
    result = attack_patterns.correlate(events, now=BASE)
    summary = attack_patterns.summarise(result["patterns"])

    assert summary["total"] == 1
    assert summary["by_level"]["1"] == 1
    assert "not a probability" in summary["note"]


# -- corroboration: who saw this, reported beside the level --------------------------- #


def _trust_path_event() -> dict:
    """A crypto artefact and the edge that reached it, each with its own evidence id."""
    return _event(
        1,
        0,
        {**_change("CRYPTO_ADDED", "payments-api"), "evidence_ids": ["ev-linux"]},
        {
            **_change("RELATIONSHIP_ESTABLISHED", "payments-api —uses→ hsm-01"),
            "evidence_ids": ["ev-network"],
        },
    )


def test_two_collectors_are_counted_as_independent_sources():
    result = attack_patterns.correlate(
        [_trust_path_event()],
        now=BASE + timedelta(minutes=1),
        collectors_by_evidence={"ev-linux": "linux-static", "ev-network": "network-tls"},
    )

    pattern = next(p for p in result["patterns"] if p["name"] == "TRUST_PATH_MUTATION")
    corroboration = pattern["corroboration"]
    assert corroboration["collectors"] == ["linux-static", "network-tls"]
    assert corroboration["independent_sources"] == 2
    assert corroboration["single_source"] is False
    assert corroboration["signals_with_provenance"] == 2
    assert corroboration["signals_total"] == 2
    assert "2 independent collectors" in corroboration["note"]
    # reported beside the level, never folded into it
    assert pattern["level"] == 2
    assert "not folded into it" in corroboration["does_not_change_level"]
    assert result["corroboration"]["single_source_patterns"] == 0


def test_one_collector_is_a_single_source_and_says_so():
    result = attack_patterns.correlate(
        [_trust_path_event()],
        now=BASE + timedelta(minutes=1),
        collectors_by_evidence={"ev-linux": "linux-static", "ev-network": "linux-static"},
    )

    pattern = next(p for p in result["patterns"] if p["name"] == "TRUST_PATH_MUTATION")
    assert pattern["corroboration"]["collectors"] == ["linux-static"]
    assert pattern["corroboration"]["single_source"] is True
    assert "single source" in pattern["corroboration"]["note"]
    assert result["corroboration"]["single_source_patterns"] >= 1


def test_evidence_that_cannot_be_traced_is_listed_rather_than_assumed():
    result = attack_patterns.correlate(
        [_trust_path_event()],
        now=BASE + timedelta(minutes=1),
        collectors_by_evidence={"ev-linux": "linux-static"},
    )

    pattern = next(p for p in result["patterns"] if p["name"] == "TRUST_PATH_MUTATION")
    assert pattern["corroboration"]["unmapped_evidence_ids"] == ["ev-network"]
    assert pattern["corroboration"]["signals_with_provenance"] == 1


def test_without_provenance_no_collector_is_invented():
    result = attack_patterns.correlate([_event(1, 0, _change("COVERAGE_DEGRADED", "Linux hosts"))], now=BASE + timedelta(minutes=1))

    corroboration = result["patterns"][0]["corroboration"]
    assert corroboration["collectors"] == []
    assert corroboration["independent_sources"] == 0
    assert "no collector corroborates" in corroboration["note"]
    assert "not the same as a single source" in corroboration["note"]
    assert result["corroboration"]["evidence_mapped"] == 0


def test_a_subject_fallback_is_used_only_when_a_signal_cites_no_evidence():
    event = _event(1, 0, _change("COVERAGE_DEGRADED", "Windows hosts"))
    result = attack_patterns.correlate(
        [event],
        now=BASE + timedelta(minutes=1),
        collectors_by_subject={"Windows hosts": ["windows-static"]},
    )

    corroboration = result["patterns"][0]["corroboration"]
    assert corroboration["collectors"] == ["windows-static"]
    assert corroboration["unmapped_evidence_ids"] == []
