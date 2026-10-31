"""The eleven evidence planes: cited by the correlator, and fed by a real collector.

Two questions this must answer with evidence rather than prose:

* can the shipped correlator *cite* a fact from a plane — measured by running it;
* can a collector in this build *supply* one — measured by importing the producer.

A plane that passes one and fails the other is blind, and the register names it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models import attack_patterns, attack_planes

BASE = datetime(2026, 10, 31, 9, 0, tzinfo=timezone.utc)


def _event(minute: int, *changes: dict) -> dict:
    return {
        "event_id": f"evt-{minute}",
        "run_id": f"run-{minute}",
        "last_detected_at": (BASE + timedelta(minutes=minute)).isoformat(),
        "changes": list(changes),
    }


def _change(kind: str, subject: str, **extra) -> dict:
    return {"kind": kind, "severity": "WARNING", "subject": subject, "detail": f"{kind} on {subject}", **extra}


def _fact(plane: str, subject: str, relation: str = "OBSERVED", evidence: str | None = None) -> dict:
    return {
        "plane": plane,
        "subject": subject,
        "relation": relation,
        "statement": f"{plane} says {relation.lower()} about {subject}",
        "evidence_ids": [evidence or f"ev-{plane.lower()}"],
    }


def _correlate(events: list[dict], facts: list[dict]) -> dict:
    return attack_patterns.correlate(events, now=BASE + timedelta(minutes=10), plane_facts=facts)


# --------------------------------------------------------------------------- #
# the two rules
# --------------------------------------------------------------------------- #


def test_a_change_that_several_planes_describe_is_corroborated_not_escalated():
    document = _correlate(
        [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))],
        [_fact("STATIC", "payments-api"), _fact("RUNTIME", "payments-api")],
    )
    pattern = next(p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT")
    assert pattern["level"] == 2
    assert pattern["independent_planes"] == ["RUNTIME", "STATIC"]
    # agreement never reaches the incident level, which only a human may set
    assert all(p["level_name"] != "SECURITY_INCIDENT" for p in document["patterns"])
    assert any("not suspicion of intent" in line for line in pattern["not_proven"])


def test_one_plane_describing_a_subject_is_not_agreement():
    document = _correlate(
        [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))],
        [_fact("RUNTIME", "payments-api")],
    )
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]
    assert document["planes"]["subjects_corroborated"] == 0


def test_two_facts_from_one_plane_corroborate_nothing():
    document = _correlate(
        [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))],
        [
            _fact("RUNTIME", "payments-api", evidence="ev-a"),
            _fact("RUNTIME", "payments-api", evidence="ev-b"),
        ],
    )
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]
    assert document["planes"]["by_plane"]["RUNTIME"] == 2


def test_a_projected_plane_never_counts_as_a_second_witness():
    """The CBOM is built from the planes it would otherwise corroborate."""
    assert "CBOM" in attack_patterns.DERIVED_PLANES
    document = _correlate(
        [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))],
        [_fact("STATIC", "payments-api"), _fact("CBOM", "payments-api")],
    )
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]
    # it is still recorded and cited, just not counted as a witness
    assert document["planes"]["by_plane"]["CBOM"] == 1
    assert document["planes"]["subjects_corroborated"] == 0


def test_two_planes_disagreeing_is_a_finding_about_the_evidence():
    document = _correlate(
        [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))],
        [
            _fact("STATIC", "payments-api"),
            _fact("HSM", "payments-api", relation="ABSENT"),
        ],
    )
    pattern = next(p for p in document["patterns"] if p["name"] == "PLANE_CONTRADICTION")
    assert pattern["level"] == 2
    assert set(pattern["planes"]) == {"HSM", "STATIC"}
    assert "neither plane is accusing the other" in " ".join(pattern["not_proven"])
    assert set(pattern["subjects"]) == {"payments-api"}


def test_a_fact_from_a_plane_the_engine_does_not_know_is_counted_not_relabelled():
    document = _correlate(
        [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))],
        [_fact("SIEM", "payments-api"), _fact("RUNTIME", "payments-api")],
    )
    assert document["planes"]["unrecognised_plane_facts"] == 1
    assert document["planes"]["by_plane"]["NETWORK"] == 0
    assert "SIEM" not in document["planes"]["by_plane"]
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]


def test_without_plane_facts_the_result_is_unchanged():
    events = [_event(1, _change("CRYPTO_DEMOTED", "payments-api"))]
    bare = attack_patterns.correlate(events, now=BASE + timedelta(minutes=10))
    empty = attack_patterns.correlate(events, now=BASE + timedelta(minutes=10), plane_facts=[])
    assert [p["pattern_id"] for p in bare["patterns"]] == [p["pattern_id"] for p in empty["patterns"]]
    assert bare["planes"]["facts_considered"] == 0
    assert bare["planes"]["vocabulary"] == list(attack_patterns.PLANES)


# --------------------------------------------------------------------------- #
# the register measures the correlator
# --------------------------------------------------------------------------- #


def test_the_register_covers_the_vision_and_the_correlator_vocabulary():
    document = attack_planes.register()
    assert document["schema"] == "cryptoscan.attack-planes/1"
    assert tuple(row["id"] for row in document["planes"]) == attack_patterns.PLANES
    assert document["vocabulary_matches"] is True
    assert document["counts"]["planes"] == 11
    assert set(document["derived_planes"]) == set(attack_patterns.DERIVED_PLANES)


def test_every_row_states_what_it_asserts_and_what_it_cannot():
    document = attack_planes.register()
    for row in document["planes"]:
        assert row["asserts"], row["id"]
        assert row["blind_spot"], row["id"]
        assert row["producers"], f"{row['id']} declares no producer to measure"
        assert row["measurement"]["probe_statement"], row["id"]
        assert row["measurement"]["patterns_citing_plane"], row["id"]


def test_counts_are_counts_of_rows():
    document = attack_planes.register()
    rows = document["planes"]
    counts = document["counts"]
    assert counts["consumed"] == sum(1 for row in rows if row["consumed"])
    assert counts["supplied"] == sum(1 for row in rows if row["supply"] == attack_planes.SUPPLIED)
    assert counts["correlated"] == sum(1 for row in rows if row["correlated"])
    assert counts["corroborating"] == sum(1 for row in rows if row["corroborates"])
    assert counts["blind"] == len(document["blind"])
    assert counts["blind"] == counts["planes"] - counts["correlated"]
    assert "does not rank by likelihood" in document["note"]


def test_a_plane_the_correlator_stops_reading_is_reported_rejected(monkeypatch):
    """Mutation: drop the plane from the correlator's vocabulary and the row collapses."""
    monkeypatch.setattr(
        attack_planes.attack_patterns,
        "PLANES",
        tuple(plane for plane in attack_patterns.PLANES if plane != "KMS"),
    )
    document = attack_planes.register()
    row = next(item for item in document["planes"] if item["id"] == "KMS")
    assert row["reading"] == attack_planes.REJECTED
    assert row["correlated"] is False
    assert row["id"] in [item["id"] for item in document["blind"]]
    assert document["vocabulary_matches"] is False


def test_a_plane_whose_producer_is_missing_is_unsupplied(monkeypatch):
    """The supply axis is measured by import, so a removed function degrades its own row."""
    real = attack_planes.resolve_producer

    def broken(ref: str) -> dict:
        if ref.startswith("api.estate_kms"):
            return {"present": False, "reason": "ModuleNotFoundError: no module named 'api.estate_kms'"}
        return real(ref)

    monkeypatch.setattr(attack_planes, "resolve_producer", broken)
    document = attack_planes.register()
    row = next(item for item in document["planes"] if item["id"] == "KMS")
    assert row["supply"] == attack_planes.UNSUPPLIED
    assert row["correlated"] is False
    assert row["missing"] == ["api.estate_kms:collect_kms_usage"]
    # the reading half is unaffected: the correlator still cites it
    assert row["reading"] == attack_planes.CONSUMED


def test_the_measurement_does_not_depend_on_the_clock():
    first = attack_planes.register()
    second = attack_planes.register()
    assert [row["reading"] for row in first["planes"]] == [row["reading"] for row in second["planes"]]


# --------------------------------------------------------------------------- #
# stored evidence → plane facts
# --------------------------------------------------------------------------- #


def test_a_collector_supplies_facts_for_exactly_one_plane():
    records = [
        {"evidence_id": "e1", "collector": "runtime.agent.preload_trace", "target": "payments-api"},
        {"evidence_id": "e2", "collector": "api.estate_discovery:collect_pki", "target": "payments-api"},
        {"evidence_id": "e3", "collector": "some.unknown.collector", "target": "payments-api"},
        {"evidence_id": "e4", "collector": "runtime.agent.preload_trace", "target": "elsewhere"},
    ]
    facts = attack_planes.facts_from_records(records, subjects={"payments-api"})
    assert {fact["plane"] for fact in facts} == {"RUNTIME", "CERTIFICATE"}
    assert {fact["subject"] for fact in facts} == {"payments-api"}
    assert {fact["evidence_ids"][0] for fact in facts} == {"e1", "e2"}


def test_a_collector_outside_the_plane_table_produces_no_fact():
    assert attack_planes.plane_for_collector("") is None
    assert attack_planes.plane_for_collector("some.unknown.collector") is None
    assert attack_planes.plane_for_collector("cbom.inventory.builder") == "CBOM"


def test_stored_facts_then_corroborate_a_change():
    records = [
        {"evidence_id": "e1", "collector": "runtime.agent.preload_trace", "target": "payments-api"},
        {"evidence_id": "e2", "collector": "api.estate_discovery:collect_static", "target": "payments-api"},
    ]
    facts = attack_planes.facts_from_records(records, subjects={"payments-api"})
    document = _correlate([_event(1, _change("CRYPTO_DEMOTED", "payments-api"))], facts)
    pattern = next(p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT")
    assert pattern["independent_planes"] == ["RUNTIME", "STATIC"]


# --------------------------------------------------------------------------- #
# served
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_planes_register_refuses_an_anonymous_caller(client):
    anonymous = await client.get("/api/v1/estate/evidence/threat/planes")
    assert anonymous.status_code in (401, 403)


@pytest.mark.asyncio
async def test_the_planes_register_is_served(authenticated_client):
    response = await authenticated_client.get("/api/v1/estate/evidence/threat/planes")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema"] == "cryptoscan.attack-planes/1"
    assert payload["vocabulary_matches"] is True
    assert len(payload["planes"]) == 11
    assert payload["counts"]["correlated"] == payload["counts"]["planes"]
    row = payload["planes"][0]
    assert row["asserts"] and row["blind_spot"] and row["measurement"]["patterns_citing_plane"]


def test_the_committed_register_matches_a_fresh_render():
    """The document is generated, so it cannot describe a build it was not rendered from."""
    import sys
    from pathlib import Path as _Path

    sys.path.insert(0, str(_Path(__file__).resolve().parents[4] / "scripts"))
    import gen_attack_planes as gen

    committed = _Path(__file__).resolve().parents[4] / "docs" / "bank-environment" / (
        "106-attack-correlation-planes.md"
    )
    assert committed.is_file(), "regenerate with: scripts/gen_attack_planes.py --write"
    assert committed.read_text() == gen.render(attack_planes.register()), (
        "the committed correlation-plane register does not match this build — regenerate "
        "and read the diff"
    )
