"""Joining the planes on a subject — which first has to mean one asset.

The failure mode this guards against is cheap and looks like success: group by the
string each collector used and a four-spelling host becomes four subjects, so no
correlation ever fires. The opposite failure is worse — merging two hosts that
share a name — so resolution is exact-key only and refuses ambiguity.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models import attack_patterns, subject_resolution as S

BASE = datetime(2026, 10, 31, 9, 0, tzinfo=timezone.utc)


def _assets() -> list[dict]:
    return [
        {
            "asset_id": "HOST-payments",
            "name": "payments-api",
            "type": "HOST",
            "identity": {
                "hostname": "alb-payments-01",
                "ip": "10.0.3.4",
                "spiffe_id": "spiffe://bank.example/ns/payments/sa/api",
            },
        },
        {"asset_id": "HOST-auth", "name": "auth-api", "identity": {"hostname": "alb-auth-01"}},
    ]


def _event(minute: int, subject: str, kind: str = "CRYPTO_DEMOTED") -> dict:
    return {
        "event_id": f"evt-{minute}",
        "last_detected_at": (BASE + timedelta(minutes=minute)).isoformat(),
        "changes": [{"kind": kind, "severity": "WARNING", "subject": subject}],
    }


def _fact(plane: str, subject: str, relation: str = "OBSERVED") -> dict:
    return {
        "plane": plane,
        "subject": subject,
        "relation": relation,
        "statement": f"{plane} on {subject}",
        "evidence_ids": [f"ev-{plane.lower()}-{subject}"],
    }


# --------------------------------------------------------------------------- #
# normalisation and classification are about spelling only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "scheme", "value"),
    [
        ("spiffe://bank.example/ns/payments/sa/api/", "SPIFFE", "spiffe://bank.example/ns/payments/sa/api"),
        ("Payments.Bank.Example.:443", "DNS", "payments.bank.example"),
        ("10.0.3.4:8443", "IP", "10.0.3.4"),
        ("alb-payments-01", "NAME", "alb-payments-01"),
        ("  10.0.3.4  ", "IP", "10.0.3.4"),
    ],
)
def test_a_subject_is_classified_by_shape_never_by_similarity(raw, scheme, value):
    assert S.classify(raw) == (scheme, value)


def test_an_empty_subject_resolves_to_nothing_and_says_so():
    index = S.SubjectIndex.from_assets(_assets())
    resolution = index.resolve("   ")
    assert resolution.status == S.UNRESOLVED
    assert resolution.reason == "empty subject"


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #


def test_the_four_spellings_of_one_host_resolve_to_one_asset():
    index = S.SubjectIndex.from_assets(_assets())
    for subject, scheme in (
        ("alb-payments-01", "HOST"),
        ("payments-api", "NAME"),
        ("10.0.3.4:443", "IP"),
        ("spiffe://bank.example/ns/payments/sa/api", "SPIFFE"),
        ("HOST-payments", "ASSET_ID"),
    ):
        resolution = index.resolve(subject)
        assert resolution.status == S.RESOLVED, subject
        assert resolution.asset_id == "HOST-payments"
        assert resolution.scheme == scheme


def test_an_unknown_name_is_unresolved_rather_than_guessed():
    index = S.SubjectIndex.from_assets(_assets())
    resolution = index.resolve("alb-payments-02")
    assert resolution.status == S.UNRESOLVED
    assert resolution.asset_id is None
    assert "no asset in this estate" in (resolution.reason or "")


def test_nothing_is_merged_by_prefix_or_first_label():
    """`alb-payments-01` must not resolve to `alb-payments` by trimming."""
    index = S.SubjectIndex.from_assets(
        [{"asset_id": "HOST-x", "name": "alb-payments", "identity": {"hostname": "alb-payments"}}]
    )
    assert index.resolve("alb-payments-01").status == S.UNRESOLVED
    assert index.resolve("payments").status == S.UNRESOLVED


def test_two_assets_claiming_one_key_refuse_rather_than_pick():
    index = S.SubjectIndex.from_assets(
        [
            {"asset_id": "HOST-a", "name": "payments-api", "identity": {"hostname": "payments"}},
            {"asset_id": "HOST-b", "name": "payments-worker", "identity": {"hostname": "payments"}},
        ]
    )
    resolution = index.resolve("payments")
    assert resolution.status == S.AMBIGUOUS
    assert resolution.asset_id is None
    assert resolution.candidates == ("HOST-a", "HOST-b")
    assert "merging would join unrelated assets" in (resolution.reason or "")
    # and the index reports the collision instead of hiding it
    assert index.as_dict()["ambiguous_keys"]["HOST"]["payments"] == ["HOST-a", "HOST-b"]


def test_two_hosts_with_the_same_short_name_stay_apart():
    index = S.SubjectIndex.from_assets(
        [
            {"asset_id": "HOST-1", "name": "api", "identity": {"dns": "api.payments.example"}},
            {"asset_id": "HOST-2", "name": "api", "identity": {"dns": "api.auth.example"}},
        ]
    )
    # the bare name is claimed by both, so it refuses instead of picking one
    assert index.resolve("api").status == S.AMBIGUOUS
    # the DNS names are unambiguous
    assert index.resolve("api.payments.example").asset_id == "HOST-1"
    assert index.resolve("api.auth.example").asset_id == "HOST-2"


def test_the_index_is_deterministic():
    first = S.SubjectIndex.from_assets(_assets()).as_dict()
    second = S.SubjectIndex.from_assets(_assets()).as_dict()
    assert first == second


# --------------------------------------------------------------------------- #
# correlation over resolved subjects
# --------------------------------------------------------------------------- #


def test_a_change_and_two_planes_naming_one_host_differently_do_not_agree():
    """The pre-resolution behaviour, kept as the baseline this work has to beat."""
    document = attack_patterns.correlate(
        [_event(1, "alb-payments-01")],
        now=BASE + timedelta(minutes=5),
        plane_facts=[_fact("RUNTIME", "payments-api"), _fact("NETWORK", "10.0.3.4:443")],
    )
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]
    assert document["subjects"]["state"] == "NOT_RESOLVED"


def test_with_resolution_the_same_three_names_are_one_subject():
    index = S.SubjectIndex.from_assets(_assets())
    document = attack_patterns.correlate(
        [_event(1, "alb-payments-01")],
        now=BASE + timedelta(minutes=5),
        plane_facts=[_fact("RUNTIME", "payments-api"), _fact("NETWORK", "10.0.3.4:443")],
        subject_index=index,
    )
    pattern = next(p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT")
    assert pattern["asset"] == "HOST-payments"
    assert pattern["subjects"] == ["10.0.3.4:443", "alb-payments-01", "payments-api"]
    assert pattern["independent_planes"] == ["NETWORK", "RUNTIME"]
    assert document["subjects"]["merged_subjects"] == [
        {"asset_id": "HOST-payments", "subjects": ["10.0.3.4:443", "alb-payments-01", "payments-api"]}
    ]
    assert document["subjects"]["by_scheme"] == {"HOST": 1, "IP": 1, "NAME": 1}


def test_an_ambiguous_subject_is_never_grouped_into_either_asset():
    index = S.SubjectIndex.from_assets(
        [
            {"asset_id": "HOST-a", "name": "payments", "identity": {"hostname": "payments-a"}},
            {"asset_id": "HOST-b", "name": "payments", "identity": {"hostname": "payments-b"}},
        ]
    )
    document = attack_patterns.correlate(
        [_event(1, "payments")],
        now=BASE + timedelta(minutes=5),
        plane_facts=[_fact("RUNTIME", "payments"), _fact("NETWORK", "payments")],
        subject_index=index,
    )
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]
    assert document["subjects"]["ambiguous"], "the refusal must be visible in the result"
    assert document["subjects"]["ambiguous"][0]["candidates"] == ["HOST-a", "HOST-b"]
    assert document["subjects"]["resolved"] == 0


def test_an_unresolved_subject_still_groups_against_itself():
    """Failing to resolve must not lose the facts — it only stops cross-name joining."""
    index = S.SubjectIndex.from_assets(_assets())
    document = attack_patterns.correlate(
        [_event(1, "legacy-host-9")],
        now=BASE + timedelta(minutes=5),
        plane_facts=[_fact("RUNTIME", "legacy-host-9"), _fact("CONFIGURATION", "legacy-host-9")],
        subject_index=index,
    )
    pattern = next(p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT")
    assert pattern["asset"] is None
    assert pattern["subjects"] == ["legacy-host-9"]
    assert document["subjects"]["unresolved"] >= 1


def test_two_changes_on_one_host_now_corroborate_across_planes():
    """The point of the whole exercise: separated names, one host, one agreement."""
    index = S.SubjectIndex.from_assets(_assets())
    document = attack_patterns.correlate(
        [_event(1, "alb-payments-01", "CRYPTO_DEMOTED")],
        now=BASE + timedelta(minutes=5),
        plane_facts=[_fact("RUNTIME", "payments-api")],
        subject_index=index,
    )
    # one plane plus the change is not agreement; the change's own plane is not a witness
    assert not [p for p in document["patterns"] if p["name"] == "MULTI_PLANE_AGREEMENT"]
    document = attack_patterns.correlate(
        [_event(1, "alb-payments-01", "CRYPTO_DEMOTED")],
        now=BASE + timedelta(minutes=5),
        plane_facts=[_fact("RUNTIME", "payments-api"), _fact("HSM", "payments-api", "ABSENT")],
        subject_index=index,
    )
    names = {p["name"] for p in document["patterns"]}
    assert "MULTI_PLANE_AGREEMENT" not in names
    contradiction = next(p for p in document["patterns"] if p["name"] == "PLANE_CONTRADICTION")
    assert contradiction["asset"] == "HOST-payments"
