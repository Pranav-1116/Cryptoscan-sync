"""Evidence is not a fact, and a fact is not a usage.

These tests exist because the shortcut they forbid is *convenient*. "OpenSSL 3.0.13 is installed"
is one line away from "AES-256-GCM is used", the second line makes a BOM look richer, and every
false positive in the accuracy dashboard can be traced to somebody taking it.
"""

from __future__ import annotations

import pytest

from cbom import facts
from cbom.facts import Observation


def obs(subject="app", property_name="algorithm", value="AES-256-GCM",
        klass=facts.RUNTIME_OBSERVED, kind=facts.RUNTIME_USAGE, source="test",
        evidence_id="EVID-v1-a", scope=""):
    return Observation(subject=subject, property=property_name, value=value, klass=klass,
                       kind=kind, source=source, evidence_id=evidence_id, scope=scope)


# --------------------------------------------------------------------------- #
# capability is not usage
# --------------------------------------------------------------------------- #

def test_a_library_capability_never_becomes_a_usage_fact():
    derivation = facts.derive([obs(subject="lib:openssl", klass=facts.CONFIGURED,
                                   kind=facts.CAPABILITY, source="dpkg")])
    fact = derivation.get("lib:openssl", "algorithm")
    assert fact.state == facts.FOUND
    assert fact.kind == facts.CAPABILITY
    assert fact.decided is True                   # a real fact — about capability
    assert facts.cap_placement(fact)["placement"] == facts.CAPABILITY


def test_an_installed_package_does_not_imply_a_used_algorithm():
    """The review's example, as an executable statement."""
    observations = [
        obs(subject="app:payments", property_name="package", value="openssl",
            klass=facts.STATIC_OBSERVED, kind=facts.STATIC_REFERENCE, evidence_id="EVID-v1-pkg"),
        obs(subject="app:payments", property_name="version", value="3.0.13",
            klass=facts.STATIC_OBSERVED, kind=facts.STATIC_REFERENCE, evidence_id="EVID-v1-ver"),
        obs(subject="app:payments", property_name="algorithm", value="AES-256-GCM",
            klass=facts.CONFIGURED, kind=facts.CAPABILITY, evidence_id="EVID-v1-cap"),
    ]
    derivation = facts.derive(observations, properties={"app:payments": ["algorithm", "package",
                                                                        "version"]})
    algorithm = derivation.get("app:payments", "algorithm")
    assert algorithm.kind == facts.CAPABILITY
    assert algorithm.value == "AES-256-GCM"
    assert "capability" in algorithm.detail
    assert facts.cap_placement(algorithm)["placement"] == facts.CAPABILITY


@pytest.mark.parametrize("kind", [facts.RUNTIME_USAGE, facts.NETWORK_NEGOTIATED])
@pytest.mark.parametrize("klass", [facts.VENDOR_DECLARED, facts.IMPORTED, facts.CONFIGURED,
                                   facts.INFERRED, facts.OBSERVED])
def test_a_usage_claim_cannot_be_backed_by_a_document(klass, kind):
    with pytest.raises(ValueError, match="cannot support"):
        obs(klass=klass, kind=kind)


def test_an_observation_without_evidence_is_refused():
    with pytest.raises(ValueError, match="rumour"):
        obs(evidence_id="")


def test_an_unknown_class_is_refused_rather_than_defaulted():
    with pytest.raises(ValueError, match="unknown observation class"):
        obs(klass="PROBABLY_TRUE")


# --------------------------------------------------------------------------- #
# inference is a lead, never an answer
# --------------------------------------------------------------------------- #

def test_an_inferred_value_is_recorded_and_never_used_for_a_decision():
    derivation = facts.derive([obs(value="AES-256-GCM", klass=facts.INFERRED,
                                   kind=facts.CAPABILITY, source="heuristic")])
    fact = derivation.get("app", "algorithm")
    assert fact.state == facts.UNKNOWN_STATE
    assert fact.value is None
    assert fact.decided is False
    assert fact.evidence_ids == ("EVID-v1-a",)      # the lead is still on record
    assert any(refusal["code"] == "INFERRED_ONLY" for refusal in derivation.refusals)


def test_corroboration_by_several_classes_is_not_a_conflict():
    derivation = facts.derive([
        obs(value="AES-256-GCM", klass=facts.RUNTIME_OBSERVED, evidence_id="EVID-v1-r"),
        obs(value="AES-256-GCM", klass=facts.NETWORK_OBSERVED, kind=facts.NETWORK_NEGOTIATED,
            evidence_id="EVID-v1-n"),
        obs(value="AES-256-GCM", klass=facts.CONFIGURED, kind=facts.CONFIGURED_USAGE,
            evidence_id="EVID-v1-c"),
    ])
    fact = derivation.get("app", "algorithm")
    assert fact.state == facts.FOUND
    assert set(fact.classes) == {facts.RUNTIME_OBSERVED, facts.NETWORK_OBSERVED, facts.CONFIGURED}
    assert "corroborated" in fact.detail
    assert fact.strength() == facts.STRENGTH[facts.RUNTIME_OBSERVED]
    assert fact.evidence_ids == ("EVID-v1-c", "EVID-v1-n", "EVID-v1-r")


# --------------------------------------------------------------------------- #
# disagreement is preserved, not resolved
# --------------------------------------------------------------------------- #

def test_runtime_and_static_disagreeing_is_a_conflict_not_the_stronger_side():
    derivation = facts.derive([
        obs(value="AES-256-GCM", klass=facts.RUNTIME_OBSERVED, evidence_id="EVID-v1-run"),
        obs(value="AES-128-GCM", klass=facts.STATIC_OBSERVED, kind=facts.STATIC_REFERENCE,
            evidence_id="EVID-v1-src"),
        obs(value="AES-256-GCM", klass=facts.CONFIGURED, kind=facts.CONFIGURED_USAGE,
            evidence_id="EVID-v1-cfg"),
    ])
    fact = derivation.get("app", "algorithm")
    assert fact.state == facts.CONFLICT
    assert fact.conflict == facts.RUNTIME_STATIC_CONFLICT
    assert fact.value is None            # nothing is asserted
    assert {side["value"] for side in fact.sides} == {"AES-256-GCM", "AES-128-GCM"}
    assert {side["evidence_id"] for side in fact.sides} == {"EVID-v1-run", "EVID-v1-src"}
    assert facts.cap_placement(fact)["placement"] == facts.CONFLICT
    assert facts.cap_placement(fact)["value"] is None
    assert facts.refused(fact) is True


def test_a_stale_sbom_against_a_running_library_is_a_dependency_conflict():
    derivation = facts.derive([
        obs(property_name="dependency_version", value="3.0.13", klass=facts.IMPORTED,
            kind=facts.INVENTORY, evidence_id="EVID-v1-sbom"),
        obs(property_name="dependency_version", value="3.0.11", klass=facts.RUNTIME_OBSERVED,
            evidence_id="EVID-v1-proc"),
    ])
    fact = derivation.get("app", "dependency_version")
    assert fact.conflict == facts.DEPENDENCY_VERSION_CONFLICT
    assert len(fact.sides) == 2


def test_a_capability_beside_a_usage_is_explained_rather_than_conflicting():
    derivation = facts.derive([
        obs(value="AES-256-GCM", klass=facts.RUNTIME_OBSERVED, evidence_id="EVID-v1-run"),
        obs(value="AES-128-GCM", klass=facts.CONFIGURED, kind=facts.CAPABILITY,
            evidence_id="EVID-v1-cap"),
    ])
    fact = derivation.get("app", "algorithm")
    assert fact.state == facts.FOUND
    assert fact.value == "AES-256-GCM"
    assert "capability" in fact.detail


def test_capability_is_plural_and_not_a_conflict():
    derivation = facts.derive([
        obs(value="AES-256-GCM", klass=facts.CONFIGURED, kind=facts.CAPABILITY,
            evidence_id="EVID-v1-a"),
        obs(value="AES-128-GCM", klass=facts.CONFIGURED, kind=facts.CAPABILITY,
            evidence_id="EVID-v1-b"),
    ])
    fact = derivation.get("app", "algorithm")
    assert fact.state == facts.FOUND
    assert fact.kind == facts.CAPABILITY
    assert fact.value is None
    assert {side["value"] for side in fact.sides} == {"AES-256-GCM", "AES-128-GCM"}


# --------------------------------------------------------------------------- #
# absence is four different facts
# --------------------------------------------------------------------------- #

def test_nothing_observed_is_unknown_not_absent():
    derivation = facts.derive([], properties={"hsm-1": ["algorithm"]})
    fact = derivation.get("hsm-1", "algorithm")
    assert fact.state == facts.UNKNOWN_STATE
    assert fact.value is None
    assert facts.NOT_OBSERVABLE not in facts.ABSENCE_EVIDENCE


def test_searched_and_empty_is_absence_within_a_scope():
    fact = facts.presence([], subject="host-1", property_name="algorithm", scope="/srv",
                          searched=True)
    assert fact.state == facts.NOT_FOUND_WITHIN_SCOPE
    assert "/srv" in fact.detail
    assert "not absence in the estate" in fact.detail
    assert facts.NOT_FOUND_WITHIN_SCOPE in facts.ABSENCE_EVIDENCE


def test_a_scope_no_collector_reaches_is_not_observable_not_none():
    fact = facts.presence([], subject="hsm-1", property_name="algorithm", searched=False)
    assert fact.state == facts.NOT_OBSERVABLE
    assert fact.value is None
    assert facts.NOT_OBSERVABLE not in facts.ABSENCE_EVIDENCE


def test_a_failed_collection_never_reads_as_an_empty_estate():
    derivation = facts.derive([], properties={"hsm-2": ["algorithm"]},
                              scopes={"hsm-2": {"scope": "pkcs11",
                                                "failure": "management API timed out"}})
    fact = derivation.get("hsm-2", "algorithm")
    assert fact.state == facts.COLLECTION_FAILED
    assert "timed out" in fact.detail
    assert any(refusal["code"] == facts.COLLECTION_FAILED for refusal in derivation.refusals)


def test_a_failed_collection_overrides_an_inferred_value():
    derivation = facts.derive(
        [obs(subject="hsm-3", klass=facts.INFERRED, kind=facts.CAPABILITY)],
        scopes={"hsm-3": {"scope": "pkcs11", "failure": "timeout"}})
    assert derivation.get("hsm-3", "algorithm").state == facts.COLLECTION_FAILED


# --------------------------------------------------------------------------- #
# identity of the evidence
# --------------------------------------------------------------------------- #

def test_an_evidence_digest_is_stable_and_version_prefixed():
    first = facts.observation_digest(obs())
    assert first == facts.observation_digest(obs())
    assert first.startswith("EVID-v1-")
    assert first != facts.observation_digest(obs(value="AES-128-GCM"))
    assert facts.fact_digest(facts.derive([obs()]).facts[0]).startswith("FACT-v1-")


def test_the_legal_pairs_are_exhaustive():
    """A new class or kind cannot be added without deciding what may back it."""
    assert set(facts.KIND_MEANING) == {
        facts.CAPABILITY, facts.CONFIGURED_USAGE, facts.STATIC_REFERENCE, facts.INVENTORY,
        facts.RUNTIME_USAGE, facts.NETWORK_NEGOTIATED}
    assert set(facts.STRENGTH) == set(facts.OBSERVATION_CLASSES)
    assert facts.INFERRED not in facts.DECIDING_CLASSES
    assert facts.UNKNOWN_CLASS not in facts.DECIDING_CLASSES
    for kind in facts.KINDS:
        assert facts._LEGAL[kind], kind


def test_the_derivation_serialises_without_leaking_a_value_it_did_not_decide():
    payload = facts.derive([
        obs(value="AES-256-GCM", klass=facts.RUNTIME_OBSERVED),
        obs(value="AES-128-GCM", klass=facts.STATIC_OBSERVED, kind=facts.STATIC_REFERENCE,
            evidence_id="EVID-v1-src"),
    ]).as_dict()
    assert payload["schema"] == facts.SCHEMA
    assert payload["facts"][0]["value"] is None
    assert len(payload["facts"][0]["sides"]) == 2
