"""If this HSM fails, what breaks?

The tests are written around the two ways a blast radius lies: counting something
that is not a dependency, and turning an unknown into a zero. Both are asserted
against directly.
"""

from __future__ import annotations

import pytest

from universal_vendor.hardware.business_impact import (
    CRITICALITY_ORDER,
    ImpactRejected,
    ServiceRecord,
    failure_impact,
)
from universal_vendor.hardware.relationships import (
    Evidence,
    UnevidencedRelationship,
    derive_edges,
    require_evidence,
)

PAYMENTS_CONFIG = """
pkcs11:
  module: /usr/lib/libCryptoki2_64.so
  token:
    label: PAYMENTS01
"""

CARDS_CONFIG = """
kmip:
  server: PAYMENTS01
"""

SERVICES = (
    ServiceRecord(name="Payment Processing", applications=("Payment API",),
                  business_system="Card Authorization", criticality="CRITICAL",
                  evidence=Evidence("DECLARED", "cmdb:service/payment-processing")),
    ServiceRecord(name="Statement Rendering", applications=("Statement Worker",),
                  business_system="Customer Statements", criticality="MEDIUM",
                  evidence=Evidence("DECLARED", "cmdb:service/statement-rendering")),
)


def edges():
    return (derive_edges("Payment API", config_text=PAYMENTS_CONFIG,
                         config_reference="apps/payment/config.yml")
            + derive_edges("Card Authorization API", config_text=CARDS_CONFIG,
                           config_reference="apps/cards/config.yml"))


# -- the chain -------------------------------------------------------------- #


def test_a_failure_walks_hardware_to_application_to_service_to_business_system():
    report = failure_impact("PAYMENTS01", edges(), services=SERVICES)
    assert report.applications == ["Card Authorization API", "Payment API"]
    assert report.services == ["Payment Processing"]
    assert report.business_systems == ["Card Authorization"]
    assert report.critical_systems == ["Card Authorization"]
    assert report.to_dict()["applications_affected"] == 2
    assert report.to_dict()["critical_systems_affected"] == 1


def test_the_statement_is_the_sentence_an_operator_reads():
    report = failure_impact("PAYMENTS01", edges(), services=SERVICES)
    assert report.statement.startswith("PAYMENTS01 failure reaches 2 application(s)")
    assert "1 critical business system(s) (Card Authorization)" in report.statement


def test_every_hop_reports_the_evidence_that_carried_it():
    hops = failure_impact("PAYMENTS01", edges(), services=SERVICES).hops
    assert len(hops) == 1
    hop = hops[0]
    assert hop["service"] == "Payment Processing"
    assert hop["service_evidence"]["evidence_id"].startswith("EV-")
    assert {entry["application"] for entry in hop["application_evidence"]} == {
        "Payment API"}
    assert all(entry["evidence_ids"] for entry in hop["application_evidence"])


def test_an_unmapped_application_is_named_rather_than_counted_as_zero():
    report = failure_impact("PAYMENTS01", edges(), services=())
    assert report.services == [] and report.business_systems == []
    assert report.unmapped_applications == ["Card Authorization API", "Payment API"]
    assert "no business mapping" in report.statement


def test_only_evidenced_edges_are_walked():
    unevidenced = {"subject": "Ghost API", "hardware": "PAYMENTS01",
                   "kind": "USES_HSM", "confidence": "HIGH", "evidence": []}
    report = failure_impact("PAYMENTS01", [*edges(), unevidenced], services=SERVICES)
    assert "Ghost API" not in report.applications


def test_a_certificate_is_not_an_application():
    certificate = require_evidence("cert:ab12", "PAYMENTS01", "TERMINATES_TLS",
                                   (Evidence("CONFIG", "lb-01#ssl-certificate"),))
    report = failure_impact("PAYMENTS01", [*edges(), certificate], services=SERVICES)
    assert "cert:ab12" not in report.applications


def test_no_dependency_is_stated_as_no_dependency_not_as_safe():
    report = failure_impact("HSM-NOBODY-USES", edges(), services=SERVICES)
    assert report.applications == []
    assert report.statement.startswith("no evidenced application depends on")


# -- a service record is evidence or it is nothing -------------------------- #


def test_a_service_without_evidence_is_refused():
    with pytest.raises(UnevidencedRelationship):
        ServiceRecord(name="Payment Processing", applications=("Payment API",),
                      business_system="Card Authorization", criticality="CRITICAL",
                      evidence=None)  # type: ignore[arg-type]


def test_a_service_that_names_no_application_cannot_be_reached():
    with pytest.raises(ImpactRejected):
        ServiceRecord(name="Orphan", applications=(), business_system="Payments",
                      criticality="HIGH",
                      evidence=Evidence("DECLARED", "cmdb:service/orphan"))


def test_a_criticality_outside_the_banks_vocabulary_is_refused():
    with pytest.raises(ImpactRejected):
        ServiceRecord(name="P1", applications=("Payment API",),
                      business_system="Card Authorization", criticality="SEV-1",
                      evidence=Evidence("DECLARED", "cmdb:service/p1"))


def test_criticality_is_normalised_not_trusted_verbatim():
    record = ServiceRecord(name="P1", applications=("Payment API",),
                           business_system="Card Authorization", criticality="critical",
                           evidence=Evidence("DECLARED", "cmdb:service/p1"))
    assert record.criticality == "CRITICAL"
    assert list(CRITICALITY_ORDER) == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_a_cmdb_only_hop_cannot_claim_more_than_medium_confidence():
    report = failure_impact("PAYMENTS01", edges(), services=SERVICES)
    # config-proven application edge (HIGH) + declared service mapping (MEDIUM)
    assert report.lowest_confidence == "MEDIUM"


def test_the_weakest_hop_sets_the_confidence_of_the_answer():
    declared_application = require_evidence(
        "Payment API", "PAYMENTS01", "USES_HSM",
        (Evidence("DECLARED", "cmdb:application/payment-api/hardware/PAYMENTS01"),))
    report = failure_impact("PAYMENTS01", [declared_application], services=SERVICES)
    assert report.lowest_confidence == "MEDIUM"
    assert report.applications == ["Payment API"]


def test_two_services_on_one_system_count_the_system_once():
    services = (
        ServiceRecord(name="Payment Processing", applications=("Payment API",),
                      business_system="Card Authorization", criticality="CRITICAL",
                      evidence=Evidence("DECLARED", "cmdb:service/pp")),
        ServiceRecord(name="Card Not Present", applications=("Payment API",),
                      business_system="Card Authorization", criticality="CRITICAL",
                      evidence=Evidence("DECLARED", "cmdb:service/cnp")),
    )
    report = failure_impact("PAYMENTS01", edges(), services=services)
    assert report.services == ["Payment Processing", "Card Not Present"]
    assert report.business_systems == ["Card Authorization"]
    assert report.to_dict()["business_systems_affected"] == 1
