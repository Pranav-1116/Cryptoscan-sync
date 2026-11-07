"""Supplier-concentration tests (PQC ICT supply-chain analysis §6:
'multiple critical services depending on one supplier or component')."""

from __future__ import annotations

import pytest

from shared_models.supplier_concentration import (
    CONCENTRATION_SCHEMA, CRITICAL, HIGH, LOW, MEDIUM,
    supplier_concentration,
)

AS_OF = "2026-11-07"


def _dep(**over):
    base = dict(service="payments-api", supplier="ACME HSM",
                component="Luna 7", criticality=CRITICAL,
                evidence_ref="ev-1")
    base.update(over)
    return base


def test_dependencies_are_evidence_backed_and_attributed():
    with pytest.raises(ValueError):
        supplier_concentration(dependencies=[_dep(evidence_ref="")], as_of=AS_OF)
    with pytest.raises(ValueError):
        supplier_concentration(dependencies=[_dep(service="")], as_of=AS_OF)
    with pytest.raises(ValueError):
        supplier_concentration(dependencies=[_dep(criticality="SEVERE")], as_of=AS_OF)


def test_one_supplier_backing_two_critical_services_is_named():
    report = supplier_concentration(dependencies=[
        _dep(service="payments-api", evidence_ref="ev-1"),
        _dep(service="settlement-api", evidence_ref="ev-2"),
        _dep(service="marketing-site", supplier="Other Co",
             criticality=MEDIUM, evidence_ref="ev-3"),
    ], as_of=AS_OF)
    assert report["state"] == "CONCENTRATED"
    assert report["is_clean_result"] is False
    assert "score" not in report, "named clusters explain; nothing blends"
    finding = report["findings"][0]
    assert finding["finding"] == "supplier_concentration"
    assert finding["subject"] == "ACME HSM"
    assert finding["severe_services"] == ["payments-api", "settlement-api"]
    assert finding["evidence_refs"] == ["ev-1", "ev-2"]
    assert "stalls all of them" in finding["note"]


def test_one_component_across_suppliers_is_also_concentration():
    report = supplier_concentration(dependencies=[
        _dep(service="payments-api", supplier="ACME HSM",
             component="OpenSSL-3-quantum-fork", evidence_ref="ev-1"),
        _dep(service="settlement-api", supplier="Globex Cloud",
             component="OpenSSL-3-quantum-fork", criticality=HIGH,
             evidence_ref="ev-2"),
    ], as_of=AS_OF)
    kinds = {f["finding"] for f in report["findings"]}
    assert "component_concentration" in kinds
    component = next(f for f in report["findings"]
                     if f["finding"] == "component_concentration")
    assert component["subject"] == "OpenSSL-3-quantum-fork"
    assert "reaches all of them" in component["note"]


def test_single_service_dependencies_are_a_measured_clean():
    report = supplier_concentration(dependencies=[
        _dep(service="payments-api", evidence_ref="ev-1"),
        _dep(service="settlement-api", supplier="Other Co",
             component="Vault-X", criticality=HIGH, evidence_ref="ev-2"),
    ], as_of=AS_OF)
    assert report["state"] == "NO_CONCENTRATION"
    assert report["is_clean_result"] is True
    assert report["findings"] == []


def test_no_recorded_dependencies_is_unknown_not_a_safe_chain():
    report = supplier_concentration(dependencies=[], as_of=AS_OF)
    assert report["state"] == "UNKNOWN"
    assert report["is_clean_result"] is False
    assert "not a safe one" in report["note"]


def test_clusters_carry_every_service_and_evidence_ref():
    report = supplier_concentration(dependencies=[
        _dep(service="payments-api", evidence_ref="ev-1"),
        _dep(service="settlement-api", evidence_ref="ev-2"),
        _dep(service="recon-batch", criticality=LOW, evidence_ref="ev-9"),
    ], as_of=AS_OF)
    acme = next(c for c in report["supplier_clusters"] if c["name"] == "ACME HSM")
    assert acme["services"] == ["payments-api", "recon-batch", "settlement-api"]
    assert acme["severe_services"] == ["payments-api", "settlement-api"]
    assert acme["evidence_refs"] == ["ev-1", "ev-2", "ev-9"]
    assert acme["count"] == 3 and acme["severe_count"] == 2
    assert report["schema"] == CONCENTRATION_SCHEMA
