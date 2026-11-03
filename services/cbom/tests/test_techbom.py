"""Guide 164 tests — TechBOM as a projection of evidence-backed technology claims."""

from __future__ import annotations

import pytest

from cbom import techbom as t


def asset(kind, name, **kwargs):
    kwargs.setdefault("evidence_ids", [f"EVD-{name}"])
    return {"kind": kind, "name": name, **kwargs}


def claim(source, relation, target, basis="config-parse", **kwargs):
    return {"from": source, "relation": relation, "to": target, "basis": basis,
            "evidence_ids": kwargs.pop("evidence_ids", ["EVD-1"]), **kwargs}


def estate(assets, claims, **kwargs):
    return {"schema": t.ESTATE_SCHEMA, "estate_id": "EST-1", "assets": assets,
            "claims": claims, **kwargs}


PAYMENTS = estate(
    [asset("BUSINESS_SYSTEM", "Payments", owner="Payments Platform"),
     asset("APPLICATION", "Payments API", version="2026.11.02"),
     asset("SERVICE", "payments-api"),
     asset("CONTAINER", "payments-api-7f9"),
     asset("IMAGE", "payments-api:2026.11.02"),
     asset("PACKAGE", "openssl", version="3.0.13"),
     asset("CRYPTO_LIBRARY", "OpenSSL 3.0.13", version="3.0.13"),
     asset("CRYPTO_ASSET", "AES-256-GCM", evidence_type="RUNTIME_OBSERVED"),
     asset("NETWORK_ENDPOINT", "payments.bank.example:443"),
     asset("LOAD_BALANCER", "External-LB-01"),
     asset("API_GATEWAY", "payments-gw"),
     asset("CERTIFICATE", "CERT-9281"),
     asset("PUBLIC_KEY", "CERT-9281-key"),
     asset("ALGORITHM", "ECDSA P-256"),
     asset("HSM", "HSM-01"),
     asset("FIRMWARE", "HSM fw 8.4", version="8.4"),
     asset("VENDOR", "Vendor X"),
     asset("HOST", "worker-3"),
     asset("VM", "vm-worker-3"),
     asset("PHYSICAL_SERVER", "srv-12")],
    [claim("Payments", "CONTAINS", "Payments API", basis="cmdb-import"),
     claim("Payments API", "PROVIDES", "payments-api"),
     claim("payments-api", "RUNS", "payments-api-7f9", basis="api-poll"),
     claim("payments-api-7f9", "FROM_IMAGE", "payments-api:2026.11.02",
           basis="api-poll"),
     claim("payments-api:2026.11.02", "SHIPS", "openssl", basis="sbom-import"),
     claim("openssl", "LINKS", "OpenSSL 3.0.13", basis="sbom-import"),
     claim("Payments API", "USES_CRYPTO", "AES-256-GCM", basis="runtime-probe"),
     claim("Payments API", "EXPOSES", "payments.bank.example:443"),
     claim("payments.bank.example:443", "FRONTED_BY", "External-LB-01",
           basis="api-poll"),
     claim("External-LB-01", "FORWARDS_TO", "payments-gw"),
     claim("payments-gw", "ROUTES_TO", "Payments API"),
     claim("payments.bank.example:443", "PRESENTS", "CERT-9281",
           basis="packet-capture"),
     claim("CERT-9281", "CONTAINS_KEY", "CERT-9281-key", basis="packet-capture"),
     claim("CERT-9281-key", "USES_ALGORITHM", "ECDSA P-256", basis="packet-capture"),
     claim("Payments API", "USES_HSM", "HSM-01"),
     claim("HSM-01", "RUNS_FIRMWARE", "HSM fw 8.4", basis="vendor-datasheet"),
     claim("HSM fw 8.4", "SUPPLIED_BY", "Vendor X", basis="vendor-datasheet"),
     claim("payments-api-7f9", "SCHEDULED_ON", "worker-3", basis="api-poll"),
     claim("worker-3", "HOSTED_ON", "vm-worker-3", basis="api-poll"),
     claim("vm-worker-3", "RUNS_ON", "srv-12", basis="api-poll")],
    expected={"BUSINESS_SYSTEM": 1, "APPLICATION": 1, "HSM": 2, "PACKAGE": 1},
    gaps=[{"kind": "HSM", "reason": "1 HSM collector unavailable"}],
)


# --------------------------------------------------------------------------- #
# identity and the asset model
# --------------------------------------------------------------------------- #

def test_an_asset_needs_a_known_kind_a_name_and_evidence():
    with pytest.raises(t.ClaimRefused, match="not a technology asset type"):
        t.asset("SPACESHIP", "x", evidence_ids=["E"])
    with pytest.raises(t.ClaimRefused, match="needs a name"):
        t.asset("APPLICATION", "  ", evidence_ids=["E"])
    with pytest.raises(t.ClaimRefused, match="no evidence id"):
        t.asset("APPLICATION", "Payments API")


def test_identity_is_a_stable_key_plus_a_readable_id():
    bom = t.build(PAYMENTS)
    app = bom["by_key"]["APPLICATION:payments api:production"]
    assert app["id"] == "TECH-APP-001"
    assert app["digest"]
    assert app["key"] != app["id"]


def test_same_estate_same_ids_and_a_changed_estate_renumbers():
    first = t.build(PAYMENTS)
    second = t.build(PAYMENTS)
    assert [row["id"] for row in first["assets"]] == [row["id"] for row in second["assets"]]
    bigger = t.build(estate([*PAYMENTS["assets"], asset("APPLICATION", "AAA First")],
                            PAYMENTS["claims"]))
    assert bigger["by_key"]["APPLICATION:payments api:production"]["id"] == "TECH-APP-002"


def test_a_duplicate_asset_is_refused_rather_than_merged():
    bom = t.build(estate([asset("APPLICATION", "Payments API"),
                          asset("APPLICATION", "payments api", owner="someone else")], []))
    assert len(bom["assets"]) == 1
    assert bom["refusals"][0]["code"] == "DUPLICATE_ASSET"


# --------------------------------------------------------------------------- #
# claims: no co-occurrence, no over-claiming
# --------------------------------------------------------------------------- #

def test_co_occurrence_is_not_a_basis():
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("Payments API", "USES_HSM", "HSM-01", basis="co-occurrence",
                evidence_ids=["E"])
    assert caught.value.code == "CO_OCCURRENCE_NOT_EVIDENCE"
    assert "proximity" in str(caught.value)


@pytest.mark.parametrize("basis", ["same-scan", "proximity", "name-similarity",
                                   "assumption"])
def test_every_proximity_basis_is_named_and_refused(basis):
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("a", "USES_HSM", "b", basis=basis, evidence_ids=["E"])
    assert caught.value.code == "CO_OCCURRENCE_NOT_EVIDENCE"


def test_an_edge_may_never_be_stronger_than_its_evidence():
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("Payments API", "USES_HSM", "HSM-01", basis="vendor-datasheet",
                confidence="OBSERVED", evidence_ids=["E"])
    assert caught.value.code == "CLAIM_STRONGER_THAN_EVIDENCE"
    lowered = t.claim("Payments API", "USES_HSM", "HSM-01", basis="runtime-probe",
                      confidence="CONFIGURED", evidence_ids=["E"])
    assert lowered["confidence"] == "CONFIGURED"


def test_a_claim_needs_an_evidence_id_and_not_just_a_basis():
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("a", "USES_HSM", "b", basis="config-parse")
    assert caught.value.code == "CLAIM_WITHOUT_EVIDENCE"


def test_an_inference_must_name_its_rule():
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("a", "USES_HSM", "b", basis="name-match", evidence_ids=["E"])
    assert caught.value.code == "INFERENCE_WITHOUT_RULE"
    row = t.claim("a", "USES_HSM", "b", basis="name-match", rule="same-host",
                  evidence_ids=["E"])
    assert row["confidence"] == "INFERRED" and row["rule"] == "same-host"


def test_an_unknown_basis_or_relation_is_refused_not_guessed():
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("a", "USES_HSM", "b", basis="vibes", evidence_ids=["E"])
    assert caught.value.code == "UNKNOWN_BASIS"
    with pytest.raises(t.ClaimRefused) as caught:
        t.claim("a", "PROBABLY_USES", "b", basis="config-parse", evidence_ids=["E"])
    assert caught.value.code == "UNKNOWN_RELATION"


# --------------------------------------------------------------------------- #
# the layer boundaries are type rules
# --------------------------------------------------------------------------- #

def test_certificate_does_not_prove_application_crypto():
    ok, reason = t.check_types("USES_ALGORITHM", "APPLICATION", "ALGORITHM")
    assert ok is False and "starts at PUBLIC_KEY" in reason
    bom = t.build(estate([asset("APPLICATION", "Payments API"),
                          asset("ALGORITHM", "ECDSA P-256")],
                         [claim("Payments API", "USES_ALGORITHM", "ECDSA P-256",
                                basis="packet-capture")]))
    assert bom["claims"] == []
    assert bom["refusals"][0]["code"] == "TYPE_MISMATCH"


def test_network_does_not_reach_into_application_internals():
    ok, reason = t.check_types("SCHEDULED_ON", "NETWORK_ENDPOINT", "HOST")
    assert ok is False and "starts at CONTAINER, POD" in reason


def test_an_edge_to_an_undeclared_node_is_refused():
    bom = t.build(estate([asset("APPLICATION", "Payments API")],
                         [claim("Payments API", "USES_HSM", "HSM-99")]))
    assert bom["claims"] == []
    assert bom["refusals"][0]["code"] == "UNKNOWN_REF"


def test_a_runtime_crypto_use_may_not_be_evidenced_by_a_manifest():
    bom = t.build(estate(
        [asset("APPLICATION", "Payments API"),
         asset("CRYPTO_ASSET", "AES-256-GCM", evidence_type="RUNTIME_OBSERVED")],
        [claim("Payments API", "USES_CRYPTO", "AES-256-GCM", basis="sbom-import")]))
    assert bom["refusals"][0]["code"] == "EVIDENCE_CLASS_MISMATCH"
    kept = t.build(estate(
        [asset("APPLICATION", "Payments API"),
         asset("CRYPTO_ASSET", "AES-256-GCM", evidence_type="RUNTIME_OBSERVED")],
        [claim("Payments API", "USES_CRYPTO", "AES-256-GCM", basis="runtime-probe")]))
    assert kept["claims"][0]["confidence"] == "OBSERVED"


# --------------------------------------------------------------------------- #
# the estate as a whole
# --------------------------------------------------------------------------- #

def test_the_bom_carries_every_chain_and_a_confidence_per_edge():
    bom = t.build(PAYMENTS)
    assert set(bom["claim_counts"]) == {"SOFTWARE", "NETWORK", "CERTIFICATE", "KEYS",
                                        "HARDWARE", "VENDOR"}
    assert all(row["confidence"] in t.CONFIDENCE for row in bom["claims"])
    assert bom["refusals"] == []
    assert "evidenced relationship(s)" in bom["statement"]


def test_completeness_states_the_denominator_and_the_gap():
    block = t.build(PAYMENTS)["completeness"]
    assert block["overall"] == "PARTIAL"
    hsm = next(row for row in block["rows"] if row["kind"] == "HSM")
    assert hsm == {"kind": "HSM", "observed": 1, "expected": 2, "coverage": 0.5,
                   "verdict": "PARTIAL"}
    assert block["gaps"] == [{"kind": "HSM", "reason": "1 HSM collector unavailable"}]
    assert "1 stated gap(s)" in block["statement"]


def test_a_kind_with_no_denominator_is_unmeasured_not_complete():
    block = t.completeness([{"kind": "TPM"}], {})
    assert block["rows"][0]["verdict"] == "UNMEASURED"
    assert block["overall"] == "UNMEASURED"


# --------------------------------------------------------------------------- #
# reconciliation
# --------------------------------------------------------------------------- #

def test_reconciliation_preserves_a_conflict_instead_of_picking_one():
    body = t.reconcile([
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.11",
         "source": "runtime", "basis": "process-trace"},
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
         "source": "sbom", "basis": "sbom-import"},
        {"subject": "Payments API", "attribute": "openssl version", "value": "3.0.13",
         "source": "container", "basis": "api-poll"}])
    conflict = body["conflicts"][0]
    assert conflict["status"] == "CONFLICT"
    assert conflict["values"] == ["3.0.11", "3.0.13"]
    assert conflict["resolution"] == "UNRESOLVED"
    assert conflict["strongest"] == "OBSERVED"
    assert "kept as a conflict" in conflict["statement"]


def test_agreement_is_not_verification():
    body = t.reconcile([
        {"subject": "Payments API", "attribute": "version", "value": "2026.11.02",
         "source": "cmdb", "basis": "cmdb-import"},
        {"subject": "Payments API", "attribute": "version", "value": "2026.11.02",
         "source": "vendor", "basis": "vendor-datasheet"}])
    assert body["conflicts"] == []
    assert "agreement is not verification" in body["findings"][0]["statement"]


def test_a_proximity_basis_cannot_settle_a_reconciliation():
    body = t.reconcile([
        {"subject": "A", "attribute": "v", "value": "1", "source": "scan",
         "basis": "same-scan"},
        {"subject": "A", "attribute": "v", "value": "2", "source": "runtime",
         "basis": "runtime-probe"}])
    assert body["findings"][0]["observations"][0]["confidence"] == "UNKNOWN"
    assert body["conflicts"]


# --------------------------------------------------------------------------- #
# blast radius
# --------------------------------------------------------------------------- #

def test_blast_radius_walks_dependents_through_proven_edges():
    body = t.blast_radius(t.build(PAYMENTS), query="ECDSA P-256")
    assert body["seeds"] == ["TECH-ALG-001"]
    assert "TECH-APP-001" in {row["id"] for row in body["reachable"]}
    # the containment above the application is a CMDB import, so the owning system is a
    # possibility rather than part of the proven blast radius
    assert body["systems"] == []
    assert "TECH-SYS-001" in body["possible"]
    assert body["seeds"][0] not in {row["id"] for row in body["reachable"]}


def test_an_imported_or_vendor_declared_edge_is_not_a_proven_path():
    bom = t.build(estate(
        [asset("VENDOR", "Vendor X"), asset("FIRMWARE", "fw 8.4"),
         asset("HSM", "HSM-01")],
        [claim("fw 8.4", "SUPPLIED_BY", "Vendor X", basis="vendor-datasheet"),
         claim("HSM-01", "RUNS_FIRMWARE", "fw 8.4", basis="vendor-datasheet")]))
    body = t.blast_radius(bom, query="Vendor X")
    assert body["reachable"] == []
    assert set(body["possible"]) == {"TECH-FW-001", "TECH-HSM-001"}
    assert bom["unproven_edges"] == sorted(row["id"] for row in bom["claims"])


def test_blast_radius_separates_what_is_only_inferred():
    bom = t.build(estate(
        [asset("APPLICATION", "Payments API"), asset("HSM", "HSM-01"),
         asset("BUSINESS_SYSTEM", "Payments")],
        [claim("Payments", "CONTAINS", "Payments API", basis="cmdb-import"),
         claim("Payments API", "USES_HSM", "HSM-01", basis="name-match",
               rule="same-name")]))
    body = t.blast_radius(bom, query="HSM-01")
    assert body["reachable"] == []
    assert body["possible"] == ["TECH-APP-001", "TECH-SYS-001"]
    assert "reachable only through an inference" in body["statement"]


def test_blast_radius_names_migration_blockers():
    body = t.blast_radius(t.build(PAYMENTS), query="HSM-01")
    assert body["pqc_blockers"]
    assert body["pqc_blockers"][0]["kind"] == "HSM"


def test_a_blast_radius_for_nothing_says_so():
    body = t.blast_radius(t.build(PAYMENTS), query="no-such-asset")
    assert body["reachable"] == []
    assert "matches" in body["statement"]


# --------------------------------------------------------------------------- #
# time, projection, summary
# --------------------------------------------------------------------------- #

def test_a_version_change_is_named_as_one():
    before = t.build(PAYMENTS)
    changed = {**PAYMENTS, "assets": [
        {**row, "version": "3.0.11"} if row["name"] == "openssl" else row
        for row in PAYMENTS["assets"]]}
    after = t.build(changed)
    events = t.diff(before, after)["events"]
    version = [row for row in events if row["change"] == "TECHNOLOGY_VERSION_CHANGED"]
    assert version and "3.0.13 → 3.0.11" in version[0]["detail"]
    assert version[0]["category"] == "SBOM_CHANGED"


def test_a_certificate_change_lands_in_its_own_category():
    before = t.build(PAYMENTS)
    changed = {**PAYMENTS, "assets": [
        {**row, "version": "CERT-9821"} if row["name"] == "CERT-9281" else row
        for row in PAYMENTS["assets"]]}
    body = t.diff(before, t.build(changed))
    assert body["by_category"] == {"CERTIFICATE_CHANGED": 1}
    assert body["not_proven"]


def test_an_unchanged_estate_produces_no_churn():
    body = t.diff(t.build(PAYMENTS), t.build(PAYMENTS))
    assert body["events"] == []
    assert "nothing moved" in body["statement"]


def test_a_techbom_can_never_be_its_own_source():
    bom = t.build(PAYMENTS)
    with pytest.raises(ValueError, match="not a source"):
        t.from_document(bom)
    with pytest.raises(ValueError, match="techbom-estate"):
        t.build(bom)
    assert bom["projection"] is True
    assert bom["source_of_truth"] == "CANONICAL_ESTATE"


def test_the_summary_counts_confidence_rather_than_only_assets():
    body = t.summary(t.build(PAYMENTS))
    assert body["assets"] == 20
    assert body["by_confidence"]["VENDOR_DECLARED"] == 2
    assert body["completeness"] == "PARTIAL"
    assert body["by_chain"].get("RUNTIME", 0) == 0
