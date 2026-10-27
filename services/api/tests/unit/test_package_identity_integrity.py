"""Authenticated SBOM/trace regressions; synthetic fixtures, not bank accuracy."""
from copy import deepcopy
from datetime import timedelta
from urllib.parse import quote

import pytest
from db.models.base import utcnow
from db.models.evidence_record import EvidenceRecord
from db.models.software_supply_chain import ReleaseSbomBinding
from db.models.user import User
from api.assurance import store
from test_assurance_workflows import (
    P, admin, approval, assured as assured, banks as banks, done, export_document,
    new_scan, signer_and_key, supplier_body,
)
from test_software_supply_chain_api import PREFIX, EVIDENCE, attach, deploy, register


def document(fmt, version):
    purl = "pkg:maven/org.bank/crypto@" + quote(version, safe="")
    if fmt == "cyclonedx":
        doc = {"bomFormat": "CycloneDX", "components": [
            {"name": "crypto", "version": version, "purl": purl, "bom-ref": "crypto"}]}
    else:
        doc = {"spdxVersion": "SPDX-2.3", "packages": [{
            "name": "crypto", "versionInfo": version, "SPDXID": "SPDXRef-crypto",
            "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]}]}
    return doc, purl


def stored(client, doc):
    return done(client.post(PREFIX + "/sboms", json={"doc": doc, **EVIDENCE}))


def relationship(binding, purl, evidence):
    return {"expected_revision": 0, "relation": "PACKAGE_CRYPTO", "subject_type": "sbom_binding",
        "subject_id": binding["id"], "object_type": "evidence", "object_id": evidence.id,
        "package_identity": purl, "observed_at": (utcnow() - timedelta(minutes=1)).isoformat(),
        "expires_at": (utcnow() + timedelta(hours=1)).isoformat(), "evidence_ids": [evidence.id],
        "evidence_ref": "synthetic/exact-package-review", "basis": "OPERATOR_REVIEWED",
        "rationale": "Synthetic review cannot resolve a build-system variable"}


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
@pytest.mark.parametrize("version", ["${crypto.version}", "1.x", "[1.0,2.0)"])
def test_unresolved_sbom_package_cannot_become_a_reviewed_crypto_path(assured, fmt, version):
    clients, db, _ = assured
    client = clients["bank_a"]
    doc, purl = document(fmt, version)
    before = deepcopy(doc)
    sbom = stored(client, doc)
    assert sbom["unresolved_component_count"] == 1
    artifact = register(client)
    binding = attach(client, artifact, sbom)
    assert binding["unresolved_component_count"] == 1
    assert binding["components"][0]["package_identity"] is None
    assert binding["components"][0]["version"] == version
    assert doc == before
    done(deploy(client, artifact, system_id="system-a"))
    scan = new_scan(db)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=scan.id).one()
    rejected = client.post(P + "/relationships", json=relationship(binding, purl, evidence))
    assert rejected.status_code == 409, rejected.text
    trace = done(client.get(P + "/applications/system-a/trace"), 200)
    assert trace["paths"] == []
    assert trace["unresolved"][0]["reason"] == "UNRESOLVED_EXACT_PACKAGE_VERSION"
    assert trace["complete"] is trace["runtime_verified"] is False


@pytest.mark.parametrize("state", ["PROPOSED", "REVIEWED"])
def test_preupgrade_unresolved_relationship_cannot_be_approved_or_traced(assured, state):
    clients, db, _ = assured
    client = clients["bank_a"]
    doc, purl = document("cyclonedx", "${crypto.version}")
    sbom = stored(client, doc)
    artifact = register(client)
    binding = attach(client, artifact, sbom)
    done(deploy(client, artifact, system_id="system-a"))
    scan = new_scan(db)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=scan.id).one()
    # Seed a pre-upgrade projection, not a current API grant/approval bypass:
    # older normalization retained a variable as an exact package identity.
    legacy = db.get(ReleaseSbomBinding, binding["id"])
    legacy.components = [{**legacy.components[0], "package_identity": purl}]
    db.commit()
    proposer = db.query(User).filter_by(username="bank_a").one().id
    reviewer = db.query(User).filter_by(username="platform_admin").one().id
    body = relationship(binding, purl, evidence)
    body.pop("expected_revision")
    identifier = store.subject("synthetic-preupgrade-package-edge", binding["id"])
    first = store.append(db, "a", "bom_relationship", identifier, 0,
                         {**body, "state": "PROPOSED", "trust": "DECLARED_NOT_VERIFIED"}, proposer)
    if state == "REVIEWED":
        row = store.append(db, "a", "bom_relationship", identifier, 1,
            {**first.payload, "state": "REVIEWED", "proposed_by": proposer, "approved_by": reviewer,
             "approval_evidence_ref": "synthetic/preupgrade-review", "approval_reason": "Historical test fixture",
             "trust": "CUSTOMER_REVIEWED_ASSERTION_NOT_INDEPENDENT_RUNTIME_PROOF"}, reviewer)
    else:
        row = first
    original = done(client.get(P + f"/records/bom_relationship/{identifier}"), 200)["revisions"]
    assert original[-1]["payload_sha256"] == row.payload_sha256
    if state == "PROPOSED":
        rejected = admin(clients).post(P + f"/relationships/{identifier}/approve", json=approval())
        assert rejected.status_code == 409, rejected.text
    trace = done(client.get(P + "/applications/system-a/trace"), 200)
    assert trace["paths"] == []
    assert trace["unresolved"][0]["reason"] == "UNRESOLVED_EXACT_PACKAGE_VERSION"
    history = done(client.get(P + f"/records/bom_relationship/{identifier}"), 200)["revisions"]
    assert history == original
    assert clients["bank_b"].get(P + "/applications/system-a/trace").status_code == 404
    assert clients["platform_admin"].get(P + "/applications/system-a/trace").status_code == 404


@pytest.mark.parametrize("version", ["${crypto.version}", "1.x", "[1.0,2.0)"])
def test_signed_supplier_package_variable_or_range_stays_quarantined(assured, version):
    clients, _db, _ = assured
    client = clients["bank_a"]
    artifact = register(client)
    signer, private, _ = signer_and_key(clients)
    payload = export_document()
    _, purl = document("cyclonedx", version)
    payload["pages"][0]["facts"] = [{"kind": "packages", "package_identity": purl}]
    uploaded = done(client.post(P + "/supplier-evidence", json=supplier_body(
        artifact, signer, private, document=payload)))
    identifier = uploaded["subject_id"]
    result = done(admin(clients).post(P + f"/supplier-evidence/{identifier}/approve", json=approval()), 200)
    assert result["payload"]["origin_verified"] is True  # real synthetic signature remains valid
    assert result["payload"]["state"] == "QUARANTINED"
    assert result["payload"]["problems"] == ["MALFORMED"]
    assert result["payload"]["independent_truth_verified"] is False
