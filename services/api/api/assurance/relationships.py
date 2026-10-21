"""Typed evidence assertions over EXISTING identities; never string/name joins."""
from datetime import datetime
from fastapi import HTTPException
from db.models.base import utcnow
from db.models.assurance import AssuranceRevision, CollectionPhaseReceipt
from db.models.evidence_record import EvidenceRecord
from db.models.hardware_live import HardwareAsset
from db.models.software_supply_chain import SoftwareArtifact, SoftwareDeployment, ReleaseSbomBinding
from db.models.system import System
from db.models.vendor import Vendor
from db.repositories.execution_control import aware
from . import store

MODELS = {"sbom_binding": ReleaseSbomBinding, "phase_receipt": CollectionPhaseReceipt,
          "deployment": SoftwareDeployment, "hardware": HardwareAsset, "vendor": Vendor,
          "system": System, "evidence": EvidenceRecord}
TYPES = {"PACKAGE_CRYPTO": ("sbom_binding", "evidence"), "ENDPOINT_SERVICE": ("phase_receipt", "system"),
         "SERVICE_DEPLOYMENT": ("system", "deployment"), "HARDWARE_FIRMWARE": ("hardware", "evidence"),
         "SUPPLIER_PRODUCT": ("vendor", "evidence")}


def active(row):
    return (getattr(row, "lifecycle_state", "ACTIVE") == "ACTIVE"
            and (not getattr(row, "valid_until", None) or aware(row.valid_until) > utcnow())
            and not getattr(row, "deleted_at", None))


def validate(db, owner, value):
    if (value["subject_type"], value["object_type"]) != TYPES[value["relation"]]:
        raise HTTPException(422, "Relationship has incompatible typed endpoints")
    a = store.exact(db, MODELS[value["subject_type"]], owner, value["subject_id"])
    b = store.exact(db, MODELS[value["object_type"]], owner, value["object_id"])
    proofs = [store.exact(db, EvidenceRecord, owner, i) for i in value["evidence_ids"]]
    if not active(a) or not active(b) or any(not active(e) for e in proofs):
        raise HTTPException(409, "Inactive/expired/retracted identity or evidence")
    if value["object_type"] == "evidence" and value["object_id"] not in value["evidence_ids"]:
        raise HTTPException(422, "Object observation must be among the explicit supporting evidence")
    if value["relation"] == "PACKAGE_CRYPTO":
        if not value["package_identity"] or value["package_identity"] not in {c.get("package_identity") for c in a.components}:
            raise HTTPException(409, "Exact versioned package is not resolved by this release SBOM binding")
    elif value["package_identity"]:
        raise HTTPException(422, "Package identity only belongs on a PACKAGE_CRYPTO assertion")
    if value["relation"] == "ENDPOINT_SERVICE" and not (a.state == "COMPLETED" and a.observation_succeeded is True):
        raise HTTPException(409, "An open port/refused/failed probe does not identify a service")
    if value["relation"] == "SERVICE_DEPLOYMENT" and b.system_id != a.id:
        raise HTTPException(409, "Service system does not match the explicit deployment identity")
    return a, b


def save(db, owner, identifier, body, actor):
    value = body.model_dump(mode="json", exclude={"expected_revision"})
    if not aware(body.observed_at) <= utcnow() < aware(body.expires_at) or body.expires_at <= body.observed_at:
        raise HTTPException(422, "Relationship observation/freshness window is invalid")
    validate(db, owner, value)
    return store.append(db, owner, "bom_relationship", identifier, body.expected_revision,
                        {**value, "state": "PROPOSED", "trust": "DECLARED_NOT_VERIFIED"}, actor)


def approve(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "bom_relationship", identifier)
    if row.payload["state"] != "PROPOSED" or actor == row.created_by:
        raise HTTPException(409, "Relationship needs a different human reviewer")
    validate(db, owner, row.payload)
    if aware(datetime.fromisoformat(row.payload["expires_at"])) <= utcnow():
        raise HTTPException(409, "Relationship assertion expired before review")
    return store.append(db, owner, "bom_relationship", identifier, body.expected_revision,
        {**row.payload, "state": "REVIEWED", "proposed_by": row.created_by, "approved_by": actor,
         "approval_evidence_ref": body.evidence_ref, "approval_reason": body.reason,
         "trust": "CUSTOMER_REVIEWED_ASSERTION_NOT_INDEPENDENT_RUNTIME_PROOF"}, actor)


def trace(db, owner, system_id):
    store.exact(db, System, owner, system_id)
    deployments = store.rows(db, SoftwareDeployment, owner).filter_by(system_id=system_id).limit(201).all()
    if len(deployments) > 200:
        raise HTTPException(409, "Application exceeds bounded trace; select a smaller release scope")
    paths, unresolved = [], []
    for dep in deployments:
        artifact = store.exact(db, SoftwareArtifact, owner, dep.artifact_id)
        if not active(dep):
            unresolved.append({"deployment_id": dep.id, "reason": "INACTIVE_OR_EXPIRED_DEPLOYMENT"})
            continue
        bindings = store.rows(db, ReleaseSbomBinding, owner).filter_by(artifact_id=artifact.id).limit(101).all()
        if len(bindings) > 100:
            raise HTTPException(409, "Release exceeds bounded SBOM trace")
        for binding in bindings:
            if not active(binding):
                unresolved.append({"sbom_binding_id": binding.id, "reason": "INACTIVE_OR_EXPIRED_BINDING"})
                continue
            assertions = store.rows(db, AssuranceRevision, owner).filter_by(kind="bom_relationship").filter(
                AssuranceRevision.payload["subject_id"].as_string() == binding.id,
                AssuranceRevision.payload["relation"].as_string() == "PACKAGE_CRYPTO").limit(2001).all()
            if len(assertions) > 2000:
                raise HTTPException(409, "Relationship history exceeds trace budget; narrow the release scope")
            newest = {}
            for row in assertions:
                if row.revision > getattr(newest.get(row.subject_id), "revision", 0):
                    newest[row.subject_id] = row
            for component in binding.components:
                purl = component.get("package_identity")
                links = [r for r in newest.values() if r.payload.get("package_identity") == purl and purl]
                resolved = False
                for link in links:
                    value = link.payload
                    if value["state"] != "REVIEWED" or aware(datetime.fromisoformat(value["expires_at"])) <= utcnow():
                        continue
                    try:
                        _, evidence = validate(db, owner, value)
                    except HTTPException:
                        continue
                    resolved = True
                    paths.append({"application_id": system_id, "deployment_id": dep.id,
                        "deployment_basis": dep.assertion_source, "deployment_evidence_ref": dep.evidence_ref,
                        "artifact_id": artifact.id, "artifact_digest": artifact.digest, "artifact_identity_source": artifact.identity_source,
                        "sbom_binding_id": binding.id, "sbom_sha256": binding.sbom_sha256, "package_identity": purl,
                        "crypto_evidence_id": evidence.id, "algorithm": evidence.algorithm, "purpose": evidence.purpose,
                        "location": {"file": evidence.file_path, "line": evidence.line_number},
                        "relationship_id": link.subject_id, "relationship_sha256": link.payload_sha256,
                        "evidence_ids": value["evidence_ids"], "trust": value["trust"],
                        "deployed_verified": False, "invocation_verified": False})
                    if len(paths) > 5000:
                        raise HTTPException(409, "Application trace exceeds path budget")
                if not resolved:
                    unresolved.append({"artifact_id": artifact.id, "sbom_binding_id": binding.id,
                        "bom_ref": component.get("bom_ref"), "package_identity": purl,
                        "reason": "NO_CURRENT_REVIEWED_CRYPTO_EDGE" if purl else "UNRESOLVED_EXACT_PACKAGE_VERSION"})
                    if len(unresolved) > 5000:
                        raise HTTPException(409, "Application trace exceeds unresolved-component budget")
        if not bindings:
            unresolved.append({"artifact_id": artifact.id, "reason": "NO_SBOM_BINDING"})
    return {"application_id": system_id, "paths": paths, "unresolved": unresolved,
            "complete": False, "runtime_verified": False,
            "note": "Explicit evidence-traceable reviewed assertions; package presence is not deployment, invocation, firmware, security use or independent supplier trust."}
