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
from shared_models.software_identity import package_identity
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


def current_components(binding, owner):
    """Current joins need retained original bytes, not only a derived SQL index."""
    import hashlib
    from api.routers.devsecops import _sbom_storage, _find_manifest, _artifact_blob
    from devsecops.software_identity import sbom_components
    from shared_models.qualified_export import bounded_json
    from shared_models.software_identity import MAX_SBOM_BYTES
    try:
        storage = _sbom_storage()
        manifest = _find_manifest(storage, binding.sbom_artifact_id, tenant_id=owner)
        if not manifest or manifest.get("tenant_id") != owner:
            raise ValueError("Original owner unavailable")
        raw, _ = _artifact_blob(storage, manifest, owner)
        if (len(raw) > MAX_SBOM_BYTES or hashlib.sha256(raw).hexdigest() != binding.sbom_sha256
                or binding.sbom_sha256 != manifest.get("sha256")):
            raise ValueError("Original digest mismatch")
        return sbom_components(bounded_json(raw, max_bytes=MAX_SBOM_BYTES))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, HTTPException):
        raise HTTPException(409, "Current original SBOM evidence unavailable or inconsistent") from None


def validate(db, owner, value, *, resolved=None):
    if value.get("schema_version") == "cryptoscan.host-association/v1":
        raise HTTPException(409, "Host associations require the scoped host evidence review adapter")
    if (value["subject_type"], value["object_type"]) != TYPES[value["relation"]]:
        raise HTTPException(422, "Relationship has incompatible typed endpoints")
    if resolved is not None and value["relation"] == "PACKAGE_CRYPTO":
        a, identities, evidence = resolved
        b = evidence.get(value["object_id"])
        proofs = [evidence.get(i) for i in value["evidence_ids"]]
        if (a.id != value["subject_id"] or a.tenant_id != owner or b is None
                or any(e is None or e.tenant_id != owner for e in [b, *proofs])):
            raise HTTPException(404, "Referenced evidence/identity not found")
    else:
        a = store.exact(db, MODELS[value["subject_type"]], owner, value["subject_id"])
        b = store.exact(db, MODELS[value["object_type"]], owner, value["object_id"])
        proofs = [store.exact(db, EvidenceRecord, owner, i) for i in value["evidence_ids"]]
    if not active(a) or not active(b) or any(not active(e) for e in proofs):
        raise HTTPException(409, "Inactive/expired/retracted identity or evidence")
    if value["object_type"] == "evidence" and value["object_id"] not in value["evidence_ids"]:
        raise HTTPException(422, "Object observation must be among the explicit supporting evidence")
    if value["relation"] == "PACKAGE_CRYPTO":
        if resolved is None:
            identities = {package_identity(c.get("package_identity")) for c in current_components(a, owner)}
        if not value["package_identity"] or value["package_identity"] not in identities:
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


def _current(value):
    # Intake validation is not enough after a clock correction or restore.
    return (aware(datetime.fromisoformat(value["observed_at"])) <= utcnow()
            < aware(datetime.fromisoformat(value["expires_at"])))


def approve(db, owner, identifier, body, actor):
    row = store.latest(db, owner, "bom_relationship", identifier)
    if row.payload["state"] != "PROPOSED" or actor == row.created_by:
        raise HTTPException(409, "Relationship needs a different human reviewer")
    validate(db, owner, row.payload)
    if not _current(row.payload):
        raise HTTPException(409, "Relationship observation/freshness window is not current for review")
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
            components = current_components(binding, owner)
            assertions = store.rows(db, AssuranceRevision, owner).filter_by(kind="bom_relationship").filter(
                AssuranceRevision.payload["subject_id"].as_string() == binding.id,
                AssuranceRevision.payload["relation"].as_string() == "PACKAGE_CRYPTO").limit(2001).all()
            if len(assertions) > 2000:
                raise HTTPException(409, "Relationship history exceeds trace budget; narrow the release scope")
            newest = {}
            for row in assertions:
                # Verify every loaded envelope, including predecessors, before
                # it influences revision selection or a returned evidence path.
                store.verify(row)
                if row.revision > getattr(newest.get(row.subject_id), "revision", 0):
                    newest[row.subject_id] = row
            # Request-local batched reads, not a cross-request truth cache.
            # All loaded history is verified above; preserve exact owner and
            # each link's current lifecycle/freshness checks below.
            evidence_ids = {i for row in newest.values() for i in [row.payload["object_id"], *row.payload["evidence_ids"]]}
            if len(evidence_ids) > 10000:
                raise HTTPException(409, "Trace exceeds current evidence identity budget")
            evidence_rows = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == owner,
                EvidenceRecord.id.in_(evidence_ids)).populate_existing().all() if evidence_ids else []
            prefetched = (binding, {package_identity(c.get("package_identity")) for c in components}, {r.id: r for r in evidence_rows})
            for component in components:
                # Re-evaluate legacy derived identities without rewriting the
                # stored SBOM or historical reviewed assertion.
                purl = package_identity(component.get("package_identity"))
                links = [r for r in newest.values() if r.payload.get("package_identity") == purl and purl]
                resolved = False
                for link in links:
                    value = link.payload
                    if value["state"] != "REVIEWED" or not _current(value):
                        continue
                    try:
                        _, evidence = validate(db, owner, value, resolved=prefetched)
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
