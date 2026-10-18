"""Exact-estate package SBOM -> immutable release -> deployment assertions.

No name/tag/path auto-adoption and no promotion of declarations to observation.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer

from api.dependencies import get_current_user, get_db_session, require_roles
from db.models.software_supply_chain import ReleaseSbomBinding, SoftwareArtifact, SoftwareDeployment
from db.models.system import System
from devsecops.software_identity import sbom_components
from db.repositories.user_repository import UserRepository
from shared_models.software_identity import (
    MAX_ARTIFACT_BYTES, MAX_SBOM_BYTES, SCHEMA, artifact_digest, scope_key,
)

router = APIRouter(prefix="/software-supply-chain", tags=["software-supply-chain"])
_WRITERS = ("admin", "superadmin", "security_analyst")
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
Assertion = Literal["OPERATOR_DECLARED", "SUPPLIER_DECLARED"]


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_ref: Text
    assertion_source: Assertion


class ArtifactRequest(EvidenceRequest):
    digest: str
    media_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)] = "application/octet-stream"

    @field_validator("digest")
    @classmethod
    def valid_digest(cls, value):
        return artifact_digest(value)


class SbomBindingRequest(EvidenceRequest):
    sbom_artifact_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f-]{36}$")]
    expected_sbom_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class DeploymentRequest(EvidenceRequest):
    system_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=36)]
    deployment_key: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
    environment: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)]


def _tenant(request, db, user):
    from api.routers.devsecops import _artifact_tenant
    return _artifact_tenant(request, db, user)


def _rows(db, model, tenant):
    # Exact estate, including on platform requests. Do NOT inherit the general
    # guard's shared/platform read visibility for these authoritative joins.
    return db.query(model).filter(model.tenant_id == tenant, model.scope_key == scope_key(tenant))


def _artifact(db, tenant, identifier):
    row = _rows(db, SoftwareArtifact, tenant).filter_by(id=identifier).one_or_none()
    if row is None:
        raise HTTPException(404, "artifact not found")
    return row


def _public(row, *, exclude=None):
    return row.to_dict(exclude={"scope_key", *(exclude or [])})


def _save(db, row, user, action):
    db.add(row)
    try:
        db.flush()
        UserRepository(db).audit(user, action, target_type="software_supply_chain", target_id=row.id,
                                 detail={"evidence_ref": row.evidence_ref})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "identity was concurrently registered; retry to inspect the existing assertion")
    return _public(row)


def _same(row, values):
    if any(getattr(row, key) != value for key, value in values.items()):
        raise HTTPException(409, "immutable identity/assertion conflicts with the existing record; it was not overwritten")
    return _public(row)


def _register(db, tenant, digest, media_type, source, evidence_ref, user, byte_count=None):
    values = dict(digest=digest, media_type=media_type, identity_source=source,
                  evidence_ref=evidence_ref, byte_count=byte_count)
    existing = _rows(db, SoftwareArtifact, tenant).filter_by(digest=digest).one_or_none()
    if existing:
        return _same(existing, values)
    return _save(db, SoftwareArtifact(tenant_id=tenant, scope_key=scope_key(tenant),
                                     created_by=user, **values), user, "software.artifact.register")


class SbomDocumentRequest(EvidenceRequest):
    doc: dict


@router.post("/sboms", status_code=201)
def store_sbom(body: SbomDocumentRequest, request: Request,
               db: Session = Depends(get_db_session), user: str = Depends(require_roles(*_WRITERS))):
    """Persist an external SBOM without asserting a release or deployment."""
    from api.routers.devsecops import _sbom_signing_secret, _sbom_storage
    from devsecops.artifact_crypto import encrypt_blob
    from devsecops.artifact_store import artifact_tenant_bucket
    from devsecops.sbom import check_pinning
    from devsecops.sbom_assurance import check_minimum_elements
    from devsecops.sbom_scan import sign_manifest
    from shared_models.chrono import utcnow

    tenant = _tenant(request, db, user)
    payload = json.dumps(body.doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_SBOM_BYTES:
        raise HTTPException(413, "SBOM exceeds binding byte limit")
    try:
        components = sbom_components(body.doc)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise HTTPException(422, f"unsupported SBOM: {exc}")
    identifier = str(uuid.uuid4())
    fmt = "cyclonedx" if body.doc.get("bomFormat") == "CycloneDX" else "spdx"
    key = f"tenants/{artifact_tenant_bucket(tenant)}/{identifier}.{'cdx' if fmt == 'cyclonedx' else 'spdx'}.json"
    sealed, at_rest = encrypt_blob(payload, tenant_id=tenant)
    compliance = check_minimum_elements(body.doc)
    pinning = check_pinning(components)
    manifest = {"artifact_id": identifier, "kind": "imported", "format": fmt,
                "tenant_id": tenant, "tenant_bucket": artifact_tenant_bucket(tenant), "storage_key": key,
                "sha256": hashlib.sha256(payload).hexdigest(), "component_count": len(components),
                "created_by": user, "created_at": utcnow().isoformat(), "at_rest": at_rest,
                "assertion_source": body.assertion_source, "evidence_ref": body.evidence_ref,
                "minimum_elements": compliance["score"], "compliant": compliance["compliant"],
                "pinned": pinning["pinned"], "unpinned": pinning["unpinned"], "feed_supplied": False}
    secret, key_id = _sbom_signing_secret(db)
    if secret:
        manifest.update(signature_alg="HMAC-SHA256", signature_key=key_id)
        manifest["signature"] = sign_manifest(manifest, secret)
    store = _sbom_storage()
    store.put(key, sealed)
    store.put_manifest(key, manifest)
    UserRepository(db).audit(user, "software.sbom.store", target_type="sbom_artifact", target_id=identifier,
                             detail={"sha256": manifest["sha256"], "assertion_source": body.assertion_source})
    db.commit()
    return {"schema": SCHEMA, "artifact_id": identifier, "manifest": manifest,
            "unresolved_component_count": sum(c["package_identity"] is None for c in components),
            "note": "Stored SBOM only; no release artifact or deployment inferred."}


@router.post("/artifacts", status_code=201)
def register_artifact(body: ArtifactRequest, request: Request,
                      db: Session = Depends(get_db_session), user: str = Depends(require_roles(*_WRITERS))):
    """Register a digest declaration, not an assertion we observed its bytes."""
    tenant = _tenant(request, db, user)
    return _register(db, tenant, body.digest, body.media_type, body.assertion_source, body.evidence_ref, user)


@router.post("/artifacts/measure", status_code=201)
async def measure_artifact(request: Request, evidence_ref: Text = Query(...),
                           db: Session = Depends(get_db_session), user: str = Depends(require_roles(*_WRITERS))):
    """Hash at most 16 MiB of raw bytes; discard bytes, retain content identity.

    Hashing content does not verify its origin, SBOM completeness or deployment.
    No server-side file path or outbound fetch is accepted.
    """
    tenant = _tenant(request, db, user)
    if request.headers.get("content-type", "").split(";")[0] != "application/octet-stream":
        raise HTTPException(415, "send raw application/octet-stream content")
    digest, count = hashlib.sha256(), 0
    async for chunk in request.stream():
        count += len(chunk)
        if count > MAX_ARTIFACT_BYTES:
            raise HTTPException(413, f"artifact exceeds {MAX_ARTIFACT_BYTES} byte measurement limit")
        digest.update(chunk)
    if not count:
        raise HTTPException(422, "empty artifact content")
    return _register(db, tenant, "sha256:" + digest.hexdigest(), "application/octet-stream",
                     "CONTENT_HASHED", evidence_ref, user, count)


@router.post("/artifacts/{artifact_id}/sboms", status_code=201)
def bind_sbom(artifact_id: str, body: SbomBindingRequest, request: Request,
              db: Session = Depends(get_db_session), user: str = Depends(require_roles(*_WRITERS))):
    from api.routers.devsecops import _artifact_blob, _find_manifest, _sbom_storage

    tenant = _tenant(request, db, user)
    _artifact(db, tenant, artifact_id)
    store = _sbom_storage()
    manifest = _find_manifest(store, body.sbom_artifact_id, tenant_id=tenant)
    if manifest is None or manifest.get("tenant_id") != tenant:
        # Legacy bucket normalization is not authority to adopt a document
        # whose recorded raw owner differs from this exact estate.
        raise HTTPException(404, "SBOM artifact not found")
    try:
        payload, _at_rest = _artifact_blob(store, manifest, tenant)
    except (FileNotFoundError, KeyError):
        raise HTTPException(404, "SBOM content not found")
    if len(payload) > MAX_SBOM_BYTES:
        raise HTTPException(413, "SBOM exceeds binding byte limit")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != manifest.get("sha256") or digest != body.expected_sbom_sha256:
        raise HTTPException(409, "SBOM bytes/manifest/expected digest disagree; no binding created")
    try:
        components = sbom_components(json.loads(payload))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise HTTPException(422, f"unsupported SBOM binding: {exc}")
    # A reused storage id must not disguise different document bytes, even
    # when attaching it to a different release artifact.
    previous = _rows(db, ReleaseSbomBinding, tenant).filter(
        ReleaseSbomBinding.sbom_artifact_id == body.sbom_artifact_id,
        ReleaseSbomBinding.sbom_sha256 != digest).first()
    if previous is not None:
        raise HTTPException(409, "SBOM storage identity changed content; create a new SBOM artifact id")
    values = dict(artifact_id=artifact_id, sbom_artifact_id=body.sbom_artifact_id, sbom_sha256=digest,
                  components=components, component_count=len(components),
                  unresolved_component_count=sum(c["package_identity"] is None for c in components),
                  evidence_ref=body.evidence_ref, assertion_source=body.assertion_source)
    existing = _rows(db, ReleaseSbomBinding, tenant).filter_by(
        artifact_id=artifact_id, sbom_artifact_id=body.sbom_artifact_id).one_or_none()
    if existing:
        return _same(existing, values)
    return _save(db, ReleaseSbomBinding(tenant_id=tenant, scope_key=scope_key(tenant),
                                       created_by=user, **values), user, "software.sbom.bind")


@router.post("/artifacts/{artifact_id}/deployments", status_code=201)
def bind_deployment(artifact_id: str, body: DeploymentRequest, request: Request,
                    db: Session = Depends(get_db_session), user: str = Depends(require_roles(*_WRITERS))):
    tenant = _tenant(request, db, user)
    _artifact(db, tenant, artifact_id)
    # Exact ID AND exact tenant: no name/tag matching or shared-estate adoption.
    system = db.query(System).filter(System.id == body.system_id, System.tenant_id == tenant).one_or_none()
    if system is None:
        raise HTTPException(404, "system not found")
    if system.environment and system.environment != body.environment:
        raise HTTPException(409, "deployment environment conflicts with the registered system")
    values = dict(artifact_id=artifact_id, **body.model_dump())
    existing = _rows(db, SoftwareDeployment, tenant).filter_by(deployment_key=body.deployment_key).one_or_none()
    if existing:
        return _same(existing, values)
    return _save(db, SoftwareDeployment(tenant_id=tenant, scope_key=scope_key(tenant),
                                        created_by=user, **values), user, "software.deployment.bind")


@router.get("/artifacts")
def list_artifacts(request: Request, limit: int = Query(100, ge=1, le=500),
                   db: Session = Depends(get_db_session), user: str = Depends(get_current_user)):
    tenant = _tenant(request, db, user)
    rows = _rows(db, SoftwareArtifact, tenant).order_by(SoftwareArtifact.id).limit(limit + 1).all()
    return {"schema": SCHEMA, "artifacts": [_public(row) for row in rows[:limit]], "truncated": len(rows) > limit}


@router.get("/artifacts/{artifact_id}")
def get_artifact(artifact_id: str, request: Request,
                 db: Session = Depends(get_db_session), user: str = Depends(get_current_user)):
    tenant = _tenant(request, db, user)
    artifact = _artifact(db, tenant, artifact_id)
    bindings = _rows(db, ReleaseSbomBinding, tenant).options(defer(ReleaseSbomBinding.components)).filter_by(artifact_id=artifact_id).order_by(ReleaseSbomBinding.id).limit(201).all()
    deployments = _rows(db, SoftwareDeployment, tenant).filter_by(artifact_id=artifact_id).order_by(SoftwareDeployment.id).limit(501).all()
    return {"schema": SCHEMA, "artifact": _public(artifact),
            "sbom_bindings": [_public(row, exclude={"components"}) for row in bindings[:200]],
            "deployments": [_public(row) for row in deployments[:500]],
            "truncated": len(bindings) > 200 or len(deployments) > 500,
            "note": "Bindings are declarations, not runtime deployment verification; lifecycle reconciliation is pending."}
