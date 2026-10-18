"""Audited lifecycle changes; collection absence is uncertainty, never deletion."""
from __future__ import annotations
import hashlib
import json
import uuid
from datetime import timedelta
from typing import Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from api.dependencies import get_current_user, get_db_session, require_roles
from api.routers.software_supply_chain import _tenant, _WRITERS
from db.models.relationship_lifecycle import RelationshipCollection, RelationshipLifecycleEvent, RelationshipSource
from db.models.system import System
from db.models.system_dependency import SystemDependency
from db.models.software_supply_chain import ReleaseSbomBinding, SoftwareDeployment
from shared_models.relationship_lifecycle import clock, effective_state, lifecycle_payload, utc, TERMINAL
from shared_models.software_identity import scope_key

router = APIRouter(prefix="/relationship-lifecycle", tags=["relationship-lifecycle"])
Kind = Literal["system_dependency", "sbom_binding", "deployment"]
MODELS = {"system_dependency": SystemDependency, "sbom_binding": ReleaseSbomBinding, "deployment": SoftwareDeployment}
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
Source = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$")]
RecordId = Annotated[str, StringConstraints(min_length=1, max_length=36)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Change(Strict):
    expected_revision: int = Field(ge=0)
    state: Literal["ACTIVE", "STALE", "DELETED", "SUPERSEDED"]
    reason: Text
    evidence_ref: Text
    valid_until: AwareDatetime | None = None


class Claim(Strict):
    expected_revision: int = Field(ge=0)
    expected_source: Source
    source_id: Source
    reason: Text
    evidence_ref: Text


class Confirmation(Strict):
    id: RecordId
    expected_revision: int = Field(ge=0)
    valid_until: AwareDatetime | None = None


class Collection(Strict):
    collection_key: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
    sequence: int = Field(ge=1, le=2147483647)
    outcome: Literal["COMPLETE", "PARTIAL", "FAILED"]
    observed_at: AwareDatetime
    reported_count: int = Field(ge=0)
    truncated: bool = True
    observed: list[Confirmation] = Field(max_length=5000)
    evidence_ref: Text

    @model_validator(mode="after")
    def safe_complete(self):
        if len({r.id for r in self.observed}) != len(self.observed):
            raise ValueError("duplicate record IDs")
        if self.reported_count < len(self.observed):
            raise ValueError("reported count is smaller than the supplied records")
        if self.outcome == "COMPLETE" and (self.truncated or self.reported_count != len(self.observed)):
            raise ValueError("COMPLETE requires explicit truncated=false and an exact reported count")
        if self.outcome == "FAILED" and self.observed:
            raise ValueError("FAILED cannot confirm records")
        return self


def scoped(db, model, tenant):
    query = db.query(model).filter(model.tenant_id == tenant)
    if hasattr(model, "scope_key"):
        query = query.filter(model.scope_key == scope_key(tenant))
    if model is SystemDependency:
        # An edge's owner alone is not authority to adopt foreign endpoints.
        own = db.query(System.id).filter(System.tenant_id == tenant)
        query = query.filter(model.parent_id.in_(own), model.child_id.in_(own))
    return query.populate_existing()


def record(db, kind, identifier, tenant):
    row = scoped(db, MODELS[kind], tenant).filter_by(id=identifier).one_or_none()
    if row is None:
        raise HTTPException(404, "relationship not found")
    return row


def public(row, now=None):
    result = row.to_dict(exclude={"scope_key", "components"})
    result["effective_state"] = effective_state(result, now=now or clock())
    return result


def mutate(db, row, kind, tenant, user, values, *, expected_revision, reason, evidence_ref, collection_id=None):
    before = lifecycle_payload(row)
    if row.lifecycle_revision != expected_revision:
        raise HTTPException(409, "relationship revision changed; reload before retrying")
    values = {**values, "lifecycle_revision": expected_revision + 1,
              "lifecycle_reason": reason, "lifecycle_evidence_ref": evidence_ref}
    count = scoped(db, MODELS[kind], tenant).filter_by(id=row.id, lifecycle_revision=expected_revision).update(values, synchronize_session=False)
    if count != 1:
        raise HTTPException(409, "relationship concurrently changed; retry the entire operation")
    db.expire(row)
    db.refresh(row)
    identity = {key: getattr(row, key) for key in ("parent_id", "child_id", "relation", "artifact_id", "sbom_artifact_id", "sbom_sha256", "system_id", "deployment_key", "environment") if hasattr(row, key)}
    db.add(RelationshipLifecycleEvent(tenant_id=tenant, scope_key=scope_key(tenant), record_kind=kind,
        record_id=row.id, collection_id=collection_id, identity=identity, before=before,
        after=lifecycle_payload(row), reason=reason, evidence_ref=evidence_ref, created_by=user))


def commit(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "concurrent lifecycle update; retry with the same collection key or reload revisions")


@router.get("/{kind}/{identifier}/events")
def events(kind: Kind, identifier: str, request: Request, limit: int = Query(100, ge=1, le=500),
           user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    tenant = _tenant(request, db, user)
    # Events survive independently, including deletion of an enclosing system.
    query = scoped(db, RelationshipLifecycleEvent, tenant).filter_by(record_kind=kind, record_id=identifier)
    count = query.count()
    rows = query.order_by(RelationshipLifecycleEvent.created_at, RelationshipLifecycleEvent.id).limit(limit).all()
    return {"events": [r.to_dict(exclude={"scope_key"}) for r in rows], "total_count": count, "truncated": count > len(rows)}


@router.get("/{kind}/{identifier}")
def detail(kind: Kind, identifier: str, request: Request, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return public(record(db, kind, identifier, _tenant(request, db, user)))


@router.post("/{kind}/{identifier}/state")
def change(kind: Kind, identifier: str, body: Change, request: Request,
           user: str = Depends(require_roles(*_WRITERS)), db: Session = Depends(get_db_session)):
    tenant = _tenant(request, db, user)
    row = record(db, kind, identifier, tenant)
    now = clock()
    values = {"lifecycle_state": body.state}
    if "valid_until" in body.model_fields_set:
        values["valid_until"] = utc(body.valid_until) if body.valid_until is not None else None
    if body.state == "ACTIVE":
        if effective_state({**lifecycle_payload(row), **values}, now=now) != "ACTIVE":
            raise HTTPException(409, "reactivation requires clearing or renewing the expired validity deadline explicitly")
        values["last_confirmed_at"] = now
    mutate(db, row, kind, tenant, user, values, expected_revision=body.expected_revision,
           reason=body.reason, evidence_ref=body.evidence_ref)
    commit(db)
    return public(row, now)


@router.post("/{kind}/{identifier}/claim")
def claim(kind: Kind, identifier: str, body: Claim, request: Request,
          user: str = Depends(require_roles(*_WRITERS)), db: Session = Depends(get_db_session)):
    tenant = _tenant(request, db, user)
    row = record(db, kind, identifier, tenant)
    if body.source_id == "manual" or body.source_id == row.lifecycle_source or body.expected_source != row.lifecycle_source:
        raise HTTPException(409, "claim requires an explicit matching previous owner and a different non-manual source")
    mutate(db, row, kind, tenant, user, {"lifecycle_source": body.source_id}, expected_revision=body.expected_revision,
           reason=body.reason, evidence_ref=body.evidence_ref)
    commit(db)
    return public(row)


def _reconcile(kind: Kind, source_id: Source, body: Collection, request: Request,
              user: str = Depends(require_roles(*_WRITERS)), db: Session = Depends(get_db_session)):
    tenant = _tenant(request, db, user)
    if source_id == "manual":
        raise HTTPException(409, "manual assertions require an explicit ownership claim before collection")
    normalized = body.model_dump(mode="json")
    normalized["observed_at"] = utc(body.observed_at).isoformat()
    normalized["observed"] = sorted([r.model_dump(mode="json", exclude_unset=True) for r in body.observed], key=lambda row: row["id"])
    for item in normalized["observed"]:
        if item.get("valid_until") is not None:
            item["valid_until"] = utc(item["valid_until"]).isoformat()
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    receipts = scoped(db, RelationshipCollection, tenant).filter_by(record_kind=kind, source_id=source_id)
    existing = receipts.filter_by(collection_key=body.collection_key).one_or_none()
    if existing:
        if existing.payload_hash != digest:
            raise HTTPException(409, "collection key already names a different payload")
        return existing.result
    now = clock()
    if utc(body.observed_at) > now + timedelta(minutes=5):
        raise HTTPException(422, "observation clock is in the future")
    sources = scoped(db, RelationshipSource, tenant).filter_by(record_kind=kind, source_id=source_id)
    source = sources.one_or_none()
    if source is None:
        source = RelationshipSource(tenant_id=tenant, scope_key=scope_key(tenant), record_kind=kind, source_id=source_id, last_sequence=0)
        db.add(source)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "source concurrently initialized; retry the identical request")
    if body.sequence <= source.last_sequence:
        raise HTTPException(409, "out-of-order source sequence")
    changed = sources.filter_by(last_sequence=source.last_sequence).update({"last_sequence": body.sequence}, synchronize_session=False)
    if changed != 1:
        raise HTTPException(409, "source concurrently collected; retry the identical request")
    collection_id = str(uuid.uuid4())
    query = scoped(db, MODELS[kind], tenant).filter_by(lifecycle_source=source_id)
    # A COMPLETE collection is an authoritative enumeration of one bounded stream.
    # Partition large sources explicitly; never silently retire a truncated tail.
    owned = query.limit(5001).all() if body.outcome == "COMPLETE" else query.filter(MODELS[kind].id.in_([r.id for r in body.observed])).all()
    if len(owned) > 5000:
        raise HTTPException(409, "source exceeds reconciliation bound; partition ownership before complete collection")
    by_id = {r.id: r for r in owned}
    if any(r.id not in by_id for r in body.observed):
        raise HTTPException(404, "record not found in this source and estate; no implicit adoption")
    # Fresh observations must not be overwritten by older source clocks, even
    # when an old collector supplies a higher sequence.
    if any(r.last_confirmed_at and utc(r.last_confirmed_at) > utc(body.observed_at) for r in owned):
        raise HTTPException(409, "collection predates a relationship confirmation")
    confirmed, stale, terminal = [], [], []
    for item in body.observed:
        row = by_id[item.id]
        if row.lifecycle_revision != item.expected_revision:
            raise HTTPException(409, "record revision changed; retry the entire collection")
        if row.lifecycle_state in TERMINAL:
            terminal.append(row.id)
            continue  # automatic collection cannot resurrect explicit tombstones
        if row.lifecycle_state not in {"ACTIVE", "STALE", "EXPIRED"}:
            raise HTTPException(409, "unknown lifecycle state requires explicit operator repair")
        values = {"lifecycle_state": "ACTIVE", "last_confirmed_at": utc(body.observed_at), "last_reconciliation_id": collection_id}
        if "valid_until" in item.model_fields_set:
            # A collector can renew but cannot remove a safety deadline.
            if item.valid_until is None or utc(item.valid_until) <= utc(body.observed_at):
                raise HTTPException(422, "confirmation deadline must be later than observation time; explicit operator change is required to clear it")
            values["valid_until"] = utc(item.valid_until)
        mutate(db, row, kind, tenant, user, values, expected_revision=item.expected_revision,
               reason="confirmed_by_collection", evidence_ref=body.evidence_ref, collection_id=collection_id)
        confirmed.append(row.id)
    if body.outcome == "COMPLETE":
        observed = {r.id for r in body.observed}
        for row in owned:
            if row.id not in observed and row.lifecycle_state == "ACTIVE":
                mutate(db, row, kind, tenant, user, {"lifecycle_state": "STALE", "last_reconciliation_id": collection_id},
                       expected_revision=row.lifecycle_revision, reason="missing_from_complete_collection",
                       evidence_ref=body.evidence_ref, collection_id=collection_id)
                stale.append(row.id)
    result = {"id": collection_id, "source_id": source_id, "sequence": body.sequence, "outcome": body.outcome,
              "confirmed_ids": sorted(confirmed), "stale_ids": sorted(stale), "terminal_ids_not_reactivated": sorted(terminal),
              "observed_at": body.observed_at.isoformat(), "evidence_ref": body.evidence_ref,
              "reported_count": body.reported_count, "truncated": body.truncated, "payload_hash": digest,
              "absence_means": "uncertainty, not deletion or remediation"}
    db.add(RelationshipCollection(id=collection_id, tenant_id=tenant, scope_key=scope_key(tenant), record_kind=kind,
        source_id=source_id, collection_key=body.collection_key, sequence=body.sequence, outcome=body.outcome,
        payload_hash=digest, result=result, created_by=user))
    commit(db)
    return result


@router.post("/{kind}/sources/{source_id}/collections")
def reconcile(kind: Kind, source_id: Source, body: Collection, request: Request,
              user: str = Depends(require_roles(*_WRITERS)), db: Session = Depends(get_db_session)):
    try:
        return _reconcile(kind, source_id, body, request, user, db)
    except Exception:
        db.rollback()
        raise


@router.get("/{kind}/sources/{source_id}/collections")
def collections(kind: Kind, source_id: Source, request: Request, limit: int = Query(100, ge=1, le=500),
                user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    tenant = _tenant(request, db, user)
    query = scoped(db, RelationshipCollection, tenant).filter_by(record_kind=kind, source_id=source_id)
    count = query.count()
    rows = query.order_by(RelationshipCollection.sequence.desc()).limit(limit).all()
    source = scoped(db, RelationshipSource, tenant).filter_by(record_kind=kind, source_id=source_id).one_or_none()
    return {"collections": [r.to_dict(exclude={"scope_key"}) for r in rows], "total_count": count,
            "truncated": count > len(rows), "last_sequence": source.last_sequence if source else 0}
