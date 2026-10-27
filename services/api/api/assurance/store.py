"""Exact-estate append-only revisions with optimistic concurrency and hash links."""
import hashlib
import json
import uuid
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from db.models.assurance import AssuranceRevision, AssuranceBlob
from db.models.base import utcnow
from db.models.user import User, UserSession
from db.repositories.execution_control import aware, current_request_principal, policy_for, required
from shared_models.software_identity import scope_key


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def subject(*parts):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, encoded(parts).decode()))


def rows(db, model, owner):
    return db.query(model).filter(model.tenant_id == owner, model.scope_key == scope_key(owner))


def actor(db, request, username, permission):
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX
    principal = current_request_principal()
    if not principal or principal.get("v") != 2 or principal.get("kind") != "user" or getattr(request.state, "api_key_auth", None):
        raise HTTPException(403, "A current typed human session is required")
    user = db.query(User).filter_by(id=principal["id"], username=username, is_active=True, deleted_at=None).one_or_none()
    credential = db.get(UserSession, principal["credential_id"])
    if (not user or not credential or credential.user_id != user.id or credential.revoked_at
            or aware(credential.expires_at) <= utcnow()
            or not set(normalize_roles(user.role_list)) & PERMISSION_MATRIX[permission]):
        raise HTTPException(403, "Current durable human authority is required")
    return user.id


def residency(db, owner):
    if required():
        try:
            policy_for(db, owner, allow_stopped=True)
        except Exception:
            raise HTTPException(409, "Assurance evidence residency admission unavailable") from None


def latest(db, owner, kind, identifier, *, required=True):
    row = rows(db, AssuranceRevision, owner).filter_by(kind=kind, subject_id=identifier).order_by(AssuranceRevision.revision.desc()).first()
    if row is None and required:
        raise HTTPException(404, "Assurance record not found")
    if row is not None:
        verify(row)
    return row


def latest_many(db, owner, kind, identifiers):
    if not identifiers:
        return {}
    sub = (select(AssuranceRevision.subject_id, func.max(AssuranceRevision.revision).label("rev"))
           .where(AssuranceRevision.tenant_id == owner, AssuranceRevision.scope_key == scope_key(owner),
                  AssuranceRevision.kind == kind, AssuranceRevision.subject_id.in_(identifiers))
           .group_by(AssuranceRevision.subject_id).subquery())
    result = rows(db, AssuranceRevision, owner).join(sub, (AssuranceRevision.subject_id == sub.c.subject_id) & (AssuranceRevision.revision == sub.c.rev)).filter(AssuranceRevision.kind == kind).all()
    for r in result:
        verify(r)
    return {r.subject_id: r for r in result}


def append(db, owner, kind, identifier, expected, payload, actor_id, *, commit=True):
    old = latest(db, owner, kind, identifier, required=False)
    if (old.revision if old else 0) != expected:
        raise HTTPException(409, "Immutable assurance revision conflict")
    # Detach mutable caller data, bound stored JSON, and bind content to scope,
    # subject, revision, predecessor and the actual human author (not body fields).
    payload = json.loads(encoded(payload))
    if len(encoded(payload)) > 1500000:
        raise HTTPException(413, "Assurance record exceeds storage limit")
    envelope = {"scope": scope_key(owner), "kind": kind, "subject_id": identifier,
                "revision": expected + 1, "payload": payload, "created_by": actor_id,
                "previous_sha256": old.payload_sha256 if old else None}
    row = AssuranceRevision(tenant_id=owner, scope_key=scope_key(owner), kind=kind, subject_id=identifier,
                            revision=expected + 1, payload=payload, created_by=actor_id,
                            payload_sha256=digest(envelope), previous_sha256=envelope["previous_sha256"])
    db.add(row)
    try:
        db.flush()
        if commit:
            db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Concurrent assurance revision; reload before retry") from None
    return row


def verify(row):
    envelope = {"scope": row.scope_key, "kind": row.kind, "subject_id": row.subject_id,
                "revision": row.revision, "payload": row.payload, "created_by": row.created_by,
                "previous_sha256": row.previous_sha256}
    if digest(envelope) != row.payload_sha256:
        raise HTTPException(409, "Assurance revision integrity mismatch")


def public(row):
    verify(row)
    return row.to_dict(exclude={"scope_key"})


def blob(db, owner, identifier):
    row = rows(db, AssuranceBlob, owner).filter_by(id=identifier).one_or_none()
    if not row:
        raise HTTPException(404, "Evidence blob not found")
    if row.byte_count != len(row.data) or hashlib.sha256(row.data).hexdigest() != row.sha256:
        raise HTTPException(409, "Evidence blob integrity mismatch")
    return row


def exact(db, model, owner, identifier):
    row = db.query(model).filter(model.id == identifier, model.tenant_id == owner).one_or_none()
    if row is None:
        raise HTTPException(404, "Referenced evidence/identity not found")
    return row
