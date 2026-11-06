"""The security control integration layer's API: write evidence, read findings.

Three ways to be wrong here, and the endpoint shape refuses all three.

**1. Letting a user post a snapshot.** A snapshot is the platform's own reading of a firewall,
an HSM, a KMS. A browser session cannot hold that claim: it would make "the platform observed
X" indistinguishable from "someone typed X". So ``POST /security-controls/snapshots`` requires
a *machine* identity — an mTLS agent identity when the deployment enforces one, otherwise a
service API key — and a user session token is refused with a reason, not a 401 that reads like
an expired login.

**2. Storing the same read twice.** A collector retries. A retry is not a revision, so the
write is idempotent by content digest: the same snapshot returns ``stored: false`` and the
sequence it already has, and the chain does not grow. Only a snapshot that *says* something new
advances the chain.

**3. Presenting a finding as a fact.** A finding carries its fact classes as a list, and the
write refuses one that claims ``OBSERVED`` with no observation behind it — the evidence ids are
checked, not just stored. ``NOT_CONFIGURED`` (a decision the bank has not made) and ``UNKNOWN``
(a reading nobody took) stay separate in the response because they are separate in the estate.

Reads are ordinary authenticated routes: a finding is only readable by the tenant that owns the
snapshot, because every query goes through the tenant scope rather than a caller-supplied id.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_tenant_roles
from db.models.security_control import FACT_CLASSES, FINDING_STATES
from db.models.security_control import SecurityControlFinding, SecurityControlSnapshot
from db.tenancy import current_tenant

router = APIRouter(prefix="/security-controls", tags=["security-controls"])

#: the roles that may read control evidence. Writing is not a role: it is a machine identity,
#: checked in :func:`_service_identity` below.
READ_ROLES = ("admin", "analyst", "auditor", "viewer")


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #

class FindingIn(BaseModel):
    """One statement from a snapshot. ``evidence_ids`` is mandatory for a claim."""

    control: str = Field(min_length=1, max_length=40)
    state: str = Field(min_length=1, max_length=40)
    subject: str | None = Field(default=None, max_length=400)
    vendor: str | None = Field(default=None, max_length=120)
    kind: str = Field(default="STATE", max_length=40)
    facts: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    expected: dict[str, Any] | None = None
    observed: dict[str, Any] | None = None
    detail: dict[str, Any] | None = None
    reason: str | None = Field(default=None, max_length=1000)


class SnapshotIn(BaseModel):
    """A read, as the collector saw it: the body's digest, the chain, and the findings."""

    digest: str = Field(min_length=8, max_length=80)
    captured_at: datetime | None = None
    controls: list[str] = Field(default_factory=list)
    counts: dict[str, Any] = Field(default_factory=dict)
    read_state: str = Field(default="OK", max_length=40)
    partial: bool = False
    refusals: int = 0
    body_digest: str = Field(default="", max_length=80)
    body_location: str = Field(default="", max_length=400)
    body_bytes: int = 0
    collector: str = Field(default="", max_length=120)
    #: the collector's own signature over the body, when the deployment binds signatures to
    #: agent identities. Verifying it is what turns "a machine connected" into "this machine
    #: produced this snapshot".
    signature: dict[str, Any] | None = None
    findings: list[FindingIn] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #

def _service_identity(request: Request,
                      signature: dict[str, Any] | None = None) -> dict[str, Any]:
    """The machine that is writing, or a refusal that says which credential was wrong.

    A collector proves itself one of two ways, and the deployment decides which is required:
    a certificate-backed agent identity (``CRYPTOSCAN_REQUIRE_AGENT_IDENTITY``), or a machine
    API key (``X-API-Key``). What is never accepted is a **user** session token: a snapshot
    asserts that the platform read a bank control, and a person holding a browser session has
    read nothing. That is refused with its own error code, so an operator sees "wrong kind of
    credential" rather than a generic 401 that looks like an expired login.
    """
    from api.dependencies import _resolve_api_key, _token_from_request
    from api.security import agent_identity

    state = getattr(request, "state", None)
    agent = getattr(state, "agent_identity", None) if state is not None else None

    if agent is not None:
        from api.routers.ingestion import _require_bound_identity

        _require_bound_identity(request, signature)
        return {"kind": "agent", "id": getattr(agent, "agent_id", "") or "",
                "signature_bound": True}

    # no agent certificate. A user session token is refused here, before the API key is even
    # considered, so an interactive login can never be mistaken for a collector.
    token = _token_from_request(request)
    if token and not request.headers.get("x-api-key"):
        from api.dependencies import SessionManager

        if SessionManager().validate_session(token):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "user_token_not_accepted",
                    "reason": "a user session authenticated this request; control evidence is "
                              "written by a collector identity (agent certificate or service "
                              "API key)",
                    "stored": False,
                    "note": "accepting it would make \"the platform observed this device\" "
                            "indistinguishable from \"someone typed it\"",
                },
            )

    api_key = _resolve_api_key(request)
    if isinstance(api_key, tuple):
        principal, roles, key_id = api_key
        return {"kind": "api_key", "id": key_id or principal, "principal": principal,
                "roles": list(roles), "signature_bound": False}

    if agent_identity.enforcement_enabled():
        raise HTTPException(
            status_code=403,
            detail={
                "error": "service_identity_required",
                "reason": "this deployment requires a certificate-backed agent identity to "
                          "write control evidence; no agent identity was established",
                "stored": False,
            },
        )

    raise HTTPException(
        status_code=403,
        detail={
            "error": "service_identity_required",
            "reason": "control evidence is written by a collector identity (an agent "
                      "certificate or a service API key), never by a user session token",
            "stored": False,
        },
    )


# --------------------------------------------------------------------------- #
# write
# --------------------------------------------------------------------------- #

def _validate(findings: list[FindingIn]) -> list[dict[str, str]]:
    """Every reason a finding would be a claim the layer cannot back."""
    problems: list[dict[str, str]] = []
    for index, finding in enumerate(findings):
        state = finding.state.upper()
        if state not in FINDING_STATES:
            problems.append({"index": str(index), "code": "UNKNOWN_STATE",
                             "reason": f"{finding.state} is not a state this layer reports"})
            continue
        unknown = [fact for fact in finding.facts if fact not in FACT_CLASSES]
        if unknown:
            problems.append({"index": str(index), "code": "UNKNOWN_FACT_CLASS",
                             "reason": f"{', '.join(unknown)} is not a fact class"})
        if state in {"CONFIGURED", "OBSERVED", "WITHIN_LIMIT", "OVER_LIMIT"} \
                and not finding.evidence_ids:
            problems.append({"index": str(index), "code": "FINDING_WITHOUT_EVIDENCE",
                             "reason": (f"a {state} finding cites nothing; a statement with "
                                        "no evidence id is an assertion, not a reading")})
        if not finding.facts:
            problems.append({"index": str(index), "code": "FINDING_WITHOUT_FACT_CLASS",
                             "reason": "a finding must say which of CONFIGURED, OBSERVED, "
                                       "RUNTIME_OBSERVED or INFERRED it rests on"})
    return problems


@router.post("/snapshots")
def post_snapshot(
    body: SnapshotIn,
    request: Request,
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Store one control snapshot and its findings. Idempotent by digest."""
    identity = _service_identity(request, body.signature)

    problems = _validate(body.findings)
    if problems:
        raise HTTPException(status_code=422,
                            detail={"error": "finding_refused", "problems": problems,
                                    "stored": False,
                                    "note": "a refused finding is not a failed request, it is "
                                            "a claim the model will not store"})

    from shared_models import chrono

    tenant = current_tenant()
    captured = body.captured_at or chrono.utcnow()
    if captured.tzinfo is None:
        captured = captured.replace(tzinfo=timezone.utc)

    existing = db.execute(
        select(SecurityControlSnapshot).where(SecurityControlSnapshot.digest == body.digest)
    ).scalars().first()
    if existing is not None:
        return {
            "stored": False,
            "duplicate": True,
            "snapshot_id": existing.id,
            "digest": existing.digest,
            "sequence": existing.sequence,
            "captured_at": _iso(existing.captured_at),
            "findings": _count_findings(db, existing.id),
            "reason": "this evidence is already retained; a retry is not a revision",
            "collector": existing.collector,
        }

    previous = db.execute(
        select(SecurityControlSnapshot).order_by(SecurityControlSnapshot.sequence.desc())
    ).scalars().first()
    snapshot = SecurityControlSnapshot(
        tenant_id=tenant,
        digest=body.digest,
        sequence=(previous.sequence + 1) if previous else 1,
        previous_hash=previous.entry_hash if previous else "",
        entry_hash=body.digest,  # replaced below, once the row's own content is known
        captured_at=captured,
        controls=body.controls,
        counts=body.counts,
        body_digest=body.body_digest or body.digest,
        body_location=body.body_location,
        body_bytes=body.body_bytes,
        collector=body.collector or identity["id"],
        read_state=body.read_state.upper(),
        partial=bool(body.partial),
        refusals=int(body.refusals or 0),
    )
    snapshot.entry_hash = _entry_hash(snapshot)
    db.add(snapshot)
    db.flush()

    for finding in body.findings:
        db.add(SecurityControlFinding(
            tenant_id=tenant,
            snapshot_id=snapshot.id,
            control=finding.control.upper(),
            vendor=finding.vendor,
            subject=finding.subject,
            kind=finding.kind.upper(),
            state=finding.state.upper(),
            facts=finding.facts,
            evidence_ids=finding.evidence_ids,
            expected=finding.expected,
            observed=finding.observed,
            detail=finding.detail,
            reason=finding.reason,
        ))

    _audit(db, identity, "security_control.snapshot", target_id=snapshot.id, detail={
        "digest": body.digest, "sequence": snapshot.sequence,
        "controls": body.controls, "findings": len(body.findings),
        "read_state": snapshot.read_state,
    })
    db.commit()

    return {
        "stored": True,
        "duplicate": False,
        "snapshot_id": snapshot.id,
        "digest": snapshot.digest,
        "sequence": snapshot.sequence,
        "previous_hash": snapshot.previous_hash,
        "entry_hash": snapshot.entry_hash,
        "captured_at": _iso(snapshot.captured_at),
        "findings": len(body.findings),
        "read_state": snapshot.read_state,
        "partial": snapshot.partial,
        "collector": snapshot.collector,
        "identity": {"kind": identity["kind"],
                     "signature_bound": identity["signature_bound"]},
    }


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #

@router.get("/snapshots")
def list_snapshots(
    db: Session = Depends(get_db_session),
    user: str = Depends(require_tenant_roles(*READ_ROLES)),
    limit: int = Query(default=20, ge=1, le=200),
) -> dict[str, Any]:
    rows = db.execute(
        select(SecurityControlSnapshot)
        .order_by(SecurityControlSnapshot.sequence.desc()).limit(limit)
    ).scalars().all()
    return {
        "snapshots": [{
            "snapshot_id": row.id, "digest": row.digest, "sequence": row.sequence,
            "captured_at": _iso(row.captured_at), "controls": row.controls or [],
            "read_state": row.read_state, "partial": row.partial, "refusals": row.refusals,
            "collector": row.collector,
        } for row in rows],
        "note": ("a snapshot is a read, not a state: two snapshots that say the same thing "
                 "have the same digest and the second is a duplicate"),
    }


@router.get("/findings")
def list_findings(
    db: Session = Depends(get_db_session),
    user: str = Depends(require_tenant_roles(*READ_ROLES)),
    control: str | None = Query(default=None),
    state: str | None = Query(default=None),
    subject: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    query = select(SecurityControlFinding)
    if control:
        query = query.where(SecurityControlFinding.control == control.upper())
    if state:
        query = query.where(SecurityControlFinding.state == state.upper())
    if subject:
        query = query.where(SecurityControlFinding.subject == subject)
    rows = db.execute(query.limit(limit)).scalars().all()

    summary: dict[str, int] = {}
    for row in rows:
        summary[row.state] = summary.get(row.state, 0) + 1
    return {
        "findings": [{
            "finding_id": row.id, "snapshot_id": row.snapshot_id, "control": row.control,
            "vendor": row.vendor, "subject": row.subject, "kind": row.kind,
            "state": row.state, "facts": row.facts or [], "evidence_ids": row.evidence_ids or [],
            "expected": row.expected, "observed": row.observed, "reason": row.reason,
        } for row in rows],
        "summary": summary,
        "states_kept_separate": {
            "NOT_CONFIGURED": "a decision the bank has not made",
            "UNKNOWN": "a reading the collector could not take",
        },
    }


@router.get("/verify")
def verify_chain(
    db: Session = Depends(get_db_session),
    user: str = Depends(require_tenant_roles(*READ_ROLES)),
) -> dict[str, Any]:
    """Re-walk this tenant's chain. Finds a deleted row and an edited one, not just gaps."""
    rows = db.execute(
        select(SecurityControlSnapshot).order_by(SecurityControlSnapshot.sequence.asc())
    ).scalars().all()
    problems: list[dict[str, Any]] = []
    previous = ""
    for expected, row in enumerate(rows, start=1):
        if row.sequence != expected:
            problems.append({"code": "SEQUENCE_GAP", "at": row.digest,
                             "expected": expected, "found": row.sequence})
        if row.previous_hash != previous:
            problems.append({"code": "CHAIN_BROKEN", "at": row.digest,
                             "found_previous": row.previous_hash})
        computed = _entry_hash(row)
        if row.entry_hash != computed:
            problems.append({"code": "ENTRY_HASH_MISMATCH", "at": row.digest,
                             "sequence": row.sequence})
        previous = row.entry_hash
    return {"tenant": current_tenant(), "snapshots": len(rows), "verified": not problems,
            "problems": problems, "head": previous}


@router.get("/health")
def control_health(
    db: Session = Depends(get_db_session),
    user: str = Depends(require_tenant_roles(*READ_ROLES)),
) -> dict[str, Any]:
    """Per-control state, in the one taxonomy, with the sentence the console must render.

    "No findings" is four different answers — never asked, refused, unreachable, and read with
    nothing to report — and a console that renders the list renders all four identically. This
    route is where they stop being identical: every control the layer knows about appears here
    with a state, what that state means, what to do about it, and whether it was collected at
    all.
    """
    from cbom import security_controls as layer
    from cbom.security_controls import taxonomy

    catalogue = layer.controls()
    drivers = layer.DRIVERS
    driven = {key.split(".")[0].upper() for key in drivers}

    latest = db.execute(
        select(SecurityControlSnapshot)
        .order_by(SecurityControlSnapshot.sequence.desc()).limit(1)
    ).scalars().first()
    read_state = (latest.read_state.upper() if latest else "NOT_CONFIGURED")
    seen = set((latest.controls or []) if latest else [])

    entries: list[dict[str, Any]] = []
    for control, entry in sorted(catalogue.items()):
        if control in seen and latest is not None:
            # the control was in the most recent read; its own state is the read's state
            state = read_state if taxonomy.normalise(read_state) else "NOT_CONFIGURED"
        elif entry.get("facade") or control.lower() in driven:
            state = "NOT_CONFIGURED"
        else:
            # a device control with no driver: the dialect row documents it and nothing reads it
            state = "UNSUPPORTED_DIALECT"
        entries.append({"control": control, "state": state,
                        "vendor": None, "system": latest.collector if latest else None,
                        "detail": (f"{len(entry['adapters'])} adapter(s); "
                                   f"{'facade' if entry.get('facade') else 'device'}")})

    summary = taxonomy.summarise(entries)
    return {
        "schema": "cryptoscan.security-control-health/1",
        "tenant": current_tenant(),
        "snapshot": ({"id": latest.id, "sequence": latest.sequence,
                      "captured_at": _iso(latest.captured_at),
                      "read_state": latest.read_state, "partial": latest.partial,
                      "refusals": latest.refusals} if latest else None),
        "taxonomy": {state: taxonomy.describe(state) for state in taxonomy.STATES},
        "controls": summary["per_control"],
        "coverage": {key: summary[key] for key in
                     ("total", "counts", "collected", "failed", "absent", "refused",
                      "complete", "nothing_asked", "worst", "statement")},
        "note": ("a state describes what the platform could learn, not what the control does; "
                 "NOT_CONFIGURED and UNSUPPORTED_DIALECT are gaps in the integration and "
                 "UNREACHABLE/AUTH_FAILED are faults at the device"),
    }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _entry_hash(snapshot: SecurityControlSnapshot) -> str:
    """The chain link: the row's own content, plus the hash it follows.

    Recomputing this is what makes an edited row visible. It deliberately does not include
    ``id`` or the timestamps SQLAlchemy fills in, so a row can be verified by a reader who
    reconstructs it from the API without knowing when the insert happened.
    """
    import hashlib
    import json

    canonical = json.dumps({
        "sequence": snapshot.sequence,
        "digest": snapshot.digest,
        "previous_hash": snapshot.previous_hash,
        "captured_at": _iso(snapshot.captured_at),
        "controls": sorted(snapshot.controls or []),
    }, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _count_findings(db: Session, snapshot_id: str) -> int:
    return len(db.execute(
        select(SecurityControlFinding.id)
        .where(SecurityControlFinding.snapshot_id == snapshot_id)
    ).scalars().all())


def _audit(db: Session, identity: dict[str, Any], action: str, *,
           target_id: str, detail: dict[str, Any]) -> None:
    from db.repositories.user_repository import UserRepository

    UserRepository(db).audit(
        actor=f"{identity['kind']}:{identity['id'] or '(unnamed)'}",
        action=action,
        target_type="security_control_snapshot",
        target_id=target_id,
        detail=detail,
        outcome="SUCCESS",
    )


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


@router.get("/export")
def export_estate(
    format: str = Query(default="cyclonedx", pattern="^(cyclonedx|cef|cef-lines)$"),
    db: Session = Depends(get_db_session),
    user: str = Depends(require_tenant_roles(*READ_ROLES)),
):
    """The same estate model the console renders, in the bank's own formats.

    Item 19 of the review: a control layer whose only output is a screen is a private estate
    that the bank's SIEM and its CycloneDX pipeline cannot reconcile. This route projects the
    *same* rows the console reads — it does not re-collect, re-read a device or invent a state.

    CycloneDX 1.6 because that is what the rest of the BOM estate already emits, and because its
    ``annotations`` give a finding a subject (the control's bom-ref) without inventing a schema.
    CEF because a SIEM ingests lines, escaped, with the evidence id in an extension so an alert
    can be joined back to the snapshot it came from.
    """
    from fastapi.responses import PlainTextResponse

    from cbom.security_controls import export as control_export

    health = control_health(db=db, user=user)
    rows = db.execute(select(SecurityControlFinding).limit(1000)).scalars().all()
    by_control: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_control.setdefault(row.control, []).append({
            "state": row.state, "vendor": row.vendor, "reason": row.reason,
            "evidence_ids": row.evidence_ids or [], "finding": None,
            "read_state": (health.get("snapshot") or {}).get("read_state"),
        })

    controls: list[dict[str, Any]] = []
    for entry in health.get("controls", []):
        control = str(entry.get("control"))
        measured = by_control.get(control, [])
        if measured:
            controls.extend(dict(item, id=control, kind=entry.get("detail")) for item in measured)
        else:
            controls.append({
                "id": control, "state": entry.get("state"), "kind": entry.get("detail"),
                "vendor": entry.get("vendor"),
                # a control nobody read is CONFIGURED at best; the exporter never upgrades it
                "observation_class": "CONFIGURED",
                "reason": (health.get("taxonomy", {}).get(str(entry.get("state")), {}) or {}).get("meaning"),
                "read_state": (health.get("snapshot") or {}).get("read_state"),
            })

    projection = {
        "generated_at": (health.get("snapshot") or {}).get("captured_at"),
        "version": "1",
        "controls": controls,
        "summary": {"coverage": health.get("coverage")},
        "refusals": health.get("snapshot", {}).get("refusals") if health.get("snapshot") else [],
    }
    if format == "cyclonedx":
        return control_export.to_cyclonedx(projection)
    lines = control_export.to_cef(projection)
    body = "\n".join(lines)
    return PlainTextResponse(body if body else "# no findings in the retained snapshots\n",
                             media_type="text/plain; charset=utf-8")
