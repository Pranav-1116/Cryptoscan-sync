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

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError
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

    cited = [evidence_id for finding in body.findings for evidence_id in finding.evidence_ids]
    evidence_body: Any = None
    if cited:
        # the authoritative evidence store is the content-addressed body artifact: every id a
        # finding cites must resolve inside *this* snapshot's body, checked for existence,
        # tenant ownership (the path never leaves the tenant's directory), control and asset
        # association, integrity against the recorded digest, and timestamp/provenance
        raw, problem = _read_artifact(tenant, body.body_location,
                                      body.body_digest or body.digest, body.body_bytes)
        if problem:
            raise HTTPException(
                status_code=422,
                detail={"error": "evidence_unverifiable", "code": problem, "stored": False,
                        "note": ("missing evidence artifacts are unverifiable, never valid: "
                                 "a claim whose evidence cannot be read is an assertion")})
        evidence_body = json.loads(raw.decode("utf-8"))
        records, bound = _evidence_index(evidence_body)
        problems = _validate_evidence(body.findings, records, bound,
                                      captured=captured, identity=identity)
        body_captured = str(evidence_body.get("captured_at") or "") if isinstance(evidence_body, dict) else ""
        if body_captured and _iso(captured) and body_captured != _iso(captured):
            problems.append({"index": "-", "code": "EVIDENCE_TIMESTAMP_MISMATCH",
                             "reason": (f"the body was captured at {body_captured}, the "
                                        f"snapshot claims {_iso(captured)}")})
        if problems:
            raise HTTPException(
                status_code=422,
                detail={"error": "evidence_refused", "problems": problems, "stored": False,
                        "note": ("a refused evidence reference is not a failed request, it "
                                 "is a claim the model will not store")})
    if body.collector and identity.get("id") and body.collector != identity["id"]:
        raise HTTPException(
            status_code=422,
            detail={"error": "evidence_refused", "stored": False,
                    "problems": [{"index": "-", "code": "EVIDENCE_PROVENANCE_MISMATCH",
                                  "reason": ("the snapshot claims collector "
                                             f"{body.collector!r} but the credential writing "
                                             f"it is {identity['id']!r}")}]})

    snapshot: SecurityControlSnapshot | None = None
    with _sequence_lock:
        for attempt in range(5):
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
                select(SecurityControlSnapshot)
                .order_by(SecurityControlSnapshot.sequence.desc())
                .with_for_update()
            ).scalars().first()
            snapshot = SecurityControlSnapshot(
                tenant_id=tenant,
                digest=body.digest,
                sequence=(previous.sequence + 1) if previous else 1,
                previous_hash=previous.entry_hash if previous else "",
                entry_hash="",  # bound below, once every row of the manifest exists
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
            db.add(snapshot)
            try:
                db.flush()
                break
            except (IntegrityError, OperationalError):
                # a concurrent writer took this sequence (or the digest): roll back, re-read
                # the chain head, and allocate again — a gap is never produced by losing
                # this race, cross-process included (the schema turns it into a collision)
                db.rollback()
                snapshot = None
                continue
    if snapshot is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "sequence_allocation_failed", "stored": False,
                    "reason": ("five attempts to allocate the next sequence all collided "
                               "with a concurrent writer; retry the write")})

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
    db.flush()
    # the chain link binds the *complete* manifest, child findings included — a row's entry
    # hash cannot be checked without the findings it stores, and an edit to either breaks it
    snapshot.entry_hash = _entry_hash(snapshot, _finding_rows(db, snapshot.id))

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
    """Re-walk this tenant's chain and its evidence artifacts.

    Finds a deleted row and an edited one, not just gaps: the entry hash is recomputed from
    the complete manifest (child findings included), the external evidence artifact is
    verified against its recorded digest, and every evidence id a finding cites must still
    resolve inside its own snapshot's body. A missing artifact is reported **unverifiable** —
    never as valid — and a digest mismatch is a mismatch, not a gap.
    """
    tenant = current_tenant()
    rows = db.execute(
        select(SecurityControlSnapshot).order_by(SecurityControlSnapshot.sequence.asc())
    ).scalars().all()
    problems: list[dict[str, Any]] = []
    unverifiable: list[dict[str, Any]] = []
    artifacts_verified = 0
    previous = ""
    for expected, row in enumerate(rows, start=1):
        findings = _finding_rows(db, row.id)
        if row.sequence != expected:
            problems.append({"code": "SEQUENCE_GAP", "at": row.digest,
                             "expected": expected, "found": row.sequence})
        if row.previous_hash != previous:
            problems.append({"code": "CHAIN_BROKEN", "at": row.digest,
                             "found_previous": row.previous_hash})
        computed = _verify_entry_hash(row, findings)
        if row.entry_hash != computed:
            problems.append({"code": "ENTRY_HASH_MISMATCH", "at": row.digest,
                             "sequence": row.sequence})
        cited = [eid for finding in findings for eid in (finding.evidence_ids or [])]
        if row.body_location or cited:
            raw, problem = _read_artifact(tenant, row.body_location,
                                          row.body_digest or row.digest, row.body_bytes)
            if problem in ("EVIDENCE_ARTIFACT_MISSING", "EVIDENCE_ARTIFACT_UNREADABLE",
                           "NO_EVIDENCE_STORE", "EVIDENCE_LOCATION_EMPTY",
                           "EVIDENCE_LOCATION_UNSAFE"):
                unverifiable.append({"code": "EVIDENCE_UNVERIFIABLE", "at": row.digest,
                                     "sequence": row.sequence, "detail": problem})
            elif problem:
                problems.append({"code": "EVIDENCE_DIGEST_MISMATCH", "at": row.digest,
                                 "sequence": row.sequence, "detail": problem})
            elif cited:
                artifacts_verified += 1
                _, bound = _evidence_index(json.loads(raw.decode("utf-8")))
                for finding in findings:
                    for evidence_id in (finding.evidence_ids or []):
                        if evidence_id not in bound:
                            problems.append({"code": "EVIDENCE_NOT_FOUND", "at": row.digest,
                                             "sequence": row.sequence,
                                             "evidence_id": evidence_id,
                                             "detail": ("a finding cites an id its own "
                                                        "snapshot body does not contain")})
        previous = row.entry_hash
    verified = not problems and not unverifiable
    return {"tenant": tenant, "snapshots": len(rows), "verified": verified,
            "problems": problems, "head": previous,
            "evidence": {"artifacts_verified": artifacts_verified,
                         "unverifiable": unverifiable,
                         "mismatched": [p for p in problems
                                        if p["code"].startswith("EVIDENCE_")]},
            "note": ("verified means every link recomputed, every artifact read back against "
                     "its digest and every evidence id resolved; a missing artifact is "
                     "unverifiable and is never counted as valid")}


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

    all_rows = db.execute(
        select(SecurityControlSnapshot)
        .order_by(SecurityControlSnapshot.sequence.desc())
    ).scalars().all()
    latest = all_rows[0] if all_rows else None

    # device-level and control-level are tracked apart: the device's read outcome is the
    # snapshot's own read_state/partial/refusals, while each control carries the findings
    # its own covering snapshot recorded for it — a snapshot covering several controls has
    # per-control outcomes, not one state painted over all of them
    covering: dict[str, SecurityControlSnapshot] = {}
    for row in all_rows:  # newest first: the first writer per control is its latest read
        for control in (row.controls or []):
            covering.setdefault(str(control).upper(), row)

    findings_by_key: dict[tuple[str, str], list[SecurityControlFinding]] = {}
    for finding in db.execute(select(SecurityControlFinding)).scalars().all():
        findings_by_key.setdefault((finding.snapshot_id, finding.control), []).append(finding)

    entries: list[dict[str, Any]] = []
    for control, entry in sorted(catalogue.items()):
        snapshot = covering.get(control)
        findings = (findings_by_key.get((snapshot.id, control), [])
                    if snapshot is not None else [])
        states = sorted({(f.state or "").upper() for f in findings})
        if snapshot is not None:
            read_outcome = (snapshot.read_state.upper()
                            if snapshot.read_state.upper() in taxonomy.STATES
                            else "PARTIAL_READ")
            substantive = set(states) - {"UNKNOWN", "STALE_EVIDENCE", "REFUSED"}
            if substantive:
                # this control's own statements arrived: its read learned something
                state = "OK"
                detail_extra = f"{len(findings)} finding(s) in snapshot {snapshot.sequence}"
            elif states:
                # the only statements are "could not read / refused / stale": the read
                # outcome explains the control, and it is never painted as knowledge
                state = read_outcome
                detail_extra = (f"{len(findings)} failure-stanced finding(s) in snapshot "
                                f"{snapshot.sequence}; the read learned nothing here")
            else:
                state = read_outcome
                detail_extra = (f"read with no findings of its own in snapshot "
                                f"{snapshot.sequence}")
        elif entry.get("facade") or control.lower() in driven:
            state = "NOT_CONFIGURED"
            detail_extra = "no snapshot has covered this control yet"
        else:
            # a device control with no driver: the dialect row documents it and nothing reads it
            state = "UNSUPPORTED_DIALECT"
            detail_extra = "the dialect is documented; no driver reads a device for it"
        entries.append({"control": control, "state": state,
                        "vendor": None,
                        "system": snapshot.collector if snapshot else None,
                        "read_state": snapshot.read_state if snapshot else None,
                        "snapshot_sequence": snapshot.sequence if snapshot else None,
                        "findings": len(findings),
                        "finding_states": states,
                        "detail": (f"{len(entry['adapters'])} adapter(s); "
                                   f"{'facade' if entry.get('facade') else 'device'}; "
                                   f"{detail_extra}")})

    summary = taxonomy.summarise(entries)
    return {
        "schema": "cryptoscan.security-control-health/1",
        "tenant": current_tenant(),
        "snapshot": ({"id": latest.id, "sequence": latest.sequence,
                      "captured_at": _iso(latest.captured_at),
                      "read_state": latest.read_state, "partial": latest.partial,
                      "refusals": latest.refusals} if latest else None),
        "device": ({"collector": latest.collector, "read_state": latest.read_state,
                    "partial": latest.partial, "refusals": latest.refusals,
                    "captured_at": _iso(latest.captured_at),
                    "sequence": latest.sequence} if latest else None),
        "driver_coverage": _driver_coverage(),
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
# helpers — the chain link and the authoritative evidence store
# --------------------------------------------------------------------------- #

#: The entry-hash scheme for new writes: a sha256 over the *complete* canonical snapshot
#: manifest (identity, provenance, read outcome, counts and refusals, the sorted control
#: records, the sorted child finding records with their own digests, and the previous hash).
#: Rows written before the manifest fix carry a bare hex digest (scheme ``v1``); they still
#: verify under their own recorded scheme and are never silently upgraded.
ENTRY_HASH_SCHEME = "v2"

#: In-process serialisation of sequence allocation. The read-then-write of
#: ``previous.sequence + 1`` is a race, and two collectors in this process must not both
#: decide they are next. Cross-process writers are handled by the schema: the
#: ``(tenant_id, sequence)`` constraint (plus the platform-estate partial index, migration
#: 0134) turns a collision into an IntegrityError, and the write path retries it. The lock
#: is the fast path; the constraint is the truth.
_sequence_lock = threading.Lock()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _finding_record(row: SecurityControlFinding | dict[str, Any]) -> dict[str, Any]:
    """One child finding as a canonical record: every column that carries a claim."""
    return {
        "id": str(row.id),
        "control": row.control,
        "state": row.state,
        "subject": row.subject,
        "vendor": row.vendor,
        "kind": row.kind,
        "facts": list(row.facts or []),
        "evidence_ids": list(row.evidence_ids or []),
        "expected": row.expected,
        "observed": row.observed,
        "detail": row.detail,
        "reason": row.reason,
    }


def _finding_digest(row: SecurityControlFinding | dict[str, Any]) -> str:
    record = row if isinstance(row, dict) else _finding_record(row)
    return "sha256:" + hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


def _manifest(snapshot: SecurityControlSnapshot,
              findings: list[SecurityControlFinding | dict[str, Any]]) -> dict[str, Any]:
    """The complete canonical snapshot manifest the chain binds.

    Every field that can change what the snapshot *says* is in here: identity, provenance,
    capture time, the body digest and where the body lives, the read outcome (state, partial,
    counts, refusals), the sorted control records, the sorted child finding records with
    their digests, and the previous hash. An edit to any one of them breaks the link.
    """
    rows = [_finding_record(f) if not isinstance(f, dict) else f for f in findings]
    rows.sort(key=lambda r: (str(r.get("control")), str(r.get("state")), str(r.get("subject")),
                             str(r.get("vendor")), str(r.get("kind")), str(r.get("id"))))
    return {
        "snapshot": {"id": str(snapshot.id), "sequence": snapshot.sequence},
        "tenant": snapshot.tenant_id or "",
        "collector": snapshot.collector,
        "captured_at": _iso(snapshot.captured_at),
        "digest": snapshot.digest,
        "body": {"digest": snapshot.body_digest, "location": snapshot.body_location,
                 "bytes": snapshot.body_bytes},
        "read": {"state": snapshot.read_state, "partial": snapshot.partial,
                 "counts": snapshot.counts or {}, "refusals": snapshot.refusals},
        "controls": sorted(snapshot.controls or []),
        "findings": [{"digest": _finding_digest(r), "record": r} for r in rows],
        "previous_hash": snapshot.previous_hash,
    }


def _entry_hash(snapshot: SecurityControlSnapshot,
                findings: list[SecurityControlFinding | dict[str, Any]]) -> str:
    """The chain link: the full manifest, plus the hash it follows."""
    return f"{ENTRY_HASH_SCHEME}:" + hashlib.sha256(
        _canonical(_manifest(snapshot, findings)).encode("utf-8")).hexdigest()


def _entry_hash_v1(snapshot: SecurityControlSnapshot) -> str:
    """The pre-manifest scheme, kept only so history verifies under what it recorded.

    It bound sequence, digest, previous hash, capture time and the controls — which is why
    an edit to a body digest or a child finding was invisible to it. New writes never use
    this; a stored bare-hex entry hash is verified against it and reported as scheme v1.
    """
    return hashlib.sha256(_canonical({
        "sequence": snapshot.sequence,
        "digest": snapshot.digest,
        "previous_hash": snapshot.previous_hash,
        "captured_at": _iso(snapshot.captured_at),
        "controls": sorted(snapshot.controls or []),
    }).encode("utf-8")).hexdigest()


def _entry_scheme(entry_hash: str) -> str:
    return entry_hash.split(":", 1)[0] if ":" in entry_hash else "v1"


def _verify_entry_hash(snapshot: SecurityControlSnapshot,
                       findings: list[SecurityControlFinding | dict[str, Any]]) -> str:
    """Recompute the entry hash under the scheme the row itself recorded."""
    if _entry_scheme(snapshot.entry_hash) == ENTRY_HASH_SCHEME:
        return _entry_hash(snapshot, findings)
    return _entry_hash_v1(snapshot)


def _finding_rows(db: Session, snapshot_id: str) -> list[SecurityControlFinding]:
    return list(db.execute(
        select(SecurityControlFinding)
        .where(SecurityControlFinding.snapshot_id == snapshot_id)
    ).scalars().all())


# --------------------------------------------------------------------------- #
# the authoritative evidence store: the content-addressed snapshot body
# --------------------------------------------------------------------------- #

class EvidenceRefused(Exception):
    """An evidence reference the platform will not store, with the check that caught it."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _evidence_root() -> Path | None:
    from api.config.settings import get_settings

    root = get_settings().SECURITY_CONTROLS_EVIDENCE_ROOT
    return Path(root) if root else None


def _artifact_path(tenant: str | None, body_location: str) -> Path:
    """Resolve a body location inside *this tenant's* evidence directory.

    The location is always resolved under ``<root>/<tenant>/``; absolute paths, traversal
    and a location that would land anywhere else are refused. That is what makes tenant
    ownership a path property, not a caller's promise.
    """
    root = _evidence_root()
    if root is None:
        raise EvidenceRefused("NO_EVIDENCE_STORE",
                              "no evidence store is configured (SECURITY_CONTROLS_EVIDENCE_"
                              "ROOT); a snapshot that cites evidence cannot be verified, and "
                              "unverifiable evidence is never stored as valid")
    location = (body_location or "").strip()
    if not location:
        raise EvidenceRefused("EVIDENCE_LOCATION_EMPTY",
                              "the snapshot cites evidence but names no body location")
    candidate = Path(location)
    if candidate.is_absolute() or ".." in candidate.parts or location.startswith("~"):
        raise EvidenceRefused("EVIDENCE_LOCATION_UNSAFE",
                              f"body location {location!r} would escape the tenant evidence "
                              "directory; every body is read inside its own tenant's root")
    tenant_root = (root / (tenant or "_platform")).resolve()
    resolved = (tenant_root / candidate).resolve()
    if resolved != tenant_root and tenant_root not in resolved.parents:
        raise EvidenceRefused("EVIDENCE_LOCATION_UNSAFE",
                              f"body location {location!r} resolves outside the tenant "
                              "evidence directory")
    return resolved


def _read_artifact(tenant: str | None, body_location: str, body_digest: str,
                   body_bytes: int) -> tuple[bytes | None, str | None]:
    """Read and verify the snapshot body against its recorded digest.

    Returns ``(raw, error_code)``. A missing or unreadable artifact is ``unverifiable`` —
    it is never reported as valid. A digest or size mismatch is a *mismatch*: the artifact
    present is not the artifact the snapshot recorded.
    """
    try:
        path = _artifact_path(tenant, body_location)
    except EvidenceRefused as exc:
        return None, exc.code
    if not path.is_file():
        return None, "EVIDENCE_ARTIFACT_MISSING"
    try:
        raw = path.read_bytes()
    except OSError:
        return None, "EVIDENCE_ARTIFACT_UNREADABLE"
    if body_bytes and len(raw) != int(body_bytes):
        return None, "EVIDENCE_SIZE_MISMATCH"
    expected = (body_digest or "").lower().removeprefix("sha256:")
    actual = hashlib.sha256(raw).hexdigest()
    if expected and expected != actual:
        return None, "EVIDENCE_DIGEST_MISMATCH"
    return raw, None


def _evidence_index(body: Any) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """What the artifact makes resolvable: its evidence book records, and every evidence id
    bound in its content (records and the ``evidence_ids`` of its rows and findings)."""
    records: dict[str, dict[str, Any]] = {}
    bound: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            entry = node.get("evidence_id")
            if isinstance(entry, str) and entry:
                bound.add(entry)
                if "control" in node or "kind" in node:
                    records.setdefault(entry, node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, str) and item:
                    continue
                walk(item)

    # ids live under evidence_ids lists: collect those explicitly, then walk for records
    def collect_ids(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("evidence_ids",) and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item:
                            bound.add(item)
                else:
                    collect_ids(value)
        elif isinstance(node, list):
            for item in node:
                collect_ids(item)

    collect_ids(body)
    walk(body)
    if isinstance(body, dict):
        for entry in body.get("evidence") or []:
            if isinstance(entry, dict) and isinstance(entry.get("evidence_id"), str):
                records.setdefault(entry["evidence_id"], entry)
                bound.add(entry["evidence_id"])
    return records, bound


def _norm_key(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _driver_coverage() -> dict[str, Any]:
    from cbom.security_controls.drivers import driver_coverage

    return driver_coverage()


def _validate_evidence(findings: list[FindingIn], records: dict[str, dict[str, Any]],
                       bound: set[str], *, captured: datetime,
                       identity: dict[str, Any]) -> list[dict[str, str]]:
    """Every reason a cited evidence id would not back the finding that cites it.

    Existence in the store, control and asset association, vendor and provenance
    consistency, and a fact classification that actually supports the state — each check is
    named so a refusal tells the collector what to fix instead of "invalid evidence".
    """
    problems: list[dict[str, str]] = []
    for index, finding in enumerate(findings):
        for evidence_id in finding.evidence_ids:
            tag = {"index": str(index), "evidence_id": evidence_id}
            if evidence_id not in bound:
                problems.append({**tag, "code": "EVIDENCE_NOT_FOUND",
                                 "reason": ("the evidence store has no record of this id "
                                            "under this snapshot's body; an arbitrary id is "
                                            "not evidence")})
                continue
            record = records.get(evidence_id)
            if record is None:
                continue  # content-bound in the artifact rows but not in the book: existence
                          # and the artifact digest are all that can be checked
            if _norm_key(record.get("control")) != _norm_key(finding.control):
                problems.append({**tag, "code": "EVIDENCE_CONTROL_MISMATCH",
                                 "reason": (f"the record was minted for "
                                            f"{record.get('control')!r}, not "
                                            f"{finding.control!r}")})
            subject = _norm_key(finding.subject)
            identity_ok = (not subject
                           or subject == _norm_key(record.get("identity"))
                           or subject == _norm_key(record.get("system")))
            if not identity_ok:
                problems.append({**tag, "code": "EVIDENCE_SUBJECT_MISMATCH",
                                 "reason": ("evidence read from "
                                            f"{record.get('identity') or record.get('system')!r} "
                                            f"cannot support a finding about "
                                            f"{finding.subject!r}")})
            if finding.vendor and record.get("vendor") and \
                    _norm_key(record["vendor"]) != _norm_key(finding.vendor):
                problems.append({**tag, "code": "EVIDENCE_PROVENANCE_MISMATCH",
                                 "reason": (f"the record's vendor is {record.get('vendor')!r}, "
                                            f"the finding claims {finding.vendor!r}")})
        state = finding.state.upper()
        facts = set(finding.facts)
        if state == "OBSERVED" and not facts & {"OBSERVED", "RUNTIME_OBSERVED"}:
            problems.append({"index": str(index), "code": "FACT_CLASS_DOES_NOT_SUPPORT_STATE",
                             "reason": ("an OBSERVED state rests on an observation; citing "
                                        "a configuration fact or an arbitrary id does not "
                                        "make one")})
        if state == "CONFIGURED" and "CONFIGURED" not in facts:
            problems.append({"index": str(index), "code": "FACT_CLASS_DOES_NOT_SUPPORT_STATE",
                             "reason": ("a CONFIGURED state rests on a configuration read, "
                                        "not on a fact class it does not carry")})
    return problems


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
