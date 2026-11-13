"""PQC Migration Intelligence — waves, blockers, interoperability, verified progress.

This is the persisted plan state behind the PQC Migration Intelligence
workspace. The quantum-vulnerable inventory is projected from live estate reads
(TechBOM/CBOM) elsewhere; what lives here is the migration plan itself: which
waves exist, what blocks them, which peers interoperate, and which progress
claims have been verified against evidence.

Every state write goes through the canonical state machine register
(``shared_models.state_machines.can_transition``): the register is not a
diagram, it is the authority. A ``verified`` verdict requires an evidence
reference and is refused without one; nothing promotes a claim on its own.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_admin, require_auditor
from api.events.platform_events import emit_platform_event
from db.models.base import utcnow
from db.models.pqc_migration import (
    PqcInteropNote,
    PqcMigrationBlocker,
    PqcMigrationWave,
    PqcProgressRecord,
)
from db.tenancy import filtered_get
from shared_models.state_machines import can_transition

router = APIRouter(prefix="/pqc-migration", tags=["pqc-migration"])

MACHINES = {"wave": "pqc.wave_status", "blocker": "pqc.blocker_state",
            "progress": "pqc.progress_verification"}


def _require_verified_evidence(db: Session, references: list[str]) -> None:
    """Resolve every cited record and verify its complete committed scan.

    A reference string alone is a claim, not evidence. ORM tenant scoping
    keeps foreign records absent; tombstones and incomplete/broken scans
    cannot advance a progress or wave verdict.
    """
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan
    from evidence.verification.stored_scan import verify_stored_scan

    ids = list(dict.fromkeys(str(ref).strip() for ref in references if str(ref).strip()))
    if not ids:
        raise HTTPException(status_code=422,
                            detail="verified requires an evidence reference — a verdict without evidence is refused")
    if len(ids) > 40:
        raise HTTPException(status_code=413,
                            detail="at most 40 evidence references per progress verdict")
    rows = list(db.scalars(select(EvidenceRecord).where(
        EvidenceRecord.id.in_(ids), EvidenceRecord.deleted_at.is_(None))))
    if len(rows) != len(ids):
        raise HTTPException(status_code=409,
                            detail="referenced evidence is missing, withdrawn or outside the active tenant")
    for scan_id in {row.scan_id for row in rows}:
        scan = filtered_get(db, Scan, scan_id)
        scan_rows = list(db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.scan_id == scan_id).order_by(
            EvidenceRecord.chain_position).limit(10001)))
        if scan is None or len(scan_rows) > 10000 or not scan_rows:
            raise HTTPException(status_code=409,
                                detail="referenced evidence scan is unavailable or exceeds the verification budget")
        if any(row.tenant_id != scan.tenant_id for row in scan_rows):
            raise HTTPException(status_code=409,
                                detail="evidence and scan tenant ownership do not agree")
        if verify_stored_scan(scan, scan_rows)["result"] != "PASS":
            raise HTTPException(status_code=409,
                                detail="referenced evidence scan integrity is not verified")


# ----------------------------------------------------------------- schemas --
class WaveCreate(BaseModel):
    wave_key: str = Field(..., min_length=1, max_length=80)
    title: str = Field(..., min_length=1, max_length=200)
    scope_note: str = Field("", max_length=4000)
    planned_window: Optional[str] = Field(None, max_length=120)


class TransitionRequest(BaseModel):
    to: str = Field(..., min_length=1, max_length=20)
    note: Optional[str] = Field(None, max_length=500)
    evidence_ids: list[str] = Field(default_factory=list)


class ProgressCreate(BaseModel):
    claim: str = Field(..., min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list)


class BlockerCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    detail: str = Field("", max_length=4000)


class InteropCreate(BaseModel):
    peer_system: str = Field(..., min_length=1, max_length=200)
    protocol: str = Field("", max_length=120)
    note: str = Field("", max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------- response models --
class _Row(BaseModel):
    id: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class WaveOut(_Row):
    wave_key: str
    title: str
    scope_note: str = ""
    planned_window: Optional[str] = None
    status: str
    status_note: Optional[str] = None


class BlockerOut(_Row):
    wave_id: str
    title: str
    detail: str = ""
    state: str
    raised_by: str
    raised_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolution_note: Optional[str] = None


class InteropOut(_Row):
    wave_id: str
    peer_system: str
    protocol: str = ""
    note: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    recorded_by: str


class ProgressOut(_Row):
    wave_id: str
    claim: str
    evidence_ids: list[str] = Field(default_factory=list)
    recorded_by: str
    verification_status: str
    verified_by: Optional[str] = None
    verified_at: Optional[str] = None
    verification_note: Optional[str] = None
    claim_is_not_proof: bool = True


class SummaryOut(BaseModel):
    wave_count: int
    waves_verified: int
    waves_blocked: int
    blockers_open: int
    blockers_accepted: int
    progress_recorded: int
    progress_verified: int
    progress_refuted: int
    progress_stale: int
    honesty: str


class WorkspaceOut(BaseModel):
    waves: list[WaveOut]
    blockers: list[BlockerOut]
    interop: list[InteropOut]
    progress: list[ProgressOut]
    summary: SummaryOut


# ------------------------------------------------------------------- utils --
def _wave_or_404(db: Session, wave_key: str) -> PqcMigrationWave:
    row = db.scalars(
        select(PqcMigrationWave).where(PqcMigrationWave.wave_key == wave_key)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"wave {wave_key!r} not found")
    return row


def _row_or_404(db: Session, model, row_id: str):
    row = filtered_get(db, model, row_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"{model.__name__} {row_id!r} not found")
    return row


def _apply_transition(row, machine_id: str, to: str, note: Optional[str]) -> None:
    current = row.status if hasattr(row, "status") else row.state if hasattr(row, "state") else row.verification_status
    if to == current:
        raise HTTPException(status_code=409,
                            detail=f"already {current!r}; self-loops are not transitions")
    if not can_transition(machine_id, current, to):
        raise HTTPException(status_code=409,
                            detail=f"{machine_id}: {current!r} -> {to!r} is not a transition the code makes")
    if hasattr(row, "status"):
        row.status, row.status_note = to, note
    elif hasattr(row, "state"):
        row.state = to
    else:
        row.verification_status = to


def _progress_out(row: PqcProgressRecord) -> dict:
    out = row.to_dict()
    out["claim_is_not_proof"] = True
    return out


def _summary(waves, blockers, progress) -> dict:
    open_blockers = [b for b in blockers if b.state == "open"]
    verified = [p for p in progress if p.verification_status == "verified"]
    return {
        "wave_count": len(waves),
        "waves_verified": sum(1 for w in waves if w.status == "verified"),
        "waves_blocked": sum(1 for w in waves if w.status == "blocked"),
        "blockers_open": len(open_blockers),
        "blockers_accepted": sum(1 for b in blockers if b.state == "accepted"),
        "progress_recorded": len(progress),
        "progress_verified": len(verified),
        "progress_refuted": sum(1 for p in progress if p.verification_status == "refuted"),
        "progress_stale": sum(1 for p in progress if p.verification_status == "stale"),
        "honesty": (
            "verified is written only by an explicit verification action with an "
            "evidence reference; a recorded claim is not progress proven"
        ),
    }


# ----------------------------------------------------------------- routes ---
@router.get("/workspace", response_model=WorkspaceOut)
def pqc_migration_workspace(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The whole plan state: waves, blockers, interoperability, progress."""
    waves = list(db.scalars(select(PqcMigrationWave).order_by(PqcMigrationWave.created_at)))
    blockers = list(db.scalars(select(PqcMigrationBlocker).order_by(PqcMigrationBlocker.created_at)))
    interop = list(db.scalars(select(PqcInteropNote).order_by(PqcInteropNote.created_at)))
    progress = list(db.scalars(select(PqcProgressRecord).order_by(PqcProgressRecord.created_at)))
    return {
        "waves": [w.to_dict() for w in waves],
        "blockers": [b.to_dict() for b in blockers],
        "interop": [n.to_dict() for n in interop],
        "progress": [_progress_out(p) for p in progress],
        "summary": _summary(waves, blockers, progress),
    }


@router.post("/waves", response_model=WaveOut)
def create_wave(
    body: WaveCreate,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Define a migration wave (plan object — never estate state)."""
    if db.scalars(select(PqcMigrationWave).where(
            PqcMigrationWave.wave_key == body.wave_key)).first() is not None:
        raise HTTPException(status_code=409, detail=f"wave {body.wave_key!r} already exists")
    row = PqcMigrationWave(
        wave_key=body.wave_key, title=body.title,
        scope_note=body.scope_note, planned_window=body.planned_window,
        status="planned",
    )
    db.add(row)
    db.commit()
    emit_platform_event("pqc.migration.wave_created",
                        f"wave {row.wave_key} defined by {user}",
                        {"wave_key": row.wave_key, "title": row.title},
                        target_name="pqc_migration")
    return row.to_dict()


@router.post("/waves/{wave_key}/transition", response_model=WaveOut)
def transition_wave(
    wave_key: str,
    body: TransitionRequest,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Move a wave along the register's transition graph. No other path exists."""
    row = _wave_or_404(db, wave_key)
    if body.to != row.status and not can_transition(MACHINES["wave"], row.status, body.to):
        raise HTTPException(status_code=409,
                            detail=f"{MACHINES['wave']}: {row.status!r} -> {body.to!r} is not a transition the code makes")
    if body.to == "verified":
        claims = list(db.scalars(select(PqcProgressRecord).where(
            PqcProgressRecord.wave_id == row.id)))
        unverified = [p for p in claims if p.verification_status != "verified"]
        if not claims or unverified:
            raise HTTPException(
                status_code=409,
                detail="a wave is verified only over verified progress records — "
                       f"{len(unverified)} of {len(claims)} claims are not verified",
            )
        # An earlier verdict is not durable proof if its evidence was later
        # tombstoned or corrupted. Recheck at the wave transition boundary.
        for claim in claims:
            _require_verified_evidence(db, list(claim.evidence_ids or []))
    _apply_transition(row, MACHINES["wave"], body.to, body.note)
    db.commit()
    emit_platform_event("pqc.migration.wave_transition",
                        f"wave {row.wave_key} -> {row.status} by {user}",
                        {"wave_key": row.wave_key, "to": row.status, "note": body.note},
                        target_name="pqc_migration")
    return row.to_dict()


@router.post("/waves/{wave_key}/progress", response_model=ProgressOut)
def record_progress(
    wave_key: str,
    body: ProgressCreate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Record a progress claim. Asserted — never drawn as progress proven."""
    wave = _wave_or_404(db, wave_key)
    row = PqcProgressRecord(
        wave_id=wave.id, claim=body.claim,
        evidence_ids=list(body.evidence_ids), recorded_by=user,
        verification_status="recorded",
    )
    db.add(row)
    db.commit()
    emit_platform_event("pqc.migration.progress_recorded",
                        f"progress claim recorded on {wave.wave_key} by {user}",
                        {"wave_key": wave.wave_key, "progress_id": row.id,
                         "evidence_ids": row.evidence_ids},
                        target_name="pqc_migration")
    return _progress_out(row)


@router.post("/progress/{record_id}/transition", response_model=ProgressOut)
def transition_progress(
    record_id: str,
    body: TransitionRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Write a verification verdict. verified requires an evidence reference."""
    row = _row_or_404(db, PqcProgressRecord, record_id)
    if body.to == "verified":
        verified_ids = list(dict.fromkeys([*(row.evidence_ids or []), *body.evidence_ids]))
        _require_verified_evidence(db, verified_ids)
        row.evidence_ids = verified_ids
        row.verified_by, row.verified_at = user, utcnow()
    _apply_transition(row, MACHINES["progress"], body.to, body.note)
    row.verification_note = body.note
    db.commit()
    emit_platform_event("pqc.migration.progress_verdict",
                        f"progress {row.id} -> {row.verification_status} by {user}",
                        {"progress_id": row.id, "to": row.verification_status,
                         "note": body.note, "evidence_ids": row.evidence_ids},
                        target_name="pqc_migration")
    return _progress_out(row)


@router.post("/waves/{wave_key}/blockers", response_model=BlockerOut)
def raise_blocker(
    wave_key: str,
    body: BlockerCreate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Raise a blocker on a wave. Open by construction — never auto-resolved."""
    wave = _wave_or_404(db, wave_key)
    row = PqcMigrationBlocker(
        wave_id=wave.id, title=body.title, detail=body.detail,
        state="open", raised_by=user,
    )
    db.add(row)
    db.commit()
    emit_platform_event("pqc.migration.blocker_raised",
                        f"blocker raised on {wave.wave_key} by {user}",
                        {"wave_key": wave.wave_key, "blocker_id": row.id,
                         "title": row.title},
                        target_name="pqc_migration")
    return row.to_dict()


@router.post("/blockers/{blocker_id}/transition", response_model=BlockerOut)
def transition_blocker(
    blocker_id: str,
    body: TransitionRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Resolve (or reopen) a blocker. accepted is a recorded decision, not a close."""
    row = _row_or_404(db, PqcMigrationBlocker, blocker_id)
    _apply_transition(row, MACHINES["blocker"], body.to, body.note)
    if body.to in ("cleared", "accepted"):
        row.resolved_by, row.resolved_at = user, utcnow()
    else:
        row.resolved_by, row.resolved_at = None, None
    row.resolution_note = body.note
    db.commit()
    emit_platform_event("pqc.migration.blocker_transition",
                        f"blocker {row.id} -> {row.state} by {user}",
                        {"blocker_id": row.id, "to": row.state, "note": body.note},
                        target_name="pqc_migration")
    return row.to_dict()


@router.post("/waves/{wave_key}/interop", response_model=InteropOut)
def record_interop(
    wave_key: str,
    body: InteropCreate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Record an interoperability observation against a peer system."""
    wave = _wave_or_404(db, wave_key)
    row = PqcInteropNote(
        wave_id=wave.id, peer_system=body.peer_system,
        protocol=body.protocol, note=body.note,
        evidence_ids=list(body.evidence_ids), recorded_by=user,
    )
    db.add(row)
    db.commit()
    emit_platform_event("pqc.migration.interop_recorded",
                        f"interop note for {wave.wave_key} / {row.peer_system} by {user}",
                        {"wave_key": wave.wave_key, "interop_id": row.id,
                         "peer_system": row.peer_system},
                        target_name="pqc_migration")
    return row.to_dict()
