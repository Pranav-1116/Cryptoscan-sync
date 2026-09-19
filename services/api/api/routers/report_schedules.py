"""Scheduled compliance reports: schedules, runs, immutable snapshots (W55-56 7-8).

A cron entry (or an operator) calls ``POST /report-schedules/run-due``; every
due schedule renders its template against the latest completed scan of its
target, stores an immutable snapshot (hash — and PKI signature when
configured), and emails it when SMTP is configured.
"""

from __future__ import annotations

from datetime import datetime, timezone

import base64
import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor

router = APIRouter(tags=["report-schedules"])


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    template_id: str = Field(..., min_length=1)
    requirements: list[str] | None = None  # only used with template_id="custom"
    frequency: str = "quarterly"
    scan_target: str = Field(..., min_length=1, max_length=500)
    recipients: list[str] = Field(default_factory=list)


class ScheduleUpdate(BaseModel):
    active: bool


def _report_signing_secret() -> str:
    """HMAC secret for the deterministic report PDF. Prefers an explicit env
    value; otherwise derives deterministically from the platform SECRET_KEY so
    scheduled PDFs are stable and verifiable across restarts (no AI)."""
    secret = os.environ.get("REPORT_SIGNING_SECRET") or os.environ.get("GOVERNANCE_SIGNING_SECRET")
    if secret:
        return secret
    try:
        from governance.keys import signing_secret
        return signing_secret()
    except Exception:
        return os.environ.get("SECRET_KEY", "dev-report-secret-change-me")


def _attach_signed_pdf(report: dict) -> dict:
    """Render the dependency-free signed framework PDF and embed it (base64)
    plus its HMAC signature on the report body before snapshot persistence."""
    try:
        from reporting.compliance_pdf import render_signed_pdf, report_signature
        secret = _report_signing_secret()
        pdf = render_signed_pdf(report, signing_secret=secret)
        report["pdf_b64"] = base64.b64encode(pdf).decode()
        report["pdf_signature"] = report_signature(report, secret)
        report["pdf_media_type"] = "application/pdf"
    except Exception:
        # PDF rendering must never break report generation/snapshot
        report["pdf_b64"] = None
    return report


def _repo(db: Session):
    from db.repositories.report_schedule_repository import ReportScheduleRepository

    return ReportScheduleRepository(db)


def _validate_template(template_id: str, requirements: list[str] | None) -> None:
    from reporting.report_templates import template_ids

    if template_id not in template_ids():
        raise HTTPException(status_code=422, detail=f"unknown template '{template_id}'")
    if template_id == "custom" and not requirements:
        raise HTTPException(status_code=422, detail="template 'custom' requires requirements")


def _run_schedule(schedule, db: Session) -> dict:
    """Render + snapshot + email one schedule. Never raises for expected states."""
    from db.repositories.drift_repository import DriftRepository
    from db.repositories.evidence_repository import EvidenceRepository
    from db.repositories.scan_repository import ScanRepository
    from api.routers.intelligence import _rendered_report

    scan = ScanRepository(db).get_latest_completed_for_target(schedule.scan_target)
    if scan is None:
        return {
            "schedule": schedule.name,
            "status": "SKIPPED_NO_SCAN",
            "detail": f"no completed scan for target '{schedule.scan_target}'",
        }

    report = _rendered_report(
        scan.id,
        ScanRepository(db),
        EvidenceRepository(db),
        DriftRepository(db),
        schedule.template_id,
        ",".join(schedule.requirements or []),
    )
    _attach_signed_pdf(report)  # unify: scheduled reports emit signed framework PDFs
    repo = _repo(db)
    snapshot = repo.add_snapshot(
        schedule_id=schedule.id,
        schedule_name=schedule.name,
        scan_id=scan.id,
        template_id=schedule.template_id,
        report_hash=report.get("report_hash") or "",
        report=report,
        generated_at=datetime.now(timezone.utc),
        email_status="PENDING",
    )

    from reporting.distribution import email_report

    from api.config.settings import get_settings

    settings = get_settings()
    result = email_report(
        report=report,
        template_id=schedule.template_id,
        schedule_name=schedule.name,
        recipients=list(schedule.recipients or []),
        smtp_host=settings.SMTP_HOST,
        smtp_port=settings.SMTP_PORT,
        smtp_user=settings.SMTP_USER,
        smtp_password=settings.SMTP_PASSWORD,
    )
    repo.mark_emailed(snapshot, result["status"], result.get("detail", ""))
    repo.mark_run(schedule)
    return {
        "schedule": schedule.name,
        "status": "GENERATED",
        "snapshot_id": snapshot.id,
        "scan_id": scan.id,
        "report_hash": snapshot.report_hash,
        "email": result,
    }


@router.get("/report-schedules")
def list_schedules(
    active: bool | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = _repo(db).list_schedules(active=active)
    return {
        "schedules": [
            {
                "id": row.id,
                "name": row.name,
                "template_id": row.template_id,
                "frequency": row.frequency,
                "scan_target": row.scan_target,
                "recipients": row.recipients or [],
                "active": row.active,
                "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
                "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
            }
            for row in rows
        ]
    }


@router.post("/report-schedules", status_code=201)
def create_schedule(
    body: ScheduleCreate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    _validate_template(body.template_id, body.requirements)
    if body.frequency not in {"monthly", "quarterly"}:
        raise HTTPException(status_code=422, detail="frequency must be 'monthly' or 'quarterly'")
    repo = _repo(db)
    if repo.get_by_name(body.name) is not None:
        raise HTTPException(status_code=409, detail=f"schedule '{body.name}' already exists")
    row = repo.create(
        name=body.name,
        template_id=body.template_id,
        requirements=body.requirements,
        frequency=body.frequency,
        scan_target=body.scan_target,
        recipients=body.recipients,
        created_by=user,
    )
    return {"id": row.id, "name": row.name, "next_run_at": row.next_run_at.isoformat()}


@router.patch("/report-schedules/{schedule_id}")
def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    row = _repo(db).set_active(schedule_id, body.active)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"id": row.id, "active": row.active}


@router.delete("/report-schedules/{schedule_id}")
def delete_schedule(
    schedule_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    if not _repo(db).delete(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"deleted": schedule_id}


@router.get("/report-schedules/due")
def due_schedules(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = _repo(db).due()
    return {"due": [{"id": row.id, "name": row.name, "next_run_at": row.next_run_at.isoformat()} for row in rows]}


@router.post("/report-schedules/{schedule_id}/run")
def run_schedule(
    schedule_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    schedule = _repo(db).get(schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    result = _run_schedule(schedule, db)
    if result["status"] == "SKIPPED_NO_SCAN":
        db.rollback()
        raise HTTPException(status_code=409, detail=result["detail"])
    db.commit()
    return result


@router.post("/report-schedules/run-due")
def run_due_schedules(user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    """What cron calls: generate every due schedule, report each outcome honestly."""
    results = []
    for schedule in _repo(db).due():
        try:
            outcome = _run_schedule(schedule, db)
            db.commit()
        except Exception as exc:
            db.rollback()
            outcome = {
                "schedule": schedule.name,
                "status": "FAILED",
                "detail": f"{type(exc).__name__}: {exc}"[:300],
            }
        results.append(outcome)
    return {"ran": len(results), "results": results}


@router.get("/report-snapshots")
def list_snapshots(
    scan_id: str | None = None,
    schedule_id: str | None = None,
    page: int = 1,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows, total = _repo(db).list_snapshots(scan_id=scan_id, schedule_id=schedule_id, page=page)
    return {
        "snapshots": [
            {
                "id": row.id,
                "schedule_id": row.schedule_id,
                "schedule_name": row.schedule_name,
                "scan_id": row.scan_id,
                "template_id": row.template_id,
                "report_hash": row.report_hash,
                "generated_at": row.generated_at.isoformat() if row.generated_at else None,
                "email_status": row.email_status,
            }
            for row in rows
        ],
        "total": total,
    }


@router.get("/report-snapshots/{snapshot_id}")
def get_snapshot(
    snapshot_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The immutable audit artifact: the full report exactly as generated."""
    row = _repo(db).get_snapshot(snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    payload = dict(row.report or {})
    payload["snapshot"] = {
        "id": row.id,
        "schedule_name": row.schedule_name,
        "generated_at": row.generated_at.isoformat() if row.generated_at else None,
        "emailed_at": row.emailed_at.isoformat() if row.emailed_at else None,
        "email_status": row.email_status,
    }
    return payload


@router.get("/report-snapshots/{snapshot_id}/pdf")
def get_snapshot_pdf(
    snapshot_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Download the signed framework PDF captured with a scheduled snapshot."""
    row = _repo(db).get_snapshot(snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    report = row.report or {}
    pdf_b64 = report.get("pdf_b64")
    if not pdf_b64:
        # render on demand for snapshots created before PDF unification
        body = {k: v for k, v in report.items() if k not in ("pdf_b64", "pdf_signature", "snapshot")}
        try:
            from reporting.compliance_pdf import render_signed_pdf
            pdf = render_signed_pdf(body, signing_secret=_report_signing_secret())
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=409, detail=f"no PDF for this snapshot: {exc}")
    else:
        pdf = base64.b64decode(pdf_b64)
    fname = f"compliance-{row.template_id}-{snapshot_id[:8]}.pdf"
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"',
                             "X-Report-Signature": report.get("pdf_signature", "")})
