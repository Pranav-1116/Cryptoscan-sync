"""Field accuracy — a bank's own triage of CryptoScan output, published and pooled.

`POST /scans/{scan_id}/triage`   store a scored review (`scripts/bank_triage.py score --json` → `publish`) on the scan
`GET  /scans/{scan_id}/triage`   read it back
`GET  /accuracy/field`           pool every published triage into one field-measured precision / recall / F1,
                                 per language, next to the corpus benchmark's F1 — the number BANK-READINESS cites.

Legacy compatibility metrics are NOT approved sample accuracy. The newest
projection stays in Scan.statistics; every new submission is also an immutable
assurance revision. The approved/frozen/held-out workflow is /assurance/samples.
"""

from __future__ import annotations

from api.security.estate_history import history_context

import logging

logger = logging.getLogger(__name__)


import json
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from api.dependencies import get_current_user, get_db_session, require_roles
from db.models.scan import Scan
from shared_models.field_accuracy import FieldAccuracy, TriageResult, aggregate, score_workbook

router = APIRouter(tags=["accuracy"])
require_reviewer = require_roles("superadmin", "ciso", "security_analyst", "auditor")  # a review is a signed statement, not a dashboard view

_CORPUS_REPORT = Path(__file__).resolve().parents[4] / "docs" / "accuracy" / "report.json"


def corpus_f1() -> Optional[float]:
    try:
        rep = json.loads(_CORPUS_REPORT.read_text())
        return float(rep["overall"]["f1"])
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


@router.post("/scans/{scan_id}/triage", response_model=TriageResult, status_code=201)
def publish_triage(
    scan_id: str,
    body: dict[str, Any],
    user: str = Depends(require_reviewer),
    db: Session = Depends(get_db_session),
    ctx=Depends(history_context),
):
    """Attach a bank's review to a scan. Body is either a scored `TriageResult` or a raw reviewed workbook
    (`{"workbook": {...}, "reviewer": "..."}`), which is scored server-side with the same function."""
    scan = db.query(Scan).filter_by(id=scan_id, tenant_id=ctx.tenant_id).one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if "workbook" in body:
        result = score_workbook(body["workbook"], reviewer=body.get("reviewer"), notes=body.get("notes"))
    else:
        try:
            result = TriageResult.model_validate(body)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"not a TriageResult or workbook: {exc}") from exc
    if result.tp + result.fp + result.fn == 0:
        raise HTTPException(status_code=422, detail="nothing reviewed (no TP/FP/FN verdicts)")
    if not result.scanner_version:
        result.scanner_version = scan.scanner_version
    from api.assurance import store
    from db.models.user import User
    author = db.query(User).filter_by(username=user).one_or_none()
    if author is None:
        raise HTTPException(403, "Durable review author not found")
    stats = dict(scan.statistics or {})
    old = store.latest(db, ctx.tenant_id, "legacy_triage", scan.id, required=False)
    if old is None and stats.get("field_triage"):
        old = store.append(db, ctx.tenant_id, "legacy_triage", scan.id, 0,
            {"result": stats["field_triage"], "basis": "LEGACY_LATEST_IMPORTED_OLDER_HISTORY_UNKNOWN",
             "approved_customer_sample": False}, author.id, commit=False)
    store.append(db, ctx.tenant_id, "legacy_triage", scan.id, old.revision if old else 0,
        {"result": result.model_dump(mode="json"), "workbook": body.get("workbook"),
         "basis": "SERVER_SCORED_UNFROZEN_WORKBOOK" if "workbook" in body else "CALLER_SUBMITTED_METRICS",
         "approved_customer_sample": False, "global_accuracy_claim": False}, author.id, commit=False)
    stats["field_triage"] = {**result.model_dump(mode="json"), "published_by": user}
    scan.statistics = stats
    flag_modified(scan, "statistics")
    db.commit()
    return result


@router.get("/scans/{scan_id}/triage", response_model=TriageResult)
def get_triage(scan_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session), ctx=Depends(history_context)):
    scan = db.query(Scan).filter_by(id=scan_id, tenant_id=ctx.tenant_id).one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    triage = (scan.statistics or {}).get("field_triage")
    if not triage:
        raise HTTPException(status_code=404, detail="No triage published for this scan")
    return TriageResult.model_validate(triage)


@router.get("/accuracy/field", response_model=FieldAccuracy)
def field_accuracy(
    since: Optional[str] = Query(None, description="ISO date; only triages reviewed on/after it"),
    repo: Optional[str] = Query(None, description="restrict to one repo label"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx=Depends(history_context),
):
    """Pooled field precision / recall / F1 across every published triage, per language, against the corpus F1.
    `status = NO_FIELD_DATA` until the first bank publishes — never a made-up number."""
    results: list[TriageResult] = []
    for scan in db.query(Scan).filter(Scan.tenant_id == ctx.tenant_id, Scan.statistics.isnot(None)).all():
        triage = (scan.statistics or {}).get("field_triage")
        if not triage:
            continue
        t = TriageResult.model_validate(triage)
        if since and t.reviewed_at < since:
            continue
        if repo and t.repo != repo:
            continue
        results.append(t)
    return aggregate(results, corpus_f1=corpus_f1())
