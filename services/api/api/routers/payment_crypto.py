"""Payment cryptography API: HSM key inventory, ceremonies, audit ingestion, policy.

Everything a PCI/TR-39 program needs in one place — the key hierarchy, its
ceremony provenance, the HSM audit trail, and the PAY-xxx findings. Write
operations require the auditor role: this data feeds compliance evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, require_auditor, get_db_session
from db.repositories.payment_crypto_repository import PaymentCryptoRepository
from api.idempotency import ConflictError, idempotent_write, record
from payment_crypto.auditlog import HsmAuditParser
from payment_crypto.keyblocks import parse_tr31_header
from payment_crypto.policy import PaymentPolicyEngine
from payment_crypto.forecast import ExpiryForecaster
from payment_crypto.usage import TransactionCorrelator, UsageAnalyzer

router = APIRouter(prefix="/payment-crypto", tags=["payment-crypto"])

KEY_STATES = {"PRE_ACTIVATION", "ACTIVE", "SUSPENDED", "COMPROMISED", "DESTROYED", "EXPIRED"}


class KeyUpsert(BaseModel):
    key_id: str
    name: Optional[str] = None
    hsm_device: Optional[str] = None
    key_usage: Optional[str] = None
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    state: str = "ACTIVE"
    enabled: bool = True
    key_block: Optional[str] = None       # raw TR-31 block — parsed, never stored whole
    activation_at: Optional[str] = None
    expiry_at: Optional[str] = None
    custodian_count: Optional[int] = None
    notes: Optional[str] = None


class CeremonyUpsert(BaseModel):
    ceremony_id: str
    key_id: Optional[str] = None
    held_at: Optional[str] = None
    custodians: list[str] = []
    m_of_n: Optional[str] = None
    dual_control: bool = True
    location: Optional[str] = None
    documented: bool = True
    notes: Optional[str] = None


class HsmEventIngest(BaseModel):
    format: str = "auto"                 # auto | jsonl | syslog | csv
    text: str
    columns: Optional[dict[str, int]] = None  # csv only: ts/device/event/key_id/actor/severity -> index


class TransactionVolumeIn(BaseModel):
    day: str                            # ISO date
    count: int
    source: Optional[str] = None


class TransactionBulkIn(BaseModel):
    series: dict[str, int]              # {"2026-08-30": 10000000, ...}
    source: Optional[str] = None


class FindingStatus(BaseModel):
    status: str                          # OPEN | ACCEPTED | RESOLVED
    resolved_by: Optional[str] = None


def _repo(db: Session) -> PaymentCryptoRepository:
    return PaymentCryptoRepository(db)


def _to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"invalid ISO datetime: {value}")



def _serialize_key(row) -> dict:
    return {
        "key_id": row.key_id,
        "name": row.name,
        "hsm_device": row.hsm_device,
        "key_usage": row.key_usage,
        "algorithm": row.algorithm,
        "key_size": row.key_size,
        "state": row.state,
        "enabled": row.enabled,
        "key_block_version": row.key_block_version,
        "key_block_error": row.key_block_error,
        "activation_at": row.activation_at.isoformat() if row.activation_at else None,
        "expiry_at": row.expiry_at.isoformat() if row.expiry_at else None,
        "custodian_count": row.custodian_count,
        "source": row.source,
        "notes": row.notes,
    }


# -------------------------------------------------------------------- keys

@router.get("/keys")
def list_keys(state: Optional[str] = None, hsm_device: Optional[str] = None,
              user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    return {"keys": [_serialize_key(row) for row in _repo(db).list_keys(state=state, hsm_device=hsm_device)]}


@router.post("/keys")
def upsert_key(body: KeyUpsert, user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    if body.state.upper() not in KEY_STATES:
        raise HTTPException(status_code=422, detail=f"state must be one of {sorted(KEY_STATES)}")
    payload = body.model_dump(exclude={"key_block", "activation_at", "expiry_at"})
    payload["activation_at"] = _to_dt(body.activation_at)
    payload["expiry_at"] = _to_dt(body.expiry_at)
    if body.key_block:
        header = parse_tr31_header(body.key_block)
        if not header.valid:
            payload["key_block_error"] = "; ".join(header.errors)
        else:
            payload["key_block_version"] = header.version_id
            payload["source"] = "TR31"
            payload.setdefault("algorithm", None)
            if not payload.get("key_usage") and not header.key_usage.startswith("UNKNOWN"):
                payload["key_usage"] = header.key_usage
            if not payload.get("algorithm") and not header.algorithm.startswith("UNKNOWN"):
                payload["algorithm"] = header.algorithm
    payload["state"] = body.state.upper()
    try:
        row = _repo(db).upsert_key(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    db.commit()
    return _serialize_key(row)


@router.delete("/keys/{key_id}")
def delete_key(key_id: str, user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    if not _repo(db).delete_key(key_id):
        raise HTTPException(status_code=404, detail="Key not found")
    db.commit()
    return {"deleted": key_id}


# --------------------------------------------------------------- ceremonies

def _serialize_ceremony(row) -> dict:
    return {
        "ceremony_id": row.ceremony_id, "key_id": row.key_id,
        "held_at": row.held_at.isoformat() if row.held_at else None,
        "custodians": row.custodians or [], "m_of_n": row.m_of_n,
        "dual_control": row.dual_control, "location": row.location,
        "documented": row.documented, "status": row.status or "HELD",
    }


@router.get("/ceremonies")
def list_ceremonies(key_id: Optional[str] = None, upcoming: bool = False,
                    user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = _repo(db).list_ceremonies(key_id=key_id, upcoming_only=upcoming)
    return {"ceremonies": [_serialize_ceremony(row) for row in rows]}


class CeremonyUpdate(BaseModel):
    held_at: Optional[str] = None
    custodians: Optional[list[str]] = None
    m_of_n: Optional[str] = None
    dual_control: Optional[bool] = None
    location: Optional[str] = None
    status: Optional[str] = None   # PLANNED | HELD | ABANDONED


@router.post("/ceremonies")
def upsert_ceremony(body: CeremonyUpsert, user: str = Depends(require_auditor),
                    db: Session = Depends(get_db_session)):
    payload = body.model_dump(exclude={"held_at"})
    payload["held_at"] = _to_dt(body.held_at)
    try:
        row = _repo(db).upsert_ceremony(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    db.commit()
    return _serialize_ceremony(row)


@router.patch("/ceremonies/{ceremony_id}")
def update_ceremony(ceremony_id: str, body: CeremonyUpdate,
                    user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    """Schedule workflow: move date, custodians, or status (PLANNED -> HELD/ABANDONED)."""
    if body.status is not None and body.status not in {"PLANNED", "HELD", "ABANDONED"}:
        raise HTTPException(status_code=422, detail="status must be PLANNED, HELD or ABANDONED")
    updates = body.model_dump(exclude={"held_at"})
    if body.held_at is not None:
        updates["held_at"] = _to_dt(body.held_at)
    row = _repo(db).update_ceremony(ceremony_id, updates)
    if row is None:
        raise HTTPException(status_code=404, detail="Ceremony not found")
    db.commit()
    return _serialize_ceremony(row)


# -------------------------------------------------------------- hsm events

@router.post("/hsm-events")
def ingest_hsm_events(body: HsmEventIngest, user: str = Depends(require_auditor),
                      db: Session = Depends(get_db_session)):
    if not body.text.strip():
        raise HTTPException(status_code=422, detail="text is required (HSM audit lines)")
    parser = HsmAuditParser()
    fmt = body.format.lower()
    if fmt == "jsonl":
        result = parser.parse_jsonl(body.text)
    elif fmt == "syslog":
        result = parser.parse_syslog(body.text)
    elif fmt == "csv":
        if not body.columns:
            raise HTTPException(status_code=422, detail="csv requires columns map (ts, device, event, ...)")
        result = parser.parse_csv(body.text, body.columns)
    elif fmt == "auto":
        result = parser.autodetect(body.text)
    else:
        raise HTTPException(status_code=422, detail="format must be auto, jsonl, syslog or csv")
    _repo(db).add_events([record.to_dict() for record in result.records])
    db.commit()
    return result.counts() | {"rejected_samples": result.rejected[:5]}


@router.get("/hsm-events")
def list_hsm_events(days: int = 30, device: Optional[str] = None,
                    user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = _repo(db).recent_events(days=min(max(days, 1), 365), device=device)
    return {"events": [{
        "occurred_at": row.occurred_at.isoformat(), "device": row.device,
        "event_type": row.event_type, "key_id": row.key_id, "actor": row.actor,
        "severity": row.severity, "detail": row.detail,
    } for row in rows]}


# ------------------------------------------------------- usage & transactions

@router.post("/transactions")
def record_transactions(body: TransactionVolumeIn, user: str = Depends(require_auditor),
                        db: Session = Depends(get_db_session)):
    from datetime import date as _date

    try:
        day = _date.fromisoformat(body.day)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"day must be an ISO date (YYYY-MM-DD), got '{body.day}'")
    if body.count < 0:
        raise HTTPException(status_code=422, detail="count must be >= 0")
    row = _repo(db).upsert_transaction_volume(day, body.count, source=body.source or "manual")
    db.commit()
    return {"day": row.day.isoformat(), "transaction_count": row.transaction_count}


@router.post("/transactions/bulk")
def record_transactions_bulk(body: TransactionBulkIn, user: str = Depends(require_auditor),
                             db: Session = Depends(get_db_session), request: Request = None):
    """Upsert a daily-transaction series (data-warehouse push, one call per day/week).

    Bulk partial success (gap analysis §B): every day key returns its own
    outcome — ACCEPTED (written), REJECTED (bad item, with the reason) or
    SKIPPED (value unchanged) — and totals are computed from those items.
    One bad key never rejects the rest of the batch. Writes are idempotent
    via ``Idempotency-Key``: a replay is served the stored response and
    marked ``idempotent_replay``; the same key with a different body is a
    CONFLICT, never a silent wrong answer.
    """
    from datetime import date as _date

    from db.models.payment_crypto import PaymentTransactionVolume
    from shared_models.bulk_result import (ACCEPTED, REJECTED, SKIPPED,
                                           bulk_result, item)

    if not body.series:
        raise HTTPException(status_code=422, detail="series must contain at least one day")

    scope = request.scope if request is not None else {}
    idem_key = None
    if request is not None:
        idem_key = request.headers.get("Idempotency-Key") or None
    try:
        replay = idempotent_write(scope, "/api/v1/payment-crypto/transactions/bulk",
                                  idem_key, body.model_dump())
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if replay is not None:
        status, stored = replay
        replayed = dict(stored)
        replayed["idempotent_replay"] = True
        replayed["items"] = [
            dict(row, outcome=SKIPPED, reason=f"idempotent replay of {idem_key}")
            for row in stored.get("items", [])
        ]
        replayed["totals"] = {"accepted": 0, "rejected": 0,
                              "skipped": len(replayed["items"]),
                              "total": len(replayed["items"])}
        replayed["complete"] = False
        replayed["partial"] = False
        return replayed

    repo = _repo(db)
    items = []
    accepted_days = []
    for day_text, count in body.series.items():
        try:
            day = _date.fromisoformat(str(day_text)[:10])
        except ValueError:
            items.append(item(str(day_text), REJECTED, f"invalid ISO date key '{day_text}'"))
            continue
        if count is None or count < 0:
            items.append(item(day.isoformat(), REJECTED, f"count for {day_text} must be >= 0"))
            continue
        current = db.query(PaymentTransactionVolume).filter(
            PaymentTransactionVolume.day == day).one_or_none()
        if current is not None and int(current.transaction_count) == int(count):
            items.append(item(day.isoformat(), SKIPPED, "value unchanged"))
            continue
        repo.upsert_transaction_volume(day, int(count), source=body.source or "bulk-push")
        items.append(item(day.isoformat(), ACCEPTED, "written"))
        accepted_days.append(day.isoformat())
    db.commit()
    outcome = bulk_result(items)
    response = {
        "days_ingested": len(accepted_days),
        "days": sorted(accepted_days),
        "idempotent_replay": False,
        **outcome,
    }
    record(scope, "/api/v1/payment-crypto/transactions/bulk", idem_key,
           body.model_dump(), 200, response)
    return response


@router.get("/usage")
def usage(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = _repo(db)
    report = UsageAnalyzer().analyze(
        [_serialize_key(row) for row in repo.list_keys()],
        [{"occurred_at": row.occurred_at.isoformat(), "device": row.device,
          "event_type": row.event_type, "key_id": row.key_id, "detail": row.detail or {}}
         for row in repo.recent_events(days=90)],
    )
    report["correlation"] = TransactionCorrelator().evaluate(
        repo.transaction_series(days=60), report.get("usage_by_day") or {}
    )
    return report


# ---------------------------------------------------------------- findings

@router.post("/evaluate")
def evaluate(user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    repo = _repo(db)
    findings = PaymentPolicyEngine().evaluate(
        [_serialize_key(row) for row in repo.list_keys()],
        ceremonies=[{
            "key_id": row.key_id,
            "held_at": row.held_at.isoformat() if row.held_at else None,
            "custodians": row.custodians or [], "dual_control": row.dual_control,
            "status": row.status or "HELD", "ceremony_id": row.ceremony_id,
        } for row in repo.list_ceremonies()],
        events=[{
            "occurred_at": row.occurred_at.isoformat(), "device": row.device,
            "event_type": row.event_type, "key_id": row.key_id,
            "detail": row.detail or {},
        } for row in repo.recent_events(days=30)],
    )
    usage_report = UsageAnalyzer().analyze(
        [_serialize_key(row) for row in repo.list_keys()],
        [{"occurred_at": row.occurred_at.isoformat(), "device": row.device,
          "event_type": row.event_type, "key_id": row.key_id, "detail": row.detail or {}}
         for row in repo.recent_events(days=90)],
    )
    correlation = TransactionCorrelator().evaluate(
        repo.transaction_series(days=60), usage_report.get("usage_by_day") or {}
    )
    forecast_report = ExpiryForecaster().forecast(
        [_serialize_key(row) for row in repo.list_keys()], None,
        ceremonies=[{"key_id": row.key_id, "status": row.status or "HELD",
                     "held_at": row.held_at.isoformat() if row.held_at else None}
                    for row in repo.list_ceremonies()],
    )
    usage_findings = (
        list(usage_report.get("findings") or [])
        + list(correlation.get("findings") or [])
        + list(forecast_report.get("findings") or [])
    )
    all_findings = [finding.to_dict() for finding in findings] + usage_findings
    rows = repo.replace_findings(all_findings)
    db.commit()
    return {
        "evaluated": True,
        "findings": [{
            "id": row.id, "rule_id": row.rule_id, "key_id": row.key_id,
            "severity": row.severity, "blocking": row.blocking, "message": row.message,
            "status": row.status,
        } for row in rows],
        "counts": {
            "total": len(rows),
            "blocking": sum(1 for row in rows if row.blocking),
            "severity_4_plus": sum(1 for row in rows if row.severity >= 4),
        },
    }


@router.get("/findings")
def list_findings(status: Optional[str] = None,
                  user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if status and status not in {"OPEN", "ACCEPTED", "RESOLVED"}:
        raise HTTPException(status_code=422, detail="status must be OPEN, ACCEPTED or RESOLVED")
    rows = _repo(db).list_findings(status=status)
    return {"findings": [{
        "id": row.id, "rule_id": row.rule_id, "key_id": row.key_id, "severity": row.severity,
        "blocking": row.blocking, "message": row.message, "status": row.status,
        "evidence": row.evidence, "evaluated_at": row.evaluated_at.isoformat() if row.evaluated_at else None,
    } for row in rows]}


@router.get("/forecast")
def forecast(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Rotation calendar: payment keys + TLS certificates expiring on one timeline."""
    repo = _repo(db)
    keys = [_serialize_key(row) for row in repo.list_keys()]
    certificates = []
    try:
        from db.models.certificate import Certificate

        for row in db.query(Certificate).all():
            certificates.append({
                "subject": row.subject, "issuer": row.issuer,
                "not_after": row.not_after.isoformat() if row.not_after else None,
                "public_key_algorithm": row.public_key_algorithm,
                "fingerprint": (row.fingerprint_sha256 or "")[:12],
                "renewal_status": row.renewal_status or "NONE",
            })
    except Exception:
        certificates = []  # certificate inventory empty/unavailable — keys still forecast
    return ExpiryForecaster().forecast(
        keys, certificates,
        ceremonies=[{"key_id": row.key_id,
                     "held_at": row.held_at.isoformat() if row.held_at else None}
                    for row in repo.list_ceremonies()],
    )


@router.post("/findings/{finding_id}/status")
def set_finding_status(finding_id: str, body: FindingStatus,
                       user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    try:
        row = _repo(db).set_finding_status(finding_id, body.status, resolved_by=body.resolved_by or user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.commit()
    return {"id": row.id, "status": row.status}


# ----------------------------------------------------------------- summary

@router.get("/summary")
def summary(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = _repo(db)
    keys = repo.list_keys()
    by_state: dict[str, int] = {}
    by_usage: dict[str, int] = {}
    weak = 0
    for key in keys:
        by_state[key.state] = by_state.get(key.state, 0) + 1
        by_usage[key.key_usage or "UNKNOWN"] = by_usage.get(key.key_usage or "UNKNOWN", 0) + 1
        if key.algorithm and key.algorithm.upper() in {"DES", "SINGLE_DES", "TRIPLE_DES", "2KEY_TRIPLE_DES"} and key.state == "ACTIVE":
            weak += 1
    open_findings = repo.list_findings(status="OPEN")
    return {
        "keys_total": len(keys),
        "keys_by_state": by_state,
        "keys_by_usage": by_usage,
        "active_weak_algorithm_keys": weak,
        "open_findings": len(open_findings),
        "blocking_findings": sum(1 for row in open_findings if row.blocking),
        "findings_severity_4_plus": sum(1 for row in open_findings if row.severity >= 4),
    }


# ----------------- ISO 9564 / ISO 8583 / EMV standards analysis ----------------- #
# These read *declarations* — the PIN-block format a system says it uses, the
# data elements a link carries, the CVN an issuer application runs — and report
# what each implies for PCI PIN and for the TDES→AES migration. None of them
# accepts PIN blocks, PANs or key material; the analysers refuse input that
# looks like one (see payment_crypto.pinblocks / .emv).

class PinBlockEstateRequest(BaseModel):
    """Each: {system, format, online?, key_algorithm?}"""
    declarations: list[dict]


class Iso8583LinksRequest(BaseModel):
    """Each: {link, fields: [2, 52, 64], mac_algorithm?, pin_block_format?}"""
    links: list[dict]


class EmvPortfolioRequest(BaseModel):
    """Each: {application, cvn, key_algorithm?, key_bits?}"""
    applications: list[dict]


@router.post("/pin-blocks/analyse")
def analyse_pin_blocks(body: PinBlockEstateRequest,
                       user: str = Depends(require_auditor),
                       db: Session = Depends(get_db_session)):
    """ISO 9564 PIN-block formats across the estate, with the TDES backlog."""
    from payment_crypto.pinblocks import summarise_estate

    if not body.declarations:
        raise HTTPException(status_code=400, detail="declarations must not be empty")
    return summarise_estate(body.declarations)


@router.post("/iso8583/analyse")
def analyse_iso8583(body: Iso8583LinksRequest,
                    user: str = Depends(require_auditor),
                    db: Session = Depends(get_db_session)):
    """Crypto carried by each ISO 8583 link, from its declared data elements."""
    from payment_crypto.iso8583 import summarise_links

    if not body.links:
        raise HTTPException(status_code=400, detail="links must not be empty")
    return summarise_links(body.links)


@router.post("/emv/analyse")
def analyse_emv(body: EmvPortfolioRequest,
                user: str = Depends(require_auditor),
                db: Session = Depends(get_db_session)):
    """EMV cryptogram configuration per issuer application (CVN-driven)."""
    from payment_crypto.emv import summarise_portfolio

    if not body.applications:
        raise HTTPException(status_code=400, detail="applications must not be empty")
    return summarise_portfolio(body.applications)
