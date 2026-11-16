"""Findings endpoints."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from functools import lru_cache
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import (
    TenantContext,
    get_current_user,
    get_db_session,
    get_evidence_repository,
    require_auditor,
)
from api.security.estate_history import history_context
from api.schemas.finding_schemas import (
    FindingListResponse,
    FindingProvenanceBundle,
    FindingResponse,
    ProvenanceAsset,
    ProvenanceCollector,
    ProvenanceDetection,
    ProvenanceEvidenceReference,
    ProvenanceIntegrity,
    ProvenanceObserved,
    ProvenanceSourceAndMethod,
    ProvenanceTruth,
)
from api.security.evidence_projection import project_finding
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.repositories.evidence_repository import EvidenceRepository
from db.tenancy import filtered_get

router = APIRouter(tags=["findings"])
logger = logging.getLogger(__name__)


def _to_response(row, include_raw: bool = False) -> FindingResponse:
    finding_data, redacted = project_finding(row.finding_data) if include_raw else (None, False)
    return FindingResponse(
        evidence_id=row.id,
        scan_id=row.scan_id,
        algorithm=row.algorithm,
        key_size=row.key_size,
        mode=row.mode,
        padding=row.padding,
        purpose=row.purpose,
        confidence=row.confidence,
        is_hardcoded_key=row.is_hardcoded_key,
        file_path=row.file_path,
        line_number=row.line_number,
        class_name=row.class_name,
        method_name=row.method_name,
        compliance_status=row.compliance_status,
        content_hash=row.content_hash,
        chain_hash=row.chain_hash,
        normalized_crypto=row.normalized_crypto,
        policy_evaluation=row.policy_evaluation,
        finding_data=finding_data,
        redacted_projection=redacted,
        created_at=getattr(row, "created_at", None),
        updated_at=getattr(row, "updated_at", None),
        deleted_at=getattr(row, "deleted_at", None),
        deleted_by=getattr(row, "deleted_by", None),
        delete_reason=getattr(row, "delete_reason", None),
    )


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
def list_findings(
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    algorithm: str | None = None,
    compliance_status: str | None = None,
    hardcoded_only: bool = False,
    user: str = Depends(get_current_user),
    repo: EvidenceRepository = Depends(get_evidence_repository),
):
    rows, total = repo.list_for_scan(
        scan_id,
        algorithm=algorithm,
        compliance_status=compliance_status,
        hardcoded_only=hardcoded_only,
        page=page,
        page_size=page_size,
    )
    return FindingListResponse(
        findings=[_to_response(r) for r in rows],
        total_count=total,
        page=page,
        page_size=page_size,
    )


@router.get("/findings", response_model=FindingListResponse)
def list_all_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    algorithm: str | None = None,
    compliance_status: str | None = None,
    scan_id: str | None = Query(None, description="Restrict to a single scan"),
    q: str | None = Query(None, description="Whole-store term search over "
                                            "algorithm, file path, content "
                                            "hash and evidence id"),
    user: str = Depends(get_current_user),
    repo: EvidenceRepository = Depends(get_evidence_repository),
    ctx: TenantContext = Depends(history_context),
):
    from api.cache_policy import policy_read

    # Risk findings are AUTHORITATIVE per the cache policy: fresh from the
    # store on every call, never cached — a cached finding is a decision
    # made on evidence nobody re-checked.
    rows, total = policy_read(
        "risk_findings",
        f"findings:{ctx.tenant_id}:{scan_id}:{algorithm}:{compliance_status}:{q}:{page}:{page_size}",
        lambda: repo.list_all(
            algorithm=algorithm,
            compliance_status=compliance_status,
            scan_id=scan_id,
            q=q,
            owner=ctx.tenant_id,
            page=page,
            page_size=page_size,
        ),
    )
    return FindingListResponse(
        findings=[_to_response(r) for r in rows],
        total_count=total,
        page=page,
        page_size=page_size,
    )


# ------------------------------------------------------------------------- #
# Provenance bundle — the hash-integrity-versus-truth distinction, preserved #
# as data. Every question the finding must answer: who observed it, on what, #
# when, from where, by which method, under whose authorization, with which   #
# parser and rule version, what was found — and what verification does and   #
# does NOT prove.                                                            #
# ------------------------------------------------------------------------- #

def _chain_link_verified(row) -> bool:
    """Recompute the chain link exactly as evidence/hashing/chain_hasher.py
    committed it: sha256(content_hash + previous_hash); the first entry
    chains from the scan id. True only when the stored hash matches — a
    mismatch is reported as False, never smoothed over."""
    import hashlib

    previous = row.previous_hash if row.previous_hash else (row.scan_id or "")
    expected = hashlib.sha256(
        f"{row.content_hash}{previous}".encode("utf-8")).hexdigest()
    return expected == row.chain_hash


@router.get("/findings/{evidence_id}/provenance",
            response_model=FindingProvenanceBundle)
def finding_provenance(
    evidence_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = filtered_get(db, EvidenceRecord, evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such finding")
    scan = filtered_get(db, Scan, row.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="finding's scan is gone")

    provenance_meta = row.provenance or {}
    scanner_ids = list(provenance_meta.get("scanner_ids") or [scan.scanner_id])

    # Collection authorization: the collection NAMES its authority
    # (scans.collector_authority_id + revision, stamped at collection
    # time). The stamp is validated, never guessed from whatever
    # authority happens to exist later: an authority approved after the
    # scan cannot bless a collection it never covered.
    from db.models.collector_authority import CollectorAuthority

    authority = None
    if getattr(scan, "collector_authority_id", None):
        authority = filtered_get(db, CollectorAuthority, scan.collector_authority_id)
    if authority is not None and \
            int(authority.revision or 0) == int(scan.collector_authority_revision or 0):
        authorization = {
            "status": "AUTHORIZED",
            "basis": "collection_recorded",
            "authority_id": authority.id,
            "authority_revision": int(authority.revision or 0),
            "permission": authority.permission,
            "target_kind": authority.target_kind,
            "approved_by": authority.approved_by,
            "approved_at": authority.approved_at.isoformat(),
            "expires_at": authority.expires_at.isoformat(),
            "revoked_at": authority.revoked_at.isoformat() if authority.revoked_at else None,
            "note": "the collection recorded this authority at collection "
                    "time; expiry and any later revocation are reported, "
                    "not re-judged here",
        }
    elif authority is not None:
        authorization = {
            "status": "NOT_RECORDED",
            "basis": "revision_mismatch",
            "note": "the collection named an authority whose recorded "
                    "revision no longer matches the approved revision — "
                    "truth assessment must account for this",
        }
    elif getattr(scan, "collector_authority_id", None):
        authorization = {
            "status": "NOT_RECORDED",
            "basis": "recorded_authority_missing",
            "note": "the collection named an authority that no longer "
                    "exists — truth assessment must account for this",
        }
    else:
        # Unstamped (legacy rows, or no covering authority at collection
        # time). A live authority for this target is shown as an
        # INFERENCE ONLY — coverage at collection time cannot be proven.
        candidate = db.execute(
            select(CollectorAuthority)
            .where(CollectorAuthority.tenant_id == row.tenant_id,
                   CollectorAuthority.entry == scan.target_location,
                   CollectorAuthority.revoked_at.is_(None))
            .order_by(CollectorAuthority.approved_at.desc())
        ).scalars().first()
        authorization = {
            "status": "NOT_RECORDED",
            "basis": "collection_did_not_name_authority",
            "note": "the collection did not record which authority it ran "
                    "under — coverage at collection time cannot be proven; "
                    "truth assessment must account for this",
        }
        if candidate is not None:
            authorization["candidate_authority"] = {
                "authority_id": candidate.id,
                "authority_revision": int(candidate.revision or 0),
                "approved_at": candidate.approved_at.isoformat(),
                "note": "an unrevoked authority matches this target today — "
                        "an inference, NOT proof it covered the collection",
            }

    finding, redacted = project_finding(row.finding_data)
    verified = _chain_link_verified(row)
    tenant = row.tenant_id or "unknown"
    sha = row.content_hash or ""

    return FindingProvenanceBundle(
        evidence_id=row.id,
        collector=ProvenanceCollector(
            scanner_id=scan.scanner_id,
            scanner_version=scan.scanner_version,
            operator=scan.operator,
            scan_status=scan.status,
        ),
        asset=ProvenanceAsset(
            file_path=row.file_path,
            line_number=row.line_number,
            class_name=row.class_name,
            method_name=row.method_name,
            target_type=scan.target_type,
            target_location=scan.target_location,
            target_commit=scan.target_commit,
        ),
        observed=ProvenanceObserved(
            scan_start=scan.scan_start,
            scan_end=scan.scan_end,
            recorded_at=getattr(row, "created_at", None),
        ),
        source_and_method=ProvenanceSourceAndMethod(
            collection_method=scan.scanner_id,
            target_type=scan.target_type,
            target_location=scan.target_location,
            collection_authorization=authorization,
        ),
        evidence_reference=ProvenanceEvidenceReference(
            content_hash=row.content_hash,
            storage_key=f"{tenant}/{sha[:2]}/{sha}.bin" if sha else "",
            chain_position=row.chain_position,
            chain_hash=row.chain_hash,
            previous_hash=row.previous_hash,
            manifest_hash=scan.manifest_hash,
        ),
        detection=ProvenanceDetection(
            detection_rule_version=scan.scanner_version,
            scanner_ids=scanner_ids,
        ),
        finding=finding or {},
        integrity=ProvenanceIntegrity(
            chain_link_verified=verified,
            verification_result="CHAIN_LINK_VERIFIED" if verified
            else "CHAIN_LINK_BROKEN",
        ),
        truth=ProvenanceTruth(),
    )


# --------------------------------------------------------------------------- #
# Observation conflicts (audit 50) — disagreement between observers, surfaced
# --------------------------------------------------------------------------- #

@router.get("/findings/corroboration")
def finding_corroboration(
    scan_id: str = Query(..., description="Scan whose observations are checked for agreement"),
    compare_scan_id: str | None = Query(
        None, description="Optional second scan: agreement across the two scans instead"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Where independent observers of the same site AGREE (audit 49 P1#5).

    The complementary surface to /findings/conflicts: same normalized
    algorithm and parameters, observed by >= 2 distinct scanners, with a
    tier-aware *suggested* confidence uplift — annotation only, recorded
    confidence is never rewritten. Retracted evidence never corroborates.
    """
    from normalization.corroboration import corroboration_summary

    from db.models.scan import Scan

    def _scan_exists(scan_id_value: str) -> bool:
        return db.execute(
            select(Scan).where(Scan.id == scan_id_value).limit(1)
        ).scalars().first() is not None

    if not _scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    repo = EvidenceRepository(db)

    def _view(row) -> dict:
        # same observer resolution as the scorecard surface: provenance
        # and finding-source identity become the scanner id so
        # independence is judged on real observer names
        from normalization.calibration import UNATTRIBUTED, detector_key

        base = {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
            "provenance": row.provenance,
            "finding_data": row.finding_data,
        }
        key = detector_key(base)
        if key != UNATTRIBUTED:
            base["scanner_ids"] = [key]
        return base

    # retracted evidence must not corroborate either
    baseline = [_view(r) for r in repo.get_all_for_scan(scan_id, include_deleted=False)]
    if compare_scan_id:
        if not _scan_exists(compare_scan_id):
            raise HTTPException(status_code=404, detail="Comparison scan not found")
        current = [_view(r) for r in repo.get_all_for_scan(compare_scan_id, include_deleted=False)]
        # cross-scan corroboration: stamp which scan each view came from
        # so observers from the two scans stay distinct even when both
        # fall back to unknown-observer
        for view in baseline:
            view.setdefault("scan_ids", [scan_id])
        for view in current:
            view.setdefault("scan_ids", [compare_scan_id])
        observations = baseline + current
    else:
        observations = baseline

    summary = corroboration_summary(observations)
    summary["scan_id"] = scan_id
    summary["compare_scan_id"] = compare_scan_id
    return summary


@router.get("/findings/conflicts")
def finding_conflicts(
    scan_id: str = Query(..., description="Scan whose observations are checked against each other"),
    compare_scan_id: str | None = Query(
        None, description="Optional second scan: conflicts between the two scans instead"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Where observers of the same site disagree: algorithm, parameters, or verdict.

    Within one scan this is scanner-vs-scanner disagreement; with
    ``compare_scan_id`` it is scan-vs-scan (the honest replacement for
    "trust the newest"). Conflicts are reported, never auto-resolved —
    resolution is a human/policy decision, this endpoint just refuses to
    keep the disagreement invisible.
    """
    from normalization.conflicts import detect_conflicts, detect_cross_scan_conflicts

    from db.models.scan import Scan

    def _view(row) -> dict:
        return {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
        }

    def _scan_exists(scan_id_value: str) -> bool:
        return db.execute(
            select(Scan).where(Scan.id == scan_id_value).limit(1)
        ).scalars().first() is not None

    if not _scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    repo = EvidenceRepository(db)
    # retracted (soft-deleted) evidence must not manufacture conflicts
    baseline = [_view(r) for r in repo.get_all_for_scan(scan_id, include_deleted=False)]
    if compare_scan_id:
        if not _scan_exists(compare_scan_id):
            raise HTTPException(status_code=404, detail="Comparison scan not found")
        current = [_view(r) for r in repo.get_all_for_scan(compare_scan_id, include_deleted=False)]
        conflicts = detect_cross_scan_conflicts(
            baseline, current, baseline_scan_id=scan_id, current_scan_id=compare_scan_id)
    else:
        conflicts = detect_conflicts(baseline)

    by_type: dict[str, int] = {}
    for c in conflicts:
        by_type[c["conflict_type"]] = by_type.get(c["conflict_type"], 0) + 1
    return {
        "scan_id": scan_id,
        "compare_scan_id": compare_scan_id,
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
        "by_type": by_type,
    }


@router.get("/findings/detectors/scorecards")
def detector_scorecards(
    scan_limit: int = Query(25, ge=1, le=200,
                            description="How many most-recent scans calibrate over"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Per-detector calibration scorecards (audit 49 P0#4, round 28).

    Production has no labeled ground truth, so calibration is measured
    through the two honest proxies the platform records: retractions
    (soft-deleted evidence — operator-judged false positives) and
    authority losses (the non-preferred side of decisive observation
    conflicts under the 6-tier hierarchy). Annotation only — recorded
    confidence is never rewritten.

    Tombstones COUNT (they are the retraction signal) but never feed
    conflict detection, so a retraction cannot manufacture a conflict.
    """
    from normalization.calibration import (UNATTRIBUTED, detector_key,
                                           detector_scorecards as score)
    from normalization.conflicts import detect_conflicts

    from db.models.scan import Scan

    scan_rows = db.execute(
        select(Scan).order_by(Scan.scan_start.desc()).limit(scan_limit)
    ).scalars().all()
    if not scan_rows:
        return {"detectors": [], "detector_count": 0, "tier_counts": {},
                "scans_considered": 0, "observations": 0,
                "method": {"note": "no scans yet — nothing to calibrate"}}

    repo = EvidenceRepository(db)

    def _view(row) -> dict:
        # EvidenceRecord has no scanner_ids column — the observer identity
        # lives in the provenance / finding-source JSON. Resolve it once so
        # both the scorecard grouping and the conflict detector see the
        # same observer name (authority tokens read scanner_ids).
        base = {
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "compliance_status": row.compliance_status,
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
            "provenance": row.provenance,
            "finding_data": row.finding_data,
            "deleted": row.deleted_at is not None,
        }
        key = detector_key(base)
        if key != UNATTRIBUTED:
            base["scanner_ids"] = [key]
        return base

    views: list[dict] = []
    conflicts: list[dict] = []
    for scan in scan_rows:
        # tombstones included: retraction is the FP proxy being measured
        views.extend(_view(r) for r in repo.get_all_for_scan(scan.id, include_deleted=True))
        # tombstones excluded: retracted evidence must not manufacture conflicts
        live = [_view(r) for r in repo.get_all_for_scan(scan.id, include_deleted=False)]
        conflicts.extend(detect_conflicts(live))

    result = score(views, conflicts)
    result["scans_considered"] = len(scan_rows)
    result["observations"] = len(views)
    return result


REPO_ROOT = Path(__file__).resolve().parents[4]

#: Where the precomputed calibration lives. Overridable so an image build can put
#: it anywhere and a test can point at its own copy.
CALIBRATION_ARTIFACT_ENV = "ACCURACY_LABELED_CALIBRATION"
DEFAULT_CALIBRATION_ARTIFACT = REPO_ROOT / "data" / "accuracy" / "labeled-calibration.json"

logger = logging.getLogger(__name__)


def _calibration_artifact_path() -> Path:
    override = os.environ.get(CALIBRATION_ARTIFACT_ENV)
    return Path(override) if override else DEFAULT_CALIBRATION_ARTIFACT


def _load_calibration_artifact(path: Path) -> dict | None:
    """The stored report, or None when it is absent, unreadable or stale.

    Staleness is decided by a fingerprint over the corpus definition and the
    benchmark that scores it. A report that describes a corpus this tree no
    longer ships is worse than no report: it reads as a current measurement.
    """
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        logger.warning("labeled_calibration_artifact_unreadable", extra={"path": str(path), "error_type": type(error).__name__})
        return None
    expected = _calibration_fingerprint()
    if payload.get("input_fingerprint") != expected:
        logger.info("labeled_calibration_artifact_stale", extra={"path": str(path)})
        return None
    return payload


def _calibration_fingerprint() -> str:
    """SHA-256 over the corpus definition and the benchmark (`build_labeled_calibration`).

    Kept algorithmically identical to ``build_labeled_calibration.fingerprint`` (which
    includes every wave module and the production parsers): an artifact built by one
    must be accepted by the other, and ``test_labeled_calibration_artifact`` enforces it.
    """
    import hashlib

    digest = hashlib.sha256()
    relatives = ["services/scanner/tests/accuracy/corpus.py", "scripts/accuracy_benchmark.py"]
    for pattern in ("services/scanner/tests/accuracy/corpus_wave*.py", "services/scanner/scanner/parsers/*.py"):
        relatives.extend(sorted(p.relative_to(REPO_ROOT).as_posix() for p in REPO_ROOT.glob(pattern)))
    for relative in relatives:
        digest.update(relative.encode())
        source = REPO_ROOT / relative
        digest.update(source.read_bytes() if source.exists() else b"<missing>")
    return digest.hexdigest()


def _write_calibration_artifact(path: Path, payload: dict) -> None:
    """Best effort: a read-only image still serves, it just recomputes next time."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload))
        temporary.replace(path)
    except OSError as error:
        logger.warning("labeled_calibration_artifact_not_written", extra={"path": str(path), "error_type": type(error).__name__})


@lru_cache(maxsize=1)
def _corpus_benchmark() -> tuple:
    """The labeled accuracy report: from the artifact, or computed once per process.

    Computing it means scanning all 842 labelled files with the production
    scanner — 2 s here, 6.9–10 s measured against a live server on a cold process
    — on the request thread. `scripts/build_labeled_calibration.py` writes the
    same report ahead of time; this reads it, and only falls back to computing
    (then stores the result for the other workers) when there is none.
    """
    path = _calibration_artifact_path()
    stored = _load_calibration_artifact(path)
    if stored is not None:
        return (stored,)

    import importlib.util
    import sys

    bench = REPO_ROOT / "scripts" / "accuracy_benchmark.py"
    spec = importlib.util.spec_from_file_location("accuracy_benchmark_runtime", bench)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["accuracy_benchmark_runtime"] = mod
    spec.loader.exec_module(mod)
    report = mod.run()
    payload = {
        "schema": "cryptoscan.labeled-calibration/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_fingerprint": _calibration_fingerprint(),
        "corpus_overall": report.get("overall"),
        "cases": [
            {
                "language": case.get("language"),
                "file": case.get("file"),
                "category": case.get("category"),
                "expected": case.get("expected") or [],
                "reports": case.get("reports") or [],
            }
            for case in (report.get("cases") or [])
        ],
    }
    _write_calibration_artifact(path, payload)
    return (payload,)


@router.get("/findings/detectors/labeled-calibration")
def labeled_detector_calibration(
    user: str = Depends(get_current_user),
):
    """Labeled ground-truth calibration (audits 49 P0#4 + 52, round 34).

    Per-detector TP/FP/precision measured against the hand-labeled
    accuracy corpus — every case carries the exact algorithm families a
    correct scanner must report, and hard negatives label any report as a
    false positive. Misses stay scanner-level (which detector *should*
    have seen a family is a coverage question, so per-detector recall is
    never fabricated).

    Deliberately separate from `GET /findings/detectors/scorecards`:
    that surface calibrates over production traffic through honest
    proxies (retractions, authority losses); this one measures against
    fixed ground truth. Both views, not either alone.
    """
    from scanner.labeled_calibration import labeled_detector_metrics

    report = _corpus_benchmark()[0]
    calibration = labeled_detector_metrics(report.get("cases") or [])
    calibration["corpus_overall"] = report.get("corpus_overall") or report.get("overall")
    calibration["report"] = {
        "generated_at": report.get("generated_at"),
        "cases": len(report.get("cases") or []),
        "source": "precomputed" if report.get("schema") else "computed",
    }
    return calibration


@router.get("/findings/{evidence_id}", response_model=FindingResponse)
def get_finding(
    evidence_id: str,
    user: str = Depends(get_current_user),
    repo: EvidenceRepository = Depends(get_evidence_repository),
    ctx: TenantContext = Depends(history_context),
):
    row = repo.get_by_id(evidence_id)
    if row is None or row.tenant_id != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_response(row, include_raw=True)


@router.get("/findings/{evidence_id}/verify")
def verify_finding(
    evidence_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
    ctx: TenantContext = Depends(history_context),
):
    """§4.2 (round 42): per-record evidence verification.

    A scan-level PASS is not a per-record verdict. This recomputes ONE
    record's content hash and chain linkage against its own commitments
    (and its predecessor's), using the same verifier the scan-level
    endpoint uses — the two surfaces cannot disagree. Honest scope: it
    proves storage has not diverged from the commitment, not that the
    observation itself was true.
    """
    from evidence.verification.stored_scan import verify_stored_record

    row = db.execute(
        select(EvidenceRecord).where(EvidenceRecord.id == evidence_id, EvidenceRecord.tenant_id == ctx.tenant_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = db.execute(select(Scan).where(Scan.id == row.scan_id, Scan.tenant_id == ctx.tenant_id)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Owning scan not found")
    predecessor = None
    if row.chain_position and row.chain_position > 0:
        predecessor = db.execute(
            select(EvidenceRecord).where(
                EvidenceRecord.scan_id == row.scan_id,
                EvidenceRecord.tenant_id == ctx.tenant_id,
                EvidenceRecord.chain_position == row.chain_position - 1,
            )
        ).scalar_one_or_none()
    verdict = verify_stored_record(
        row, previous_record=predecessor,
        expected_position=row.chain_position, scan_id=scan.id)
    return verdict | {
        "verified_by": user,
        "scan_status": scan.status,
        "scan_verify_path": f"/api/v1/scans/{scan.id}/verify",
    }


class SoftDeleteRequest(BaseModel):
    """Retraction request: a reason is mandatory (audit trail, report 15 §6.2)."""

    reason: str = Field(..., min_length=3, description="Why this finding is being retracted")


def _announce_findings_change(row: Any, change: str, user: str) -> None:
    """Push a findings change onto the realtime contract.

    Best-effort by design: the retraction is already committed and audited, and a broken
    event bus must not turn a successful retraction into a 500. The screen that missed the
    push refetches on its next connect — which is why the channel carries the resource path
    and not just a name.
    """
    try:
        from api import realtime

        realtime.publish(
            "findings",
            "status_changed",
            detail=f"Finding {row.id} {change} by {user}",
            payload={
                "evidence_id": str(row.id),
                "scan_id": row.scan_id,
                "status": change,
                "by": user,
            },
        )
    except Exception:  # noqa: BLE001 — an audit-grade failure would already have raised
        logger.warning("findings_realtime_publish_failed", extra={"evidence_id": str(row.id)})


@router.post("/findings/{evidence_id}/soft-delete", response_model=FindingResponse)
def soft_delete_finding(
    evidence_id: str,
    body: SoftDeleteRequest,
    user: str = Depends(require_auditor),
    repo: EvidenceRepository = Depends(get_evidence_repository),
    db: Session = Depends(get_db_session),
):
    """Retract one finding without breaking the scan's hash chain.

    Marks the evidence row as a tombstone (deleted_at / deleted_by /
    delete_reason). Chain verification and exports still see the row — the
    chain it committed to stays intact — while consumption surfaces
    (listings, CBOM generation, conflicts, drift, remediation suggestions)
    stop counting it. Auditor-only. Deleting an already-retracted row
    returns 409 with the existing tombstone info.
    """
    row = repo.get_by_id(evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if row.deleted_at is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Finding already retracted by {row.deleted_by} at {row.deleted_at.isoformat()}",
        )
    row.deleted_at = datetime.now(timezone.utc)
    row.deleted_by = user[:100]
    row.delete_reason = body.reason
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "evidence.soft_delete",
            target_type="evidence",
            target_id=str(row.id),
            detail={"scan_id": row.scan_id, "reason": body.reason},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("evidence_soft_delete_audit_failed", extra={"evidence_id": evidence_id})
        raise HTTPException(status_code=503, detail="Evidence retraction audit is unavailable")
    # a retraction changes what every findings screen should show, so it is pushed rather
    # than discovered on the next poll. Published after the commit: announcing a change the
    # transaction then rolls back is how a live screen ends up showing something false
    _announce_findings_change(row, "retracted", user)
    return _to_response(row, include_raw=True)


@router.post("/findings/{evidence_id}/restore", response_model=FindingResponse)
def restore_finding(
    evidence_id: str,
    user: str = Depends(require_auditor),
    repo: EvidenceRepository = Depends(get_evidence_repository),
    db: Session = Depends(get_db_session),
):
    """Reverse a retraction: clears the tombstone, the row re-enters consumption.

    The retraction's audit entry stays in the hash-chained log — undoing a
    tombstone remains visible as a past action. Auditor-only. 409 if the
    finding is not currently retracted.
    """
    row = repo.get_by_id(evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if row.deleted_at is None:
        raise HTTPException(status_code=409, detail="Finding is not retracted")
    prior = {"deleted_at": row.deleted_at.isoformat(), "deleted_by": row.deleted_by}
    row.deleted_at = None
    row.deleted_by = None
    row.delete_reason = None
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "evidence.restore",
            target_type="evidence",
            target_id=str(row.id),
            detail={"scan_id": row.scan_id, "prior_tombstone": prior},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("evidence_restore_audit_failed", extra={"evidence_id": evidence_id})
        raise HTTPException(status_code=503, detail="Evidence restore audit is unavailable")
    _announce_findings_change(row, "restored", user)
    return _to_response(row, include_raw=True)

