"""Monitor-time reintroduction sweep (audit 69's open follow-up, round 24).

The retired-asset registry was checked per scan *on demand* —
``POST /retirements/check/{scan_id}`` — which means a reintroduction is
only visible to whoever remembers to ask. This sweep runs on the monitor
tick instead: the newest completed scan per target is checked against the
active registry, so a retired algorithm reappearing anywhere in the estate
escalates through the alert channels without waiting for an operator.

Semantics are the scan-time check's, unchanged (same
``detect_reintroductions`` engine): sites observed only after the
retirement was registered are the alarming ones — evidence predating the
promise was never covered by it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def run_reintroduction_sweep(
    session: Any,
    *,
    now: datetime | None = None,
    on_alert: Callable[[str, str, dict], None] | None = None,
    max_scans: int = 500,
    max_links: int = 50_000,
) -> dict[str, Any]:
    """Check the newest completed scan per target against the registry.

    Bounded by construction: at most ``max_scans`` newest scans (with an
    explicit truncation flag) and at most ``max_links`` asset-evidence
    links. Alerts (CEF/webhook/email via the monitor's AlertRouter) fire
    for CRITICAL/HIGH detections; every detection emits a
    ``retirement.reintroduced`` platform event marked
    ``detected_by: monitor`` so monitor-time and scan-time detections are
    distinguishable in the journal.
    """
    from sqlalchemy import select

    from db.models.retired_asset import RetiredAsset
    from db.models.scan import Scan
    from db.repositories.evidence_repository import EvidenceRepository
    from remediation.reintroduction import detect_reintroductions

    now = _aware(now) or datetime.now(timezone.utc)

    retirements = list(
        session.execute(select(RetiredAsset).where(RetiredAsset.active == True)).scalars()  # noqa: E712
    )
    if not retirements:
        return {
            "retirements": 0,
            "scans_checked": 0,
            "scans_truncated": False,
            "reintroductions": [],
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
        }

    # newest completed scan per target, over a bounded window of newest rows
    scan_rows = (
        session.execute(
            select(Scan)
            .where(Scan.status == "COMPLETED")
            .order_by(Scan.scan_start.desc())
            .limit(max_scans)
        )
        .scalars()
        .all()
    )
    truncated = len(scan_rows) == max_scans
    newest_by_target: dict[str, Scan] = {}
    for scan in scan_rows:
        newest_by_target.setdefault(str(scan.target_location or scan.id), scan)

    # asset linkage only when an ASSET-scope retirement needs it
    asset_links: dict[str, set[str]] = {}
    links_truncated = False
    if any(str(r.scope or "").upper() == "ASSET" for r in retirements):
        from db.models.crypto_asset_evidence import CryptoAssetEvidence

        link_rows = (
            session.execute(select(CryptoAssetEvidence).limit(max_links)).scalars().all()
        )
        links_truncated = len(link_rows) == max_links
        for link in link_rows:
            asset_links.setdefault(str(link.evidence_id), set()).add(str(link.asset_id))

    retirement_dicts = [
        {
            "id": r.id,
            "algorithm": r.algorithm,
            "scope": r.scope,
            "file_path": r.file_path,
            "asset_id": r.asset_id,
            "retired_at": _aware(r.retired_at),
        }
        for r in retirements
    ]

    detections: list[dict[str, Any]] = []
    evidence_repo = EvidenceRepository(session)
    for target, scan in newest_by_target.items():
        scan_start = _aware(scan.scan_start)
        # evidence predating the retirement was never covered by the promise
        applicable = [
            r for r in retirement_dicts
            if r["retired_at"] is None or scan_start is None or scan_start >= r["retired_at"]
        ]
        if not applicable:
            continue
        findings = []
        for row in evidence_repo.get_all_for_scan(str(scan.id), include_deleted=False):
            findings.append(
                {
                    "algorithm": row.algorithm,
                    "file_path": row.file_path,
                    "line_number": row.line_number,
                    "compliance_status": row.compliance_status,
                    "is_hardcoded_key": row.is_hardcoded_key,
                    "asset_ids": sorted(asset_links.get(str(row.id), ())),
                }
            )
        for detection in detect_reintroductions(applicable, findings):
            detection = dict(detection)
            detection["scan_id"] = str(scan.id)
            detection["target"] = target
            detection["detected_by"] = "monitor"
            detections.append(detection)

    for detection in detections:
        try:
            from api.events.platform_events import emit_platform_event

            emit_platform_event(
                "retirement.reintroduced",
                f"REINTRODUCTION (monitor): {detection['algorithm']} retired "
                f"{detection.get('retired_at')} is back in scan "
                f"{detection['scan_id']} ({len(detection.get('matched_sites') or [])} site(s))",
                {"source": "monitor-sweep", **detection},
                target_name="retirement",
            )
        except Exception:
            logger.debug("reintroduction_event_skipped", exc_info=True)
        if on_alert is not None and str(detection.get("severity")) in {"CRITICAL", "HIGH"}:
            try:
                on_alert(
                    str(detection.get("target") or detection.get("scan_id") or "estate"),
                    f"retired algorithm {detection['algorithm']} reintroduced "
                    f"({detection.get('severity')}, {len(detection.get('matched_sites') or [])} site(s))",
                    {"detection": detection},
                )
            except Exception:  # noqa: BLE001 — alerting must not kill the sweep
                logger.warning("reintroduction_alert_failed", exc_info=True)

    severity_counts = {
        level: sum(1 for d in detections if d.get("severity") == level)
        for level in ("CRITICAL", "HIGH", "MEDIUM")
    }
    if detections:
        logger.warning(
            "reintroduction_sweep_detections",
            extra={"detections": len(detections), "severities": severity_counts},
        )
    return {
        "retirements": len(retirements),
        "scans_checked": len(newest_by_target),
        "scans_truncated": truncated,
        "asset_links_truncated": links_truncated,
        "reintroductions": detections,
        "severity_counts": severity_counts,
    }
