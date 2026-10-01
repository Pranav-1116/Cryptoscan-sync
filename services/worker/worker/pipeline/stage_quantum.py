"""Scan-level quantum report + PQC migration plan into scan statistics.

Runs the deterministic quantum engine over this scan's evidence rows and
persists a compact summary alongside the drift gate. Mosca's migration
time (y) comes only from the system's declared `pq_migration_years` —
never invented here.
"""

from __future__ import annotations

from db.tenancy import filtered_get

import logging
from typing import Any

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def _summary(report: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    mosca = plan.get("mosca") or {}
    return {
        "overall_hndl_risk": report.get("overall_hndl_risk"),
        "vulnerable_count": report.get("vulnerable_count"),
        "pqc_ready_count": report.get("pqc_ready_count"),
        "total_sites": (plan.get("inventory") or {}).get("total_sites"),
        "hndl_counts": report.get("counts"),
        "by_threat_type": (plan.get("inventory") or {}).get("by_threat_type"),
        "wave1_sites": ((plan.get("waves") or {}).get("1") or {}).get("site_count"),
        "workstreams": [
            {
                "target": stream.get("target"),
                "site_count": stream.get("site_count"),
                "priority": stream.get("priority"),
                "hybrid": stream.get("hybrid"),
                "earliest_deadline": stream.get("earliest_deadline"),
            }
            for stream in (plan.get("workstreams") or [])
        ],
        "mosca": {
            "verdict": mosca.get("verdict"),
            "computable": mosca.get("computable"),
            "x_shelf_life_years": mosca.get("x_shelf_life_years"),
            "y_migration_years": mosca.get("y_migration_years"),
            "z_years_to_crqc": mosca.get("z_years_to_crqc"),
            "slack_years": mosca.get("slack_years"),
        },
        "calculation_version": plan.get("calculation_version") or report.get("calculation_version"),
    }


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    if session is None or not ctx.scan_id:
        return ctx
    try:
        from sqlalchemy import select
        from sqlalchemy.orm.attributes import flag_modified

        from db.models.evidence_record import EvidenceRecord
        from db.models.scan import Scan
        from db.models.system import System
        from quantum.plan import build_migration_plan
        from quantum.risk import analyze_quantum_risk
    except Exception:
        logger.debug("quantum_stage_unavailable", exc_info=True)
        return ctx
    try:
        rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
        findings = [
            {
                "evidence_id": row.id,
                "system_id": ctx.system_id,
                "algorithm": row.algorithm,
                "key_size": row.key_size,
                "purpose": row.purpose,
                "file_path": row.file_path,
                "line_number": row.line_number,
                "compliance_status": row.compliance_status,
                "is_hardcoded_key": row.is_hardcoded_key,
            }
            for row in rows
        ]
        system = filtered_get(session, System, ctx.system_id) if ctx.system_id else None
        system_rows = []
        migration_years = None
        if system is not None:
            system_rows = [system.to_dict()]
            migration_years = (system.extra or {}).get("pq_migration_years")
        report = analyze_quantum_risk(findings, systems=system_rows)
        plan = build_migration_plan(findings, systems=system_rows, migration_years=migration_years)
        summary = _summary(report, plan)
        ctx.scan_meta["quantum"] = summary
        scan = filtered_get(session, Scan, ctx.scan_id)
        if scan is not None:
            stats = dict(scan.statistics or {})
            stats["quantum"] = summary
            scan.statistics = stats
            try:
                flag_modified(scan, "statistics")
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
            session.flush()
        verdict = (summary.get("mosca") or {}).get("verdict")
        if summary.get("overall_hndl_risk") == "CRITICAL" or verdict in {"ALREADY_LATE", "AT_RISK"}:
            logger.warning(
                "quantum_hndl_alert",
                extra={
                    "job_id": ctx.job_id,
                    "scan_id": ctx.scan_id,
                    "hndl": summary.get("overall_hndl_risk"),
                    "mosca": verdict,
                    "wave1_sites": summary.get("wave1_sites"),
                },
            )
        logger.info(
            "stage_quantum_done",
            extra={"vulnerable": summary.get("vulnerable_count"), "workstreams": len(summary.get("workstreams") or [])},
        )
    except Exception:
        logger.debug("quantum_stage_failed", exc_info=True)
    return ctx
