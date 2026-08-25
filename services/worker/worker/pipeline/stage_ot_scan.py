"""Passively parse OT/ICS captures that happen to live in the scanned tree."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    root = Path(ctx.repo_path)
    if not root.exists():
        return ctx
    try:
        from ot_scanner.core.scanner import OtPassiveScanner
    except Exception:
        logger.debug("ot_scanner_unavailable")
        return ctx
    result = OtPassiveScanner().scan_filesystem(root, scan_id=ctx.scan_id)
    if not result.get("findings") and not result.get("devices"):
        return ctx
    ctx.ot_result = result
    ctx.scan_meta["ot"] = {
        "devices": result.get("device_count") or 0,
        "findings": len(result.get("findings") or []),
        "unencrypted": result.get("unencrypted") or 0,
        "packets_sent": result.get("packets_sent") or 0,
    }
    for finding in result.get("findings") or []:
        crypto = finding.get("crypto") or {}
        ctx.findings.append(
            {
                "finding_id": f"ot-{finding.get('source', {}).get('src_ip')}-{finding.get('protocol')}",
                "scanner_id": "ot-passive-scanner-v1.0",
                "algorithm": crypto.get("encryption") or crypto.get("authentication") or "NONE",
                "purpose": "OT_NETWORK",
                "file_path": (finding.get("source") or {}).get("file_path") or "ot-traffic",
                "line_number": 0,
                "confidence": "MEDIUM",
                "compliance_issue": finding.get("compliance_issue"),
                "source": finding.get("source"),
                "crypto": crypto,
                "metadata": finding.get("metadata"),
            }
        )
    if session is not None:
        try:
            from db.repositories.maturity_repository import MaturityRepository

            repo = MaturityRepository(session)
            id_by_ip = {}
            for device in result.get("devices") or []:
                row = repo.upsert_ot_device(device)
                id_by_ip[device.get("ip_address")] = row.id
            for finding in result.get("findings") or []:
                ip = (finding.get("device") or {}).get("ip_address")
                repo.add_ot_finding(id_by_ip.get(ip), finding)
        except Exception:
            logger.debug("ot_persist_skipped", exc_info=True)
    logger.info("stage_ot_scan_done", extra=ctx.scan_meta.get("ot") or {})
    return ctx
