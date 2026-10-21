"""Common durable projection for monitor target scanner observations.

The worker monitor has domain-specific adapters for operational reasons, but
its crypto observations must not stop at a target summary. This adapter uses
the same explicit-field CBOM projection as the API live runner and writes the
tenant-qualified current state plus immutable replay events.
"""

from __future__ import annotations

import logging
import hashlib
import json
from typing import Any

logger = logging.getLogger(__name__)


def persist_monitor_projection(target: Any, result: dict[str, Any], session: Any) -> None:
    """Persist explicit observations/findings from one monitor pass.

    Missing optional API modules or a storage problem are logged and re-raised
    to the monitor engine, which records the target pass as degraded rather
    than claiming durable success.
    """
    data = result.get("data")
    if not isinstance(data, dict):
        return
    from api.live_scan.runner import LiveScanRunner
    from db.models.crypto_live import CryptoLiveState
    from db.repositories.crypto_repository import CryptoRepository
    from sqlalchemy import delete

    scanner = str(result.get("scanner") or str(getattr(target, "target_type", "monitor")).lower())
    if getattr(target, "target_type", None) == "NETWORK":
        # Authorization, coverage and port-only discovery are not observed
        # crypto. Never recursively project receipt protocol names/hints.
        data = {key: value for key, value in data.items()
                if key not in {"collection", "monitor", "scope_discovery", "job_id", "run_id"}}
    components = LiveScanRunner._scanner_cbom_components(scanner, data)
    findings: list[dict[str, Any]] = []
    for key in ("findings", "alerts", "policy_findings", "vulnerabilities"):
        values = data.get(key) or []
        if isinstance(values, dict):
            values = [values]
        if isinstance(values, list):
            findings.extend({"scanner": scanner, **item} if isinstance(item, dict)
                            else {"scanner": scanner, "message": str(item)}
                           for item in values)
    tenant_id = getattr(target, "tenant_id", None)
    prefix = tenant_id or "platform"
    network = getattr(target, "target_type", None) == "NETWORK"
    namespace = f"{prefix}:monitor:{scanner}:"
    if network:
        if not getattr(target, "id", None):
            raise ValueError("Network monitor projection requires persisted target identity")
        namespace += f"{target.id}:"
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for component in components:
        groups.setdefault((str(component.get("type") or "crypto-asset"),
                           str(component.get("name") or ""),
                           str(component.get("version") or "")), []).append(component)

    # Incomplete network collection may add positive observations, never infer
    # deletion. Completed replacement is limited to this exact target namespace.
    if not network or result.get("observation_complete") is True:
        session.execute(delete(CryptoLiveState).where(
            CryptoLiveState.asset_id.startswith(namespace, autoescape=True),
            CryptoLiveState.tenant_id == tenant_id if tenant_id is not None
            else CryptoLiveState.tenant_id.is_(None),
        ))
    session.flush()
    repo = CryptoRepository(session)
    for (kind, name, version), rows in groups.items():
        if not name:
            continue
        if network:
            digest = hashlib.sha256(json.dumps([kind, name, version]).encode()).hexdigest()
            asset_id = f"{namespace}{digest}"
        else:
            asset_id = f"{namespace}{kind}:{name}:{version}"[:200]
        repo.upsert_state({
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "cbom_version": 1,
            "algorithms": [row.get("name") for row in rows if row.get("type") == "algorithm"],
            "quantum_status": {row.get("name"): row.get("quantum_status") for row in rows
                               if row.get("quantum_status")},
            "capabilities": [row for row in rows if row.get("type") == "capability"],
            "usage": {"scanner": scanner, "target_id": getattr(target, "id", None)},
            "protocols": [row for row in rows if row.get("type") == "protocol"],
            "certificates": [row for row in rows if row.get("type") == "certificate"],
            "libraries": [row for row in rows if row.get("type") in {"library", "package", "dependency"}],
            "cbom": {"components": rows, "scanner": scanner, "target_id": getattr(target, "id", None)},
            "last_event": "MONITOR_OBSERVED",
        })
        for row in rows:
            repo.append_event({
                "tenant_id": tenant_id,
                "event_type": "MONITOR_OBSERVED",
                "asset_id": asset_id,
                "source": scanner,
                "observed_at": row.get("observed_at"),
                "payload": {"target_id": getattr(target, "id", None), "component": row,
                            "evidence_reference": row.get("evidence_reference")},
            })
    for finding in findings:
        repo.append_event({
            "tenant_id": tenant_id,
            "event_type": "MONITOR_FINDING",
            "asset_id": f"{prefix}:monitor:{scanner}:{getattr(target, 'id', 'unknown')}"[:200],
            "source": scanner,
            "payload": {"target_id": getattr(target, "id", None), "finding": finding},
        })
