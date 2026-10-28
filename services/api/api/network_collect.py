"""One bounded network crypto collection, callable from the API *and* the CLI.

Both entry points must obey exactly the same rules, so the rules live here rather
than in a request handler: the operator's STOP switch, the approved scope
(destinations, protocol, operations, expiry), the traffic budget, the local
admission gate, the audited run record, and evidence persistence.

Nothing here decides who the caller is — it takes an actor string. Every refusal
is a :class:`CollectRefused` carrying a stable ``code``, so an HTTP layer can map
it to 409/422/429 and a terminal can print it. One code path means the two
front ends cannot drift into different rulebooks.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.security.network_budget import BudgetExhausted, reserve, settle
from api.security.network_collection import (
    admit_network,
    meter_network,
    network_coverage,
    network_run,
    persist_network,
)
from db.tenancy import current_tenant

MODEL = "cryptoscan.network-crypto-observation/1"


class CollectRefused(RuntimeError):
    """A collection was not allowed to start (or to continue)."""

    def __init__(self, code: str, reason: str, *, detail: dict[str, Any] | None = None) -> None:
        self.code = code
        self.reason = reason
        self.detail = dict(detail or {})
        super().__init__(reason)


def scope_key(tenant_id: str | None, inventory_id: str) -> str:
    from api.security.network_scope import scope_key as _key

    return _key(tenant_id, inventory_id)


def load_scope(db: Session, inventory_id: str = "default") -> dict[str, Any] | None:
    """The approved scope stored for this tenant/inventory, or ``None``."""
    from db.models.app_setting import AppSetting

    key = scope_key(current_tenant(), inventory_id)
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None or not row.value:
        return None
    try:
        data = json.loads(row.value)
    except ValueError:  # an unreadable scope is no scope, never a permissive one
        return None
    if not isinstance(data, dict):
        return None
    data["_key"] = key
    data["_updated_by"] = getattr(row, "updated_by", None)
    data["_tenant"] = current_tenant()
    return data


def require_running(db: Session) -> dict[str, Any]:
    """The operator STOP switch; engaged ⇒ nothing is collected (§30)."""
    from api.security.network_safety import NetworkStopped, require_running as _require

    try:
        return _require(db, tenant_id=current_tenant())
    except NetworkStopped as exc:
        # NetworkStopped carries its provenance in ``detail``; never invent it
        raise CollectRefused(exc.code, exc.reason, detail=dict(exc.detail or {})) from exc


def collect_network(
    db: Session,
    *,
    endpoints: Iterable[str] = (),
    protocol: str = "TLS",
    operations: Iterable[str] = ("CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"),
    timeout: float = 5.0,
    inventory_id: str = "default",
    scan_versions: bool = False,
    scan_ciphers: bool = False,
    user: str = "cli",
    scanner: Any = None,
    admit: Any = None,
    meter: Any = None,
) -> dict[str, Any]:
    """Observe TLS parameters for endpoints that are already in the approved scope.

    The scope decides *which* destinations are legal; the caller may only narrow
    the set. With no approved scope, an expired scope, a protocol or operation
    outside it, a destination outside it, a spent budget or an engaged STOP switch,
    this raises before a socket is opened.
    """
    from fastapi import HTTPException

    from api.security.network_collection import checked_hosts
    from api.security.network_scope import ScopeViolation, check_scope
    from network_scanner.inventory.network_evidence import build_evidence, summarize

    require_running(db)
    scope = load_scope(db, inventory_id)
    requested = [str(item) for item in endpoints]
    planned = requested or [str(item) for item in (scope or {}).get("destinations") or []]
    operations = [str(item) for item in operations]

    try:
        scope_admission = check_scope(scope, planned, protocol=protocol, operations=operations)
    except ScopeViolation as exc:
        raise CollectRefused(exc.code, exc.reason, detail=exc.detail) from exc

    try:
        targets = checked_hosts(scope_admission["destinations"])
    except HTTPException as exc:  # the shared validator speaks HTTP; translate it
        raise CollectRefused("invalid_targets", str(exc.detail)) from exc

    try:
        budget = reserve(db, scope, inventory_id=inventory_id, connections=len(targets), user=user)
    except BudgetExhausted as exc:
        raise CollectRefused(exc.code, exc.reason, detail=exc.detail) from exc

    admission = (admit or admit_network)(targets)
    (meter or meter_network)(db, targets)

    collector = scanner
    if collector is None:
        from network_scanner.core.scanner import NetworkTlsScanner

        collector = NetworkTlsScanner(live=True, timeout=timeout, workers=min(8, len(targets)))

    with network_run(
        db,
        user=user,
        target=",".join(targets)[:2000],
        admission=admission,
        kind="crypto-observe",
        profile={
            "protocol": scope_admission["protocol"],
            "operations": scope_admission["operations"],
            "scope_name": scope_admission["scope_name"],
            "scope_admission": scope_admission,
            "entry_point": "api.network_collect",
        },
    ) as run:
        result = collector.scan_hosts(targets, scan_versions=scan_versions, scan_ciphers=scan_ciphers)
        findings = result.get("findings") or []
        observed_at = datetime.now(timezone.utc).isoformat()
        evidence = [
            build_evidence(
                finding,
                scope_revision=str((scope or {}).get("saved_at") or "") or None,
                observed_at=observed_at,
                scope_name=scope_admission["scope_name"],
                extra={"operation": "TLS_HANDSHAKE", "run_id": run.job_id},
            )
            for finding in findings
        ]
        summary = summarize(evidence)
        payload = {
            **result,
            "network_evidence": evidence,
            "network_evidence_summary": summary,
            "scope_admission": scope_admission,
        }
        stored = persist_network(
            db,
            payload,
            run,
            kind="crypto-observe",
            phase_admission=[
                {"endpoint": endpoint, "phase": "tls_handshake", "decision": "PERMITTED"}
                for endpoint in targets
            ],
            collection_metadata={
                "protocol": scope_admission["protocol"],
                "scope_name": scope_admission["scope_name"],
                "evidence_schema": "cryptoscan.network-evidence/1",
            },
        )
        # ``stored`` carries run_id/probe_telemetry; the scanner result alone does
        # not, and ``network_coverage`` needs the run id it just wrote.
        run.succeed(coverage=network_coverage(stored))

    observed_bytes = sum(int((record.get("passive") or {}).get("bytes") or 0) for record in evidence)
    settled = settle(db, scope, inventory_id=inventory_id, bytes_used=observed_bytes, user=user)
    return {
        "scan_id": stored["job_id"],
        "run_id": stored["run_id"],
        "scope": scope_admission,
        "evidence": evidence,
        "summary": summary,
        "certificates": result.get("certificates") or [],
        "probe_telemetry": result.get("probe_telemetry"),
        "budget": {"reserved": budget, "settled": settled},
        "evidence_chain": stored.get("evidence_chain"),
        "model": MODEL,
    }
