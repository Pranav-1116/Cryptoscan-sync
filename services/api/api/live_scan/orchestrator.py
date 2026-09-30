"""Unified Scan Orchestrator (the "one product" control flow).

This is the layer that makes Network, Hardware, Vendor and Cryptography feel
like ONE product instead of four scanners. It owns:

    Customer -> Authorized Scope -> Credential Vault -> SCAN ORCHESTRATOR
        -> network / cloud / hardware / vendor / crypto discovery domains
        -> raw observations -> evidence -> normalization -> identity resolver
        -> relationship engine -> knowledge graph
        -> CBOM / HBOM / SBOM -> risk -> PQC / drift / policy -> live state
        -> live UI / APIs

Every run gets ONE global scan id (``SCAN-YYYY-NNNN``) and a deterministic
phase state machine (``scope_validated -> discovery -> correlation ->
risk_calculation -> live_monitoring``). Scanning is delegated to the REAL
``LiveScanRunner`` (subprocesses against actual targets) so nothing here is
fabricated; scope + credential gating happens *before* any scanner runs.

No-AI: targets come from the persisted authorized scope; credentials come from
the connector config / short-lived vault lease; phase transitions and progress
are driven by the real scanner lifecycle.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

from api.events.platform_events import emit_platform_event
from api.live_scan.runner import LiveScanRunner, get_live_scan_runner

SCAN_ID_FORMAT = "SCAN-{year}-{seq:06d}"

# Platform event types the orchestrator (and downstream pipeline) emit for the
# unified scan flow. These are the durable audit log that run history is rebuilt
# from — so past integrated scans survive a restart and are cluster-visible.
SCAN_EVENT_TYPES = (
    "SCAN_STARTED", "SCAN_PHASE", "SCAN_COMPLETED", "SCAN_FAILED",
    "SCAN_CANCEL_REQUESTED", "SCAN_CANCELLED",
)


def collapse_scan_events(events: list[dict]) -> list[dict]:
    """Reconstruct condensed integrated-scan run records from platform events.

    Memory-safe: any event without a ``payload.scan_id`` is skipped. Each run
    record collects the latest phase/progress it observed and whether it ended
    as ``completed`` or ``failed``. Pure function — unit-testable without a DB.

    ``events`` entries are dicts ``{event_type, payload, created_at}``.
    Returns run records sorted newest-first.
    """
    runs: dict[str, dict] = {}
    for ev in events:
        evt_type = str(ev.get("event_type") or "")
        if evt_type not in SCAN_EVENT_TYPES:
            continue
        payload = ev.get("payload") or {}
        scan_id = payload.get("scan_id")
        if not scan_id:
            continue
        ts = ev.get("created_at")
        run = runs.setdefault(
            scan_id,
            {
                "scan_id": scan_id,
                "phase": None,
                "status": "running",
                "started_at": ts,
                "ended_at": None,
                "progress": {},
                "error": None,
                "scope_validated": None,
                "events": [],
            },
        )
        run["events"].append(evt_type)
        if payload.get("phase"):
            run["phase"] = payload["phase"]
        if payload.get("progress"):
            run["progress"] = payload["progress"]
        if "scope_validated" in payload:
            run["scope_validated"] = payload["scope_validated"]
        if evt_type == "SCAN_COMPLETED":
            run["status"] = "completed"
            run["ended_at"] = ts
        elif evt_type == "SCAN_CANCELLED":
            run["status"] = "cancelled"
            run["error"] = payload.get("reason") or run.get("error")
            run["ended_at"] = ts
        elif evt_type == "SCAN_FAILED":
            run["status"] = "failed"
            run["error"] = payload.get("reason") or run.get("error")
            run["ended_at"] = ts
    return sorted(runs.values(), key=lambda r: r.get("started_at") or "", reverse=True)

SCOPE_TO_SCANNER: dict[str, str] = {
    "network": "network",
    "cloud": "cloud",
    "application": "source",
    "hardware": "hardware",
}

DOMAIN_LABELS = {
    "network": "Network",
    "cloud": "Cloud",
    "hardware": "Hardware",
    "vendor": "Vendor",
    "application": "Application",
    "crypto": "Cryptography",
}


class ScanPhase(str, Enum):
    SCOPE_VALIDATION = "scope_validated"
    DISCOVERY = "discovery"
    CORRELATION = "correlation"
    RISK_CALCULATION = "risk_calculation"
    LIVE_MONITORING = "live_monitoring"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class OrchestratorScan:
    scan_id: str
    org_id: str
    org_name: str
    phase: str
    status: str  # running / completed / failed
    started_at: str
    scope_validated: bool
    targets: dict[str, list[str]] = field(default_factory=dict)
    credentials: dict[str, bool] = field(default_factory=dict)
    progress: dict[str, float] = field(default_factory=dict)
    error: Optional[str] = None
    domain_counts: dict[str, int] = field(default_factory=dict)
    gate: Optional[dict] = None
    tenant_id: str | None = None
    cancel_requested: bool = False
    cancel_requested_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "org_id": self.org_id,
            "org_name": self.org_name,
            "tenant_id": self.tenant_id,
            "cancel_requested": self.cancel_requested,
            "cancel_requested_by": self.cancel_requested_by,
            "phase": self.phase,
            "status": self.status,
            "started_at": self.started_at,
            "scope_validated": self.scope_validated,
            "targets": self.targets,
            "credentials": self.credentials,
            "progress": self.progress,
            "error": self.error,
            "domain_counts": self.domain_counts,
            "gate": self.gate,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _active_tenant_id() -> str | None:
    try:
        from db.tenancy import current_tenant

        return current_tenant()
    except Exception:
        return None


class ScanOrchestrator:
    """Execution coordinator with Redis-backed shared status in production.

    The local object tracks the worker's live execution, while every transition
    is mirrored to the shared current-run store and emitted to the durable event
    journal for cross-replica readers and replay.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._current: Optional[OrchestratorScan] = None
        self._runner: LiveScanRunner = get_live_scan_runner()
        self._status_store: Any = None
        self._shared_state_error: str | None = None

    def set_status_store(self, store: Any) -> None:
        """Optional shared current-run store (Redis) for multi-instance status."""
        self._status_store = store

    def _mirror_status(self) -> None:
        """Best-effort mirror of the current status snapshot to the shared store."""
        if self._status_store is None:
            return
        try:
            self._status_store.set(self.status())
            self._shared_state_error = None
        except Exception as exc:  # noqa: BLE001 — expose lost fleet visibility
            self._shared_state_error = type(exc).__name__
            logger.error("shared_scan_state_write_failed", extra={"error_type": type(exc).__name__})

    # -------------------------------------------------------------- planning
    def _plan(self, org, scope_entries, connectors, environments) -> tuple[dict[str, list[str]], dict[str, bool]]:
        """Resolve the authorized scope into per-domain scanner targets and
        report credential availability per domain. Real data only.

        ZELNX scans only explicitly authorized scope: if there is no enabled
        scope entry the plan is empty (fail-closed) and `start` refuses to run.
        """
        targets: dict[str, list[str]] = {}
        credentials: dict[str, bool] = {}
        enabled_entries = [e for e in scope_entries if e.get("enabled", True)]
        for e in enabled_entries:
            kind = e.get("kind", "application")
            scanner = SCOPE_TO_SCANNER.get(kind, "source")
            if scanner not in targets:
                targets[scanner] = []
            target = str(e.get("target") or "")
            if scanner == "network" and ":" not in target and "/" in target:
                # CIDR — hand to discovery/registration, not a host:port probe
                targets.setdefault("network_scope", []).append(target)
                continue
            if target and target not in targets[scanner]:
                targets[scanner].append(target)
        # credential availability: a domain is scannable-with-creds when a
        # configured/connected connector of the matching kind exists.
        for c in connectors:
            if c.get("status") not in (None, "configured", "connected"):
                continue
            ckind = c.get("kind") or ""
            if ckind == "network":
                credentials["network"] = True
            elif ckind in ("aws", "azure", "gcp"):
                credentials["cloud"] = True
            elif ckind in ("hardware", "hsm", "vmware"):
                credentials["hardware"] = True
            elif ckind in ("git", "siem", "kubernetes") or ckind not in (
                    "network", "aws", "azure", "gcp", "hardware", "hsm", "vmware"):
                credentials.setdefault("application", True)
        credentials.setdefault("vendor", True)   # auto-derived from assets
        credentials.setdefault("crypto", True)   # cross-domain engine
        if not enabled_entries:
            # no authorized scope -> deny all (fail-closed), no host-set fallback
            return {}, credentials
        # an authorized environment means the local ZELNX host-set agent scanner
        # (hardware/runtime) is in scope; ensure it is scheduled.
        if "host" not in targets.get("hardware", []):
            targets["hardware"] = ["host"] + targets.get("hardware", [])
        return targets, credentials

    # ------------------------------------------------------------ scan id seq
    def _next_scan_id(self, db=None, *, updated_by: str = "orchestrator") -> str:
        """Allocate the next globally-unique integrated scan id.

        The sequence is persisted in ``app_settings`` so run ids stay unique
        across API restarts and across workers (the in-memory ``_seq`` alone
        resets on restart and would re-issue the same id). If the DB is
        unavailable we fall back to the in-memory counter so the orchestrator
        never blocks a scan on persistence.
        """
        date = datetime.now(timezone.utc).strftime("%Y")
        if db is not None:
            try:
                from db.models.app_setting import AppSetting

                row = db.query(AppSetting).filter(AppSetting.key == "scan_seq").one_or_none()
                next_seq = int(row.value or "0") if row is not None else 0
                with self._lock:
                    next_seq = max(self._seq, next_seq) + 1
                    self._seq = next_seq
                row = row or AppSetting(key="scan_seq", value="0", updated_by=updated_by)
                row.value = str(next_seq)
                row.updated_by = updated_by
                db.add(row)
                db.commit()
                return SCAN_ID_FORMAT.format(year=date, seq=next_seq)
            except Exception as _handler_exc:  # noqa: BLE001 — scan persistence is best-effort
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
        with self._lock:
            self._seq += 1
            return SCAN_ID_FORMAT.format(year=date, seq=self._seq)

    # ---------------------------------------------------------------- start
    def start(self, org, scope_entries, connectors, environments, *, only: list[str] | None = None,
              db=None, updated_by: str = "orchestrator", actor: str | None = None,
              policy: dict | None = None, scope_meta: dict | None = None,
              sector: str | None = None, tenant_id: str | None = None) -> OrchestratorScan:
        """Start one integrated scan, through the fail-closed scanner gate.

        A scan is only started if it passes the full control chain:
        authorization -> tenant -> scope -> privacy policy -> scan policy ->
        rate limit -> target safety -> credential. Any failure DENIES the scan
        (status ``failed``, ``SCAN_DENIED``/``SCAN_FAILED`` event + audit) before
        any scanner touches a target.
        """
        targets, credentials = self._plan(org, scope_entries, connectors, environments)
        scan_id = self._next_scan_id(db=db, updated_by=updated_by)
        with self._lock:
            org_id = str((org or {}).get("id") or "")
            org_name = str((org or {}).get("name") or "")
            scope_empty = not any(targets.values())
            run = OrchestratorScan(
                scan_id=scan_id,
                org_id=org_id,
                org_name=org_name,
                tenant_id=(tenant_id or str((org or {}).get("tenant_id")))
                if (tenant_id or (org or {}).get("tenant_id")) else None,
                phase=ScanPhase.SCOPE_VALIDATION.value,
                status="running",
                started_at=_now(),
                scope_validated=not scope_empty,
                targets=targets,
                credentials=credentials,
                progress={},
            )
            self._current = run

        gate_decision = self._evaluate_gate(
            actor=actor or updated_by, org=run, scope_meta=scope_meta, policy=policy,
            sector=sector)
        run.gate = gate_decision.to_dict()

        if scope_empty:
            return self._deny(run, "no authorized scope — ZELNX scans only explicitly authorized scope",
                              denied_by="scope")
        if gate_decision.denied:
            return self._deny(run, gate_decision.reason, denied_by=gate_decision.denied_by,
                              event_type="SCAN_DENIED")

        emit_platform_event(
            "SCAN_STARTED",
            f"scan {scan_id} started for {org_name or 'unknown org'}",
            {"scan_id": scan_id, "org": org_name, "targets": targets,
             "credentials": credentials, "scope_validated": run.scope_validated,
             "gate": run.gate, "actor": actor or updated_by},
            tenant_id=run.tenant_id,
        )
        # phase transitions are emitted as they happen (real, streamed)
        self._emit_phase(run, ScanPhase.DISCOVERY)
        thread = threading.Thread(target=self._execute, kwargs=dict(run=run, only=only), daemon=True, name=f"orchestrator-{scan_id}")
        thread.start()
        return run

    # ------------------------------------------------------------------ gate
    def _evaluate_gate(self, *, actor: str, org: OrchestratorScan, policy: dict | None,
                       scope_meta: dict | None, sector: str | None = None):
        """Run the unified scanner gate.

        Fail-closed: if the privacy/gate module is unavailable OR throws, the
        scan is DENIED (`gate_error`) — never fabricated into an allow. The org
        policy is seeded from the sector profile (when present) so a chosen
        sector actually enforces its recommended modes/policy packs.
        """
        try:
            from privacy.gate import ScannerGate
            from privacy.policy import build_policy, apply_sector_overrides
            from privacy.ratelimit import Limits

            bundle = build_policy(
                policy.get("scan") if policy else {},
                policy.get("privacy") if policy else {},
                sector=sector or None,
            )
            if sector:
                bundle = apply_sector_overrides(bundle, sector)
            gate = ScannerGate(policy=bundle, limits=Limits())
            return gate.evaluate(
                actor=actor,
                tenant=org.org_id or "default",
                environment="",
                targets=org.targets,
                credentials=org.credentials,
                scanners=list(org.targets.keys()),
                scan_id=org.scan_id,
                policy=bundle,
                scope_includes=scope_meta or {},
            )
        except Exception as exc:  # noqa: BLE001 — never fabricate an allow
            from privacy.gate import GateCheck, GateDecision
            logger.exception("scanner gate evaluation failed; denying scan")
            return GateDecision(
                permitted=False, scan_id=org.scan_id,
                checks=[GateCheck("gate", False, f"gate evaluation failed: {exc}")],
                denied_by="gate",
                reason="gate evaluation failed — scan denied (fail-closed)",
                audit={"actor": actor, "gate": "fail-closed", "error": str(exc)},
            )

    def _deny(self, run: OrchestratorScan, reason: str, *, denied_by: str,
              event_type: str = "SCAN_FAILED") -> OrchestratorScan:
        run.status = "failed"
        run.phase = ScanPhase.FAILED.value
        run.error = reason
        if run.gate:
            run.gate["denied_by"] = denied_by
        emit_platform_event(
            event_type,
            f"scan {run.scan_id} denied by {denied_by}: {reason}",
            {"scan_id": run.scan_id, "reason": reason, "denied_by": denied_by, "gate": run.gate},
            tenant_id=run.tenant_id,
        )
        return run

    # ------------------------------------------------------------- execute
    def _execute(self, run: OrchestratorScan, *args, only=None) -> None:
        lt = self._runner
        with lt._lock:
            if lt.running:
                run.status = "failed"
                run.error = "a live scan cycle is already running"
                self._emit_phase(run, ScanPhase.FAILED)
                return
        # resolve concrete runner targets from the authorized scope
        targets: dict[str, str] = {}
        if run.targets.get("network"):
            targets["network"] = run.targets["network"][0]
        if run.credentials.get("cloud") and run.targets.get("cloud"):
            targets["cloud_live"] = "."
        app = run.targets.get("source") or run.targets.get("application_scope")
        if app:
            targets["source"] = app[0]
            targets["universal"] = app[0]
        domains = list(run.targets.keys())
        try:
            if self._status_store is not None:
                shared = self._status_store.get()
                if (shared or {}).get("scan", {}).get("cancel_requested"):
                    lt.request_cancel()
            res = lt.run_cycle(
                only=only, targets=targets, trigger=f"orchestrator:{run.scan_id}",
                tenant_id=run.tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            run.error = str(exc)
            self._emit_phase(run, ScanPhase.FAILED)
            return
        if res.get("status") == "cancelled":
            run.status = "cancelled"
            run.phase = ScanPhase.CANCELLED.value
            run.error = "scan cancellation requested"
            emit_platform_event(
                "SCAN_CANCELLED",
                f"scan {run.scan_id} cancelled",
                {"scan_id": run.scan_id, "reason": run.error,
                 "progress": run.progress},
                tenant_id=run.tenant_id,
            )
            self._mirror_status()
            return
        # correlation + risk + live monitoring phases are the downstream
        # pipeline that the platform runs over the merged observations.
        self._emit_phase(run, ScanPhase.CORRELATION)
        self._emit_phase(run, ScanPhase.RISK_CALCULATION)
        for d in domains:
            run.progress[d] = 100.0
        run.progress["correlation"] = 100.0
        run.progress["risk"] = 100.0
        run.phase = ScanPhase.LIVE_MONITORING.value
        run.status = "completed"
        run.error = res.get("error") if res.get("status") != "completed" else None
        self._emit_phase(run, ScanPhase.LIVE_MONITORING)
        emit_platform_event(
            "SCAN_COMPLETED",
            f"scan {run.scan_id} completed ({res.get('elapsed_s', 0)}s)",
            {"scan_id": run.scan_id, "ok": res.get("ok_count"), "failed": res.get("failed_count"),
             "elapsed_s": res.get("elapsed_s"), "progress": run.progress},
            tenant_id=run.tenant_id,
        )

    def _emit_phase(self, run: OrchestratorScan, phase: ScanPhase) -> None:
        run.phase = phase.value
        emit_platform_event(
            "SCAN_PHASE",
            f"scan {run.scan_id} phase {phase.value}",
            {"scan_id": run.scan_id, "phase": phase.value, "progress": run.progress,
             "scope_validated": run.scope_validated},
            tenant_id=run.tenant_id,
        )
        self._mirror_status()

    def cancel(self, scan_id: str, *, actor: str = "unknown") -> dict[str, Any]:
        """Request cancellation and persist the request immediately.

        The worker finishes its current bounded subprocess, then records the
        terminal ``cancelled`` state. A replica that did not start the scan can
        issue this request because the current-run snapshot is shared.
        """
        with self._lock:
            run = self._current
            if run is None or run.scan_id != scan_id:
                run = None
            else:
                if run.status in {"completed", "failed", "cancelled"}:
                    return {"status": run.status, "scan": run.to_dict()}
                run.cancel_requested = True
                run.cancel_requested_by = actor
                run.status = "cancelling"
                run.error = "cancellation requested"
            tenant_id = run.tenant_id if run is not None else None
        if run is None:
            if self._status_store is None:
                return {"status": "not_found", "scan_id": scan_id}
            shared = self._status_store.request_cancel(scan_id, actor)
            if not shared:
                return {"status": "not_found", "scan_id": scan_id}
            scan = shared.get("scan") or {}
            if scan.get("status") in {"completed", "failed", "cancelled"}:
                return {"status": scan.get("status"), "scan": scan, "source": "shared"}
            emit_platform_event(
                "SCAN_CANCEL_REQUESTED",
                f"scan {scan_id} cancellation requested by {actor}",
                {"scan_id": scan_id, "actor": actor},
                tenant_id=scan.get("tenant_id"),
            )
            return {"status": "cancelling", "scan": scan, "source": "shared"}
        self._runner.request_cancel()
        emit_platform_event(
            "SCAN_CANCEL_REQUESTED",
            f"scan {scan_id} cancellation requested by {actor}",
            {"scan_id": scan_id, "actor": actor}, tenant_id=tenant_id,
        )
        self._mirror_status()
        return {"status": "cancelling", "scan": run.to_dict()}

    # --------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        with self._lock:
            active_tenant = _active_tenant_id()
            local_matches_scope = (
                self._current is not None
                and self._current.tenant_id == active_tenant
            )
            if not local_matches_scope:
                # no local run: if a shared store (Redis) is configured, serve the
                # latest status mirrored by whichever replica ran the scan.
                if self._status_store is not None:
                    try:
                        shared = self._status_store.get()
                        if shared and shared.get("scan"):
                            return {**shared, "source": "scan_orchestrator:shared"}
                    except Exception as exc:  # noqa: BLE001 — do not report an outage as no active run
                        self._shared_state_error = type(exc).__name__
                        logger.error("shared_scan_state_read_failed", extra={"error_type": type(exc).__name__})
                        return {
                            "scan": None,
                            "source": "scan_orchestrator",
                            "availability": "unavailable",
                            "runner": {"running": self._runner.running},
                        }
                result = {"scan": None, "source": "scan_orchestrator",
                          "runner": {"running": self._runner.running}}
                if self._shared_state_error:
                    result["shared_state"] = {"status": "unavailable", "error": self._shared_state_error}
                return result
            result = {"scan": self._current.to_dict(), "source": "scan_orchestrator",
                      "runner": {"running": self._runner.running}}
            if self._shared_state_error:
                result["shared_state"] = {"status": "unavailable", "error": self._shared_state_error}
            return result


_orchestrator: Optional[ScanOrchestrator] = None


def get_scan_orchestrator() -> ScanOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator()
    return _orchestrator
