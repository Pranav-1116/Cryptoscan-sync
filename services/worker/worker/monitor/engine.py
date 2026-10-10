"""Continuous monitoring engine: due targets -> live scanners -> state + events.

One tick: pick every enabled target whose ``next_scan_at`` has passed, run it
through the same live scanners the manual flows use, store the rolling summary,
and record an event for every outcome. Design rules for 24/7 operation:

- the tick never raises — a failing target is data, not a crash;
- failures back off exponentially (interval × 2^failures, capped at 24 h) so a
  dead endpoint cannot hammer the network every tick;
- anything unscannable (cloud without credentials, unknown type) is reported
  as BLOCKED with the exact reason — never silently skipped;
- an ALERT fires only when a scan shows a *new* issue the previous summary did
  not have, so a steady-state weak endpoint alerts once, not every cycle.

Realtime layer (enterprise live scanning):

- **change watch**: targets with ``config.watch = true`` are probed every tick
  for change (git HEAD for REPO, image id for CONTAINER). A *changed* target is
  rescanned immediately — no waiting for the next scheduled window — and a
  ``CHANGE_DETECTED`` event is recorded. The first observation is a baseline,
  never an alert (see ``worker.monitor.watch``).
- **jitter**: ``next_scan_at`` is pushed out by a random fraction of the
  interval (``jitter_fraction``) so a large fleet of targets does not thunder
  together every cycle. Off by default; enable via settings.
- **bounded concurrency**: with ``concurrency > 1`` and a ``session_factory``,
  due/watch-triggered targets run in a thread pool, each with its own fresh
  DB session — one slow scanner cannot hold up the whole fleet.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from db.models.monitor import TARGET_TYPES, MonitorTarget
from db.repositories.monitor_repository import MonitorRepository

from worker.monitor.watch import WATCH_PROBES, ChangeDetector, ProbeResult

logger = logging.getLogger(__name__)

DEFAULT_INTERVALS: dict[str, int] = {
    "NETWORK": 900,    # 15 min — endpoint posture changes fast
    "CLOUD": 21_600,   # 6 h — account-level crypto config
    "REPO": 86_400,    # daily — source-driven (watch mode rescans on push)
    "CONTAINER": 86_400,
    "PAYMENT": 3_600,     # hourly — HSM audit trails move fast
    "OT": 900,        # 15 min — passive capture re-scan (watch mode rescans on new captures)
    "VENDOR": 604_800,  # weekly — vendor posture changes slowly
    "TELECOM": 900,    # 15 min — 5GC/roaming NF posture changes fast
}
MAX_BACKOFF_SECONDS = 86_400

# A runner takes (config, session) and returns:
#   {"summary": {...}, "degraded": bool, "issues": [...]}   on success
#   {"blocked_reason": "..."}                                when it cannot run
# It raises only on genuine failure (unreachable, scanner error).
Runner = Callable[[dict, Any], dict]


def default_interval(target_type: str) -> int:
    return DEFAULT_INTERVALS.get(target_type, 86_400)


class MonitorEngine:
    def __init__(self, session: Any, *, runners: dict[str, Runner] | None = None, clock=None,
                 on_alert: Callable[[str, str, dict], None] | None = None,
                 jitter_fraction: float = 0.0, rng: Callable[[float, float], float] | None = None,
                 watch_enabled: bool = True, probes: dict[str, Callable[..., ProbeResult]] | None = None,
                 probe_timeout: float = 10.0,
                 session_factory: Callable[[], Any] | None = None, concurrency: int = 1,
                 run_reports: bool = True, run_backups: bool = True,
                 run_network: bool = True,
                 run_reintroduction: bool = True, run_sla: bool = True,
                 backup_backend_for: Callable[[str], Any] | None = None,
                 backup_storage: Any = None):
        self.session = session
        self.repo = MonitorRepository(session)
        self.runners = runners if runners is not None else _default_runners()
        self._now = clock or (lambda: datetime.now(timezone.utc))
        self._on_alert = on_alert
        self.jitter_fraction = max(0.0, float(jitter_fraction))
        self._rng = rng or random.uniform
        self.watch_enabled = bool(watch_enabled)
        self.probes = probes if probes is not None else WATCH_PROBES
        self.probe_timeout = float(probe_timeout)
        self.session_factory = session_factory
        self.concurrency = max(1, int(concurrency))
        self.run_reports = bool(run_reports)
        self.run_backups = bool(run_backups)
        self.run_network = bool(run_network)
        # round 24 (audits 69 + 31 §5.2): monitor-time reintroduction
        # detection and drift-SLA escalation run on the same tick
        self.run_reintroduction = bool(run_reintroduction)
        self.run_sla = bool(run_sla)
        self._backup_backend_for = backup_backend_for
        self._backup_storage = backup_storage

    # ---------------------------------------------------------------- tick

    def tick(self) -> dict[str, Any]:
        """Run every target that is due *or* whose watched state just changed,
        then execute any due compliance report schedules.

        Returns an honest per-target outcome list plus the trigger breakdown
        (``watch_triggered`` vs ``due``) and ``report_ran`` so operators can
        see why the daemon did work.
        """
        now = self._now()
        triggered: list[MonitorTarget] = []
        if self.watch_enabled:
            for target in self.repo.list_targets(enabled=True):
                if self._check_watch(target) == "CHANGED":
                    triggered.append(target)
        if self.concurrency > 1 and self.session_factory is not None:
            self.session.flush()  # persist watch_state so per-session workers see it

        triggered_ids = {t.id for t in triggered}
        due = [t for t in self.repo.due(now=now) if t.id not in triggered_ids]
        ordered = triggered + due
        results = self._execute_many(ordered)

        network_summary: dict[str, Any] = {}
        if self.run_network:
            # API-created network_scan_targets are a separate persisted
            # schedule from monitor_target rows. Run them in this same leader
            # tick so their results become the durable NBOM input.
            try:
                from worker.monitor.network_sweep import run_due_network_targets

                network_summary = run_due_network_targets(self.session, now=now)
            except Exception as exc:  # noqa: BLE001 — network sweep must not stop other monitor work
                logger.exception("network_sweep_failed")
                network_summary = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}

        report_outcomes: list[dict[str, Any]] = []
        if self.run_reports:
            from worker.monitor.report_sweep import run_due_report_schedules

            report_outcomes = run_due_report_schedules(self.session, on_event=self._report_event)

        reintroduction_summary: dict[str, Any] = {}
        if self.run_reintroduction:
            # audit 69's open follow-up: the retired-asset registry checked
            # continuously, not only on demand
            try:
                from worker.monitor.reintroduction_sweep import run_reintroduction_sweep

                reintroduction_summary = run_reintroduction_sweep(
                    self.session, now=now,
                    on_alert=(lambda name, issue, payload: self._on_alert(name, issue, payload))
                    if self._on_alert is not None else None,
                )
            except Exception as exc:  # noqa: BLE001 — must not stop other monitor work
                logger.exception("reintroduction_sweep_failed")
                reintroduction_summary = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}

        sla_summary_tick: dict[str, Any] = {}
        if self.run_sla:
            # audit 31 §5.2: escalate drift events that crossed an SLA window
            try:
                from worker.monitor.sla_sweep import run_sla_sweep

                sla_summary_tick = run_sla_sweep(
                    self.session, now=now,
                    on_alert=self._on_alert if self._on_alert is not None else None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("sla_sweep_failed")
                sla_summary_tick = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}

        backup_summary: dict[str, Any] = {}
        if self.run_backups:
            # real subprocess backends + persistent disk store are used by
            # default; tests may inject fakes. Missing tools fail honestly.
            backup_summary = self._run_backup_sweep(now)

        return {
            "ran": len(results),
            "results": results,
            "watch_triggered": len(triggered),
            "due": len(due),
            "network": network_summary,
            "report_ran": len(report_outcomes),
            "reports": report_outcomes,
            "reintroduction": reintroduction_summary,
            "drift_sla": sla_summary_tick,
            "backups": backup_summary,
        }

    def _run_backup_sweep(self, now) -> dict[str, Any]:
        """Run due encrypted backups (Postgres/Neo4j) + retention on the tick.

        Isolated: a backup failure never raises out of the monitor loop. The
        runner backend + storage are injected; production supplies subprocess
        pg_dump/neo4j-admin runners and a persistent storage sink."""
        try:
            from db.repositories.settings_repository import SettingsRepository
            from governance import backup_schedule as bsched, backup_jobs as bj, keys as gkeys
            import os as _os

            repo = SettingsRepository(self.session)

            # Default to REAL subprocess backends (pg_dump / neo4j-admin) and a
            # persistent on-disk store unless tests explicitly injected them.
            backend_for = self._backup_backend_for
            if backend_for is None:
                def backend_for(engine_name: str):
                    runner = bj.subprocess_runner()
                    if engine_name == "neo4j":
                        return bj.Neo4jBackend(
                            runner=runner,
                            host=_os.environ.get("NEO4J_HOST", "localhost"),
                            port=int(_os.environ.get("NEO4J_BACKUP_PORT", "6362")),
                            neo4j_bin=_os.environ.get("NEO4J_BIN", ""),
                            backup_dir=_os.environ.get("NEO4J_BACKUP_STAGING", "/tmp/cryptoscan-neo4j-backup"))
                    return bj.PgDumpBackend(
                        runner=runner,
                        host=_os.environ.get("PGHOST", _os.environ.get("POSTGRES_HOST", "localhost")),
                        port=int(_os.environ.get("PGPORT", _os.environ.get("POSTGRES_PORT", "5432"))),
                        user=_os.environ.get("PGUSER", _os.environ.get("POSTGRES_USER", "postgres")),
                        pg_bin=_os.environ.get("PG_BIN", ""))
            storage = self._backup_storage
            if storage is None:
                root = _os.environ.get("BACKUP_STORAGE_DIR", "/var/lib/cryptoscan/backups")
                try:
                    storage = bj.DiskBackupStorage(root)
                except Exception:
                    import tempfile
                    storage = bj.DiskBackupStorage(__import__("os").path.join(tempfile.gettempdir(), "cryptoscan-backups"))

            summary = bsched.run_due_backups_sweep(
                settings_repo=repo, backend_for=backend_for,
                storage=storage,
                encryption_key=gkeys.backup_fernet_key(settings_repo=repo),
                signing_secret=gkeys.signing_secret(settings_repo=repo), now=now)
            if summary.get("backed_up"):
                self._report_event("backup_sweep", f"backed_up={summary['backed_up']}", summary)
            return summary
        except Exception as exc:  # noqa: BLE001 — backups must never kill monitoring
            import logging
            logging.getLogger(__name__).warning("backup_sweep_failed: %s", exc)
            return {"error": f"{type(exc).__name__}: {exc}"}

    # ----------------------------------------------------------- report run

    def _report_event(self, event_type: str, detail: str, payload: dict) -> None:
        """Record report outcomes as monitor events (federated to SSE)."""
        self.repo.add_event(
            target=None, event_type=event_type, detail=detail[:1000], payload=payload,
        )

    # ------------------------------------------------------ change watching

    def _check_watch(self, target: MonitorTarget) -> str:
        """Probe one watched target. Verdicts: CHANGED | UNCHANGED | UNKNOWN | NONE.

        Never raises: probe failures become a (deduplicated) event and fall
        through to the normal schedule — watching must not break scanning.
        """
        config = dict(target.config or {})
        if not config.get("watch"):
            return "NONE"
        probe = self.probes.get(target.target_type)
        if probe is None:
            self._watch_unsupported(target)
            return "NONE"
        try:
            result = probe(config, timeout=self.probe_timeout)
        except Exception as exc:  # noqa: BLE001 — a probe must never kill the tick
            return self._watch_probe_failed(target, f"{type(exc).__name__}: {exc}")
        if not result.ok:
            return self._watch_probe_failed(target, result.error or "probe failed")

        previous = (config.get("watch_state") or {}).get("state")
        verdict, next_state = ChangeDetector.detect(previous, result)
        target.config = {**config, "watch_state": {"state": next_state}}
        if verdict == "CHANGED":
            self.repo.add_event(
                target=target, event_type="CHANGE_DETECTED",
                detail=f"change detected: {next_state}",
                payload={"previous": previous, "current": next_state},
            )
            logger.info("monitor_change_detected", extra={"target": target.name, "state": next_state})
            return "CHANGED"
        return verdict

    def _watch_probe_failed(self, target: MonitorTarget, error: str) -> str:
        """Record a probe failure once per distinct error (no event spam)."""
        config = dict(target.config or {})
        watch_state = dict(config.get("watch_state") or {})
        if watch_state.get("probe_error") != error:
            self.repo.add_event(
                target=target, event_type="WATCH_PROBE_FAILED",
                detail=error[:500], payload={"error": error},
            )
            target.config = {**config, "watch_state": {**watch_state, "probe_error": error}}
        return "UNKNOWN"

    def _watch_unsupported(self, target: MonitorTarget) -> None:
        """watch requested on a type with no probe — honest, once, documented."""
        config = dict(target.config or {})
        watch_state = dict(config.get("watch_state") or {})
        if not watch_state.get("unsupported"):
            self.repo.add_event(
                target=target, event_type="WATCH_UNSUPPORTED",
                detail=(
                    f"watch is not supported for {target.target_type}; "
                    f"supported: {sorted(self.probes)} — scheduled scans continue"
                ),
                payload={"supported": sorted(self.probes)},
            )
            target.config = {**config, "watch_state": {**watch_state, "unsupported": True}}

    # ------------------------------------------------------------- run one

    def _meter_scan(self, target: MonitorTarget) -> None:
        """SaaS metering: one scan_run unit per executed pass, tenant-owned
        targets only. Best-effort — metering must never break the loop."""
        if not getattr(target, "tenant_id", None):
            return
        try:
            from db.repositories.tenant_repository import TenantRepository

            TenantRepository(self.session).record_usage(
                target.tenant_id, "scan_run", 1, detail=target.name)
        except Exception:
            logger.debug("tenant_usage_record_failed", extra={"target": target.name}, exc_info=True)

    def _publish_pass(self, target: MonitorTarget, status: str) -> None:
        """Every finished pass becomes a signed raw event on the stream
        (24/7 collection). Best-effort — publishing must never break the
        monitor loop. The event lands in the TARGET's partition (2026-10):
        a tenant-owned monitor's passes are that tenant's observations, not
        platform-stream material — unowned targets keep the platform bus."""
        try:
            from eventstream.bus import get_bus_for_tenant

            get_bus_for_tenant(getattr(target, "tenant_id", None)).publish_raw(
                {
                    "kind": "monitor_pass",
                    "target_name": target.name,
                    "target_type": target.target_type,
                    "status": status,
                    "summary": target.last_summary or {},
                    "tenant_id": getattr(target, "tenant_id", None),
                    "observed_at": target.last_scan_at.isoformat() if target.last_scan_at else None,
                },
                key=target.name,
                source="monitor-daemon",
            )
        except Exception:
            logger.debug("monitor_pass_publish_failed", extra={"target": target.name}, exc_info=True)

    def run_target(self, target: MonitorTarget) -> dict[str, Any]:
        now = self._now()
        interval = int(target.interval_seconds or default_interval(target.target_type))
        runner = self.runners.get(target.target_type)
        if runner is None:
            self._finish(
                target, now=now, interval=interval, status="BLOCKED",
                error=f"no runner for target type '{target.target_type}' (expected one of {TARGET_TYPES})",
                event_type="BLOCKED",
            )
            return self._outcome(target, "BLOCKED")

        try:
            result = runner(dict(target.config or {}), self.session)
            # Domain adapters still own their operational persistence, but all
            # explicit crypto observations/findings enter the same durable
            # tenant-scoped CBOM/event journal before the target summary is
            # committed. Projection failures are real degradation, not a
            # silently successful scan.
            from worker.monitor.realtime_projection import persist_monitor_projection

            persist_monitor_projection(target, result, self.session)
            self._meter_scan(target)
        except Exception as exc:  # 24/7 rule: the target fails, the loop does not
            logger.warning("monitor_target_failed", extra={"target": target.name})
            failures = int(target.consecutive_failures or 0) + 1
            backoff = min(interval * (2 ** failures), MAX_BACKOFF_SECONDS)
            target.consecutive_failures = failures
            target.status = "FAILING" if failures >= 2 else "DEGRADED"
            target.last_error = f"{type(exc).__name__}: {exc}"[:500]
            target.next_scan_at = now + timedelta(seconds=backoff)
            self.repo.add_event(
                target=target, event_type="SCAN_FAILED",
                detail=target.last_error,
                payload={"consecutive_failures": failures, "retry_in_seconds": backoff},
            )
            return self._outcome(target, target.status)

        if result.get("blocked_reason"):
            self._finish(
                target, now=now, interval=interval, status="BLOCKED",
                error=str(result["blocked_reason"])[:500], event_type="BLOCKED",
            )
            return self._outcome(target, "BLOCKED")

        summary = dict(result.get("summary") or {})
        issues = sorted(set(result.get("issues") or summary.get("issues") or []))
        summary["issues"] = issues
        new_issues = self._new_issues(target, issues)
        target.consecutive_failures = 0
        target.last_error = None
        target.last_scan_at = now
        target.next_scan_at = now + self._next_scan_delta(interval)
        target.last_summary = summary
        degraded = bool(result.get("degraded")) or bool(issues)
        target.status = "DEGRADED" if degraded else "OK"
        self.repo.add_event(
            target=target,
            event_type="SCAN_DEGRADED" if degraded else "SCAN_OK",
            detail=f"{len(issues)} issue(s)" if issues else "clean",
            payload=summary,
        )
        for issue in new_issues:
            self.repo.add_event(
                target=target, event_type="ALERT",
                detail=f"NEW: {issue}", payload={"issue": issue},
            )
            if self._on_alert is not None:
                try:
                    self._on_alert(target.name, issue, {"target_id": target.id, "issue": issue})
                except Exception:  # noqa: BLE001 — sink failures never kill the tick
                    logger.exception("alert_dispatch_failed")
        return self._outcome(target, target.status, new_issues=new_issues)

    # ----------------------------------------------------- fleet execution

    def _execute_many(self, targets: list[MonitorTarget]) -> list[dict[str, Any]]:
        if not targets:
            return []
        if self.concurrency <= 1 or self.session_factory is None:
            return [self.run_target(target) for target in targets]
        from concurrent.futures import ThreadPoolExecutor

        def _work(target_id: str) -> dict[str, Any]:
            session = self.session_factory()
            try:
                engine = MonitorEngine(
                    session, runners=self.runners, clock=self._now,
                    on_alert=self._on_alert, jitter_fraction=self.jitter_fraction,
                    rng=self._rng, watch_enabled=False, probes=self.probes,
                    probe_timeout=self.probe_timeout, concurrency=1,
                )
                row = engine.repo.get(target_id)
                if row is None:
                    return {"target_id": target_id, "status": "GONE"}
                return engine.run_target(row)
            finally:
                session.commit()
                session.close()

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            return list(pool.map(_work, [t.id for t in targets]))

    # ------------------------------------------------------------- helpers

    def _next_scan_delta(self, interval: int) -> timedelta:
        """Interval plus jitter (0 when disabled → deterministic schedules)."""
        if self.jitter_fraction <= 0:
            return timedelta(seconds=interval)
        spread = max(0.0, interval * self.jitter_fraction)
        return timedelta(seconds=interval + self._rng(0.0, spread))

    def _new_issues(self, target: MonitorTarget, issues: list[str]) -> list[str]:
        previous = set((target.last_summary or {}).get("issues") or [])
        return [issue for issue in issues if issue not in previous]

    def _finish(self, target, *, now, interval, status, error, event_type) -> None:
        self._publish_pass(target, status)
        target.status = status
        target.last_error = error
        target.last_scan_at = now
        target.next_scan_at = now + self._next_scan_delta(interval)
        self.repo.add_event(target=target, event_type=event_type, detail=error)

    @staticmethod
    def _outcome(target: MonitorTarget, status: str, *, new_issues: list[str] | None = None) -> dict:
        return {
            "target": target.name,
            "target_id": target.id,
            "status": status,
            "new_issues": new_issues or [],
            "next_scan_at": target.next_scan_at.isoformat() if target.next_scan_at else None,
        }


def _default_runners() -> dict[str, Runner]:
    from worker.monitor.runners import (
        cloud_runner,
        container_runner,
        network_runner,
        ot_runner,
        payment_runner,
        repo_runner,
        telecom_runner,
        vendor_runner,
    )

    return {
        "NETWORK": network_runner,
        "CLOUD": cloud_runner,
        "REPO": repo_runner,
        "CONTAINER": container_runner,
        "PAYMENT": payment_runner,
        "OT": ot_runner,
        "VENDOR": vendor_runner,
        "TELECOM": telecom_runner,
    }
