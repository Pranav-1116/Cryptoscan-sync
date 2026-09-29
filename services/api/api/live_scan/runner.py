"""Live scanner orchestration — run the *real* CryptoScan scanners on an
on-demand basis and/or on a background interval, and stream their progress
plus findings over the existing SSE event bus.

This is deterministic truth-first: there is no synthetic data. Every number
shown live comes from actually invoking a scanner CLI (hardware, runtime,
network, container, cloud, OT) as a subprocess, capturing its JSON stdout,
and emitting that real result. A scanner that cannot run (missing dependency,
no target, no credentials) reports an honest error instead of a fake result.

Threading model: scans run on a single daemon worker thread (one at a time,
never overlapping). Results are published to the process-wide EventBus, whose
publish() is thread-safe and hops to SSE subscriber loops.

Every scanner service is covered live. Hardware + runtime always run. The
target-based services run on demand (via the /live-scan/run request fields)
and additionally on the periodic loop when their target is configured in the
API environment:
  CRYPTOSCAN_LIVE_NETWORK_TARGET=host:port   (TLS probe)
  CRYPTOSCAN_LIVE_NETWORK_FULL=1             (+ OCSP / renegotiation)
  CRYPTOSCAN_LIVE_CONTAINER_TARGET=<path|image|tar>
  CRYPTOSCAN_LIVE_OT_TARGET=<log file or dir>
  CRYPTOSCAN_LIVE_SOURCE_TARGET=<source dir>       (static crypto-API scan)
  CRYPTOSCAN_LIVE_UNIVERSAL_TARGET=<source dir>    (universal crypto scan)
  CRYPTOSCAN_LIVE_CLOUD=1                          (read-only live cloud; needs creds)
  CRYPTOSCAN_LIVE_INTERVAL=<seconds>               (loop interval, default 900)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _repo_root() -> Path:
    # .../services/api/api/live_scan/runner.py -> repo root is 4 parents up.
    env_root = os.environ.get("CRYPTOSCAN_ROOT")
    if env_root:
        return Path(env_root).resolve()
    return Path(__file__).resolve().parents[4]


def _build_pythonpath(root: Path) -> str:
    parts = []
    for d in sorted((root / "shared").glob("*/")):
        if d.is_dir():
            parts.append(str(d))
    for d in sorted((root / "services").glob("*/")):
        if d.is_dir():
            parts.append(str(d))
    existing = os.environ.get("PYTHONPATH", "")
    if existing:
        parts.append(existing)
    return os.pathsep.join(parts)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


#: well-known app_settings key under which the latest live-scan snapshot is
#: persisted, so results survive an API restart and can feed pages directly.
SNAPSHOT_SETTING_KEY = "live_scan.last_snapshot"


def _db_persist(snapshot: dict[str, Any]) -> bool:
    """Best-effort: write the snapshot to the settings table. Never raises —
    a missing/unconfigured DB must not block scanning."""
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            SettingsRepository(session).set(SNAPSHOT_SETTING_KEY, snapshot,
                                            updated_by="live-scanner")
            session.commit()
        return True
    except Exception:  # noqa: BLE001
        return False


def _db_load_snapshot() -> dict[str, Any] | None:
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            snap = SettingsRepository(session).get(SNAPSHOT_SETTING_KEY)
        return snap if isinstance(snap, dict) else None
    except Exception as _handler_exc:  # noqa: BLE001
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


#: privacy enforcement: the fail-safe default (no PII / secrets / private keys,
#: redaction on, data minimization on) applies whenever no org policy is stored.
def _privacy_policy_obj() -> Any | None:
    """Best-effort: load the org scan/privacy policy from app_settings.

    Returns a ``PrivacyPolicy`` (or ``None`` to signal the caller to use the
    fail-safe default). Never raises — a broken/unconfigured settings row must
    not block scanning; it just falls back to the strict default.
    """
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            repo = SettingsRepository(session)
            for key_candidate in ("scan_policy", "org:default:scan_policy"):
                raw = repo.get(key_candidate)
                if isinstance(raw, dict) and raw:
                    from privacy.policy import build_policy

                    return build_policy(raw.get("scan"), raw.get("privacy")).privacy
        from privacy.policy import PrivacyPolicy

        return PrivacyPolicy()  # fail-safe default
    except Exception:  # noqa: BLE001 — fail-safe on any error
        try:
            from privacy.policy import PrivacyPolicy

            return PrivacyPolicy()
        except Exception as _handler_exc:  # noqa: BLE001
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return None


def _privacy_scrub(snapshot: dict[str, Any], privacy_policy: Any | None) -> dict[str, Any]:
    """Apply the privacy engine to a live-scan snapshot. Fail-soft on engine
    issues (the scan already ran); returns the sanitized snapshot."""
    try:
        from privacy.engine import sanitize_snapshot

        sanitized, _report = sanitize_snapshot(snapshot, privacy_policy)
        return sanitized if isinstance(sanitized, dict) else snapshot
    except Exception:  # noqa: BLE001
        return snapshot


class ScannerSpec:
    """One invocable scanner command. The full host set runs in the periodic
    loop; the rest are on-demand only (they need a target or credentials)."""

    def __init__(
        self,
        key: str,
        argv: list[str],
        *,
        cwd: str,
        periodic: bool,
        needs_target: bool = False,
        timeout: int = 300,
        output_dir: bool = False,
        output_glob: str = "*.json",
    ) -> None:
        self.key = key
        self.argv = argv
        self.cwd = cwd
        self.periodic = periodic
        self.needs_target = needs_target
        self.timeout = timeout
        # When True, a temp working dir is created and (after success) the
        # newest file matching output_glob in it is read as the JSON result —
        # for scanners that write a report file instead of printing to stdout.
        self.output_dir = output_dir
        self.output_glob = output_glob


class LiveScanRunner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.interval: int = int(os.environ.get("CRYPTOSCAN_LIVE_INTERVAL", "900"))
        self.last_snapshot: dict[str, Any] | None = None
        self.last_run_at: str | None = None
        self.running: bool = False
        self._started_at: float | None = None
        self._persisted: bool = False
        self._prev_inventory: dict[str, Any] | None = None
        self.last_drift: dict[str, Any] | None = None

    # ------------------------------------------------------------------ specs
    def _specs(
        self,
        *,
        only: list[str] | None = None,
        targets: dict[str, str] | None = None,
    ) -> list[ScannerSpec]:
        root = _repo_root()
        py = sys.executable or "python3"
        targets = targets or {}
        specs: list[ScannerSpec] = [
            ScannerSpec(
                "hardware",
                [py, str(root / "services/universal_vendor/hw_scan.py"), "--json"],
                cwd=str(root),
                periodic=True,
                timeout=60,
            ),
            ScannerSpec(
                "runtime",
                [py, "-m", "runtime.main", "processes"],
                cwd=str(root / "services/runtime"),
                periodic=True,
                timeout=180,
            ),
        ]
        # Every scanner service is supported live. Target-bearing scanners
        # run either on-demand (via targets dict) or on the periodic loop when
        # a CRYPTOSCAN_LIVE_<SVC>_TARGET env var is configured. When a target
        # scanner has no target at all it is omitted (no fake/empty results).
        env = os.environ

        # network: explicit host:port only — never sweep an arbitrary network on a timer
        net_target = targets.get("network") or env.get("CRYPTOSCAN_LIVE_NETWORK_TARGET")
        if net_target:
            argv = [py, "-m", "network_scanner.main", net_target,
                    "--scan-versions", "--scan-ciphers", "--check-chain"]
            if targets.get("network_full") or env.get("CRYPTOSCAN_LIVE_NETWORK_FULL"):
                argv += ["--check-renegotiation", "--live-revocation"]
            specs.append(ScannerSpec(
                "network", argv,
                cwd=str(root / "services/network_scanner"),
                periodic=bool(env.get("CRYPTOSCAN_LIVE_NETWORK_TARGET")),
                needs_target=True, timeout=120,
            ))
        # telecom: registry-driven estate scan — no per-target env var; the
        # scanner probes every registered NF (5G SBA / EPC / IMS / signaling)
        if targets.get("telecom") or env.get("CRYPTOSCAN_LIVE_TELECOM"):
            specs.append(ScannerSpec(
                "telecom",
                [py, "-m", "telecom_scanner.main", "--json",
                 "--state", str(root / "data" / "telecom_state.json")],
                cwd=str(root),
                periodic=True,
                needs_target=False, timeout=300,
            ))
        ctr_target = targets.get("container") or env.get("CRYPTOSCAN_LIVE_CONTAINER_TARGET")
        if ctr_target:
            specs.append(ScannerSpec(
                "container",
                [py, "-m", "container_scanner.main", ctr_target],
                cwd=str(root / "services/container_scanner"),
                periodic=bool(env.get("CRYPTOSCAN_LIVE_CONTAINER_TARGET")),
                needs_target=True, timeout=300,
            ))
        ot_target = targets.get("ot_logs") or env.get("CRYPTOSCAN_LIVE_OT_TARGET")
        if ot_target:
            specs.append(ScannerSpec(
                "ot",
                [py, "-m", "ot_scanner.main", ot_target],
                cwd=str(root / "services/ot_scanner"),
                periodic=bool(env.get("CRYPTOSCAN_LIVE_OT_TARGET")),
                needs_target=True, timeout=180,
            ))
        # cloud: live read-only scan — needs cloud creds in the API env
        if targets.get("cloud_live") or env.get("CRYPTOSCAN_LIVE_CLOUD"):
            specs.append(ScannerSpec(
                "cloud",
                [py, "-m", "cloud_scanner.main", ".", "--live"],
                cwd=str(root / "services/cloud_scanner"),
                periodic=bool(env.get("CRYPTOSCAN_LIVE_CLOUD")),
                needs_target=True, timeout=300,
            ))
        # static source scanner (crypto API usage) — target source path
        src_target = targets.get("source") or env.get("CRYPTOSCAN_LIVE_SOURCE_TARGET")
        if src_target:
            specs.append(ScannerSpec(
                "source",
                [py, "-m", "scanner.main", "scan", "-s", str(src_target),
                 "--exclude-tests"],
                cwd=str(root / "services/scanner"),
                periodic=bool(env.get("CRYPTOSCAN_LIVE_SOURCE_TARGET")),
                needs_target=True, timeout=600,
                output_dir=True, output_glob="scan-results-*.json",
            ))
        # universal crypto scan (deterministic crypto detection across source)
        uc_target = targets.get("universal") or env.get("CRYPTOSCAN_LIVE_UNIVERSAL_TARGET")
        if uc_target:
            specs.append(ScannerSpec(
                "universal",
                [py, "-m", "universal_crypto.cli", "scan", str(uc_target), "--json"],
                cwd=str(root / "services/universal_crypto"),
                periodic=bool(env.get("CRYPTOSCAN_LIVE_UNIVERSAL_TARGET")),
                needs_target=True, timeout=600,
            ))
        if only:
            specs = [s for s in specs if s.key in only]
        return specs

    def _periodic_specs(self) -> list[ScannerSpec]:
        # include only scanners configured to repeat (host set + env targets)
        return [s for s in self._specs() if s.periodic]

    # ------------------------------------------------------------------ run
    def _run_spec(self, spec: ScannerSpec) -> dict[str, Any]:
        root = _repo_root()
        env = dict(os.environ)
        env["PYTHONPATH"] = _build_pythonpath(root)

        def _execute(out_dir: str | None) -> dict[str, Any]:
            argv = list(spec.argv)
            if out_dir is not None and spec.key == "source":
                argv += ["-o", out_dir]
            started = time.time()
            try:
                proc = subprocess.run(
                    argv, cwd=spec.cwd, env=env, capture_output=True,
                    text=True, timeout=spec.timeout,
                )
                elapsed = round(time.time() - started, 2)
                if proc.returncode != 0:
                    return {"scanner": spec.key, "ok": False,
                            "error": (proc.stderr or "non-zero exit").strip()[-400:],
                            "elapsed_s": elapsed}
                data: dict[str, Any] = {}
                if out_dir is not None:
                    files = sorted(Path(out_dir).glob(spec.output_glob),
                                   key=lambda p: p.stat().st_mtime, reverse=True)
                    if not files:
                        return {"scanner": spec.key, "ok": False,
                                "error": "scanner produced no output file",
                                "elapsed_s": elapsed}
                    data = json.loads(files[0].read_text())
                else:
                    data = json.loads(proc.stdout) if proc.stdout.strip() else {}
                return {"scanner": spec.key, "ok": True, "elapsed_s": elapsed,
                        "summary": self._summarize(spec.key, data), "data": data}
            except subprocess.TimeoutExpired:
                return {"scanner": spec.key, "ok": False,
                        "error": f"timed out after {spec.timeout}s",
                        "elapsed_s": spec.timeout}
            except FileNotFoundError as exc:
                return {"scanner": spec.key, "ok": False,
                        "error": f"scanner not found: {exc}", "elapsed_s": 0.0}
            except json.JSONDecodeError as exc:
                return {"scanner": spec.key, "ok": False,
                        "error": f"scanner did not emit JSON: {exc}",
                        "elapsed_s": round(time.time() - started, 2)}

        try:
            if spec.output_dir:
                with tempfile.TemporaryDirectory(prefix="cryptoscan-live-") as td:
                    return _execute(td)
            return _execute(None)
        except Exception as exc:  # noqa: BLE001 — never let one scanner kill the cycle
            return {"scanner": spec.key, "ok": False,
                    "error": f"runner error: {exc}", "elapsed_s": 0.0}

    @staticmethod
    def _summarize(key: str, data: dict[str, Any]) -> dict[str, Any]:
        """Small, SSE-friendly summary (full data kept in the snapshot)."""
        if key == "hardware":
            cpu = data.get("cpu") or {}
            tpm = data.get("tpm") or {}
            hsm = data.get("hsm") or {}
            return {
                "host": (data.get("host") or {}).get("hostname"),
                "cpu": cpu.get("model"),
                "aes_ni": cpu.get("aes_acceleration"),
                "hw_rng": cpu.get("hardware_rng"),
                "tpm_present": tpm.get("present"),
                "tpm_version": tpm.get("version"),
                "hsm_present": hsm.get("present"),
            }
        if key == "runtime":
            procs = data.get("processes") or []
            libs: dict[tuple, dict[str, Any]] = {}
            for p in procs:
                for d in p.get("library_details") or []:
                    name = d.get("library") or str(d.get("library_name") or "").split()[0]
                    k = (name, d.get("version"))
                    entry = libs.setdefault(k, {
                        "library": name,
                        "version": d.get("version"), "status": d.get("status"),
                        "package": d.get("package"), "processes": 0})
                    entry["processes"] += 1
            risky = {s for s in ("DISALLOWED", "DEPRECATED", "RESTRICTED")}
            risky_count = sum(1 for l in libs.values() if l.get("status") in risky)
            return {
                "crypto_processes": data.get("process_count", len(procs)),
                "total_processes_scanned": data.get("total_processes_scanned"),
                "kernel_threads_skipped": data.get("kernel_threads_skipped"),
                "libraries": len(libs),
                "risky_libraries": risky_count,
                "listening_endpoints": data.get("listening_processes"),
            }
        if key == "network":
            tel = data.get("probe_telemetry") or {}
            findings = data.get("findings") or []
            issues: list[str] = []
            for f in findings:
                issues += list(f.get("policy_issues") or [])
            return {
                "probed": tel.get("probed"), "ok": tel.get("ok"),
                "weak_tls": tel.get("weak_tls_versions"),
                "weak_ciphers": tel.get("weak_cipher_suites"),
                "policy_issues": sorted(set(issues)),
            }
        if key == "container":
            return {"findings": len(data.get("findings") or data.get("vulnerabilities") or [])}
        if key == "cloud":
            resources = data.get("resources") or data.get("assets") or []
            return {"resources": len(resources) if hasattr(resources, "__len__") else 0,
                    "findings": len(data.get("findings") or [])}
        if key == "source":
            # static scanner's ScanResult.statistics (or a bare findings list)
            stats = data.get("statistics") or data.get("stats") or {}
            findings = data.get("findings") or []
            return {
                "files_scanned": stats.get("files_scanned"),
                "findings": stats.get("total_findings", len(findings)),
                "high": stats.get("high_confidence"),
                "medium": stats.get("medium_confidence"),
                "low": stats.get("low_confidence"),
            }
        if key == "universal":
            report = data.get("report") if isinstance(data.get("report"), dict) else data
            qc = report.get("quantum_classifications") or {}
            return {
                "observations": len(report.get("observations") or []),
                "findings": len(report.get("findings") or []),
                "unknown_crypto": len(report.get("unknown_crypto") or []),
                "algorithms_classified": len(qc),
            }
        if key == "ot":
            return {"events": data.get("events_count") or len(data.get("events") or [])}
        return {}

    #: lifecycle/result events are durable: they are persisted to the DB event
    #: log in addition to the in-memory bus, so they reach browsers on other
    #: API workers (via the DB tailer) and survive a restart. High-frequency
    #: progress ticks (scanner_started/scanner_completed) stay in-memory only.
    _DURABLE_EVENTS = frozenset({
        "live_scan.started", "live_scan.completed", "live_scan.error", "live_scan.drift",
    })

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        try:
            from api.events.bus import get_event_bus

            get_event_bus().publish(event_type, payload, source="live-scanner")
        except Exception as _handler_exc:  # noqa: BLE001 — event failure must never kill a scan
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            pass
        if event_type in self._DURABLE_EVENTS:
            try:
                from api.events.platform_events import persist_platform_event

                detail = payload.get("error") or payload.get("trigger") or event_type
                persist_platform_event(event_type, str(detail), payload, target_name="live-scan")
            except Exception as _handler_exc:  # noqa: BLE001 — best-effort durability
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass

    def _auto_sync_graph(self, *, trigger: str, requested: list[str]) -> None:
        """After a scan cycle, reconcile the persisted graph and publish a
        precise graph.updated event. Best-effort and never raises."""
        try:
            from db.connection.session import SessionLocal

            from api.graph_builder import sync_graph

            with SessionLocal() as db:
                result = sync_graph(db)
            detail = (
                f"Graph auto-synced after {trigger} scan"
                f" ({result.get('nodes')} nodes / {result.get('edges')} edges)"
            )
        except Exception as exc:  # noqa: BLE001 — graph sync must not break a scan
            logger.warning("graph_auto_sync_failed: %s", exc)
            try:
                from api.events.platform_events import emit_platform_event

                emit_platform_event(
                    "graph.updated",
                    f"Scan cycle ({trigger}) completed — inventory may have changed",
                    {"trigger": trigger, "scanners": requested, "changed": True},
                    target_name="graph",
                )
            except Exception as _handler_exc:  # noqa: BLE001
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
            return
        try:
            from api.events.platform_events import emit_platform_event

            emit_platform_event(
                "graph.updated",
                detail,
                {
                    "trigger": trigger,
                    "scanners": requested,
                    "nodes": result.get("nodes"),
                    "edges": result.get("edges"),
                    "synced": result.get("synced", True),
                    "changed": True,
                },
                target_name="graph",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("graph_update_event_failed: %s", exc)

    def run_cycle(
        self,
        *,
        only: list[str] | None = None,
        targets: dict[str, str] | None = None,
        trigger: str = "manual",
    ) -> dict[str, Any]:
        """Execute one scan cycle (blocking). Publishes SSE events and stores
        the merged snapshot. Callers on the request thread should use
        start_cycle() to run it in the background."""
        with self._lock:
            if self.running:
                return {"status": "already_running"}
            self.running = True
            self._started_at = time.time()
        try:
            specs = self._specs(only=only, targets=targets)
            requested = [s.key for s in specs]
            self._publish("live_scan.started",
                          {"trigger": trigger, "scanners": requested})
            results: dict[str, Any] = {}
            for spec in specs:
                self._publish("live_scan.scanner_started",
                              {"scanner": spec.key})
                res = self._run_spec(spec)
                results[spec.key] = res
                self._publish(
                    "live_scan.scanner_completed",
                    {"scanner": spec.key, "ok": res.get("ok"),
                     "elapsed_s": res.get("elapsed_s"),
                     "summary": res.get("summary"),
                     "error": res.get("error")},
                )
            snapshot = {
                "ts": _now(),
                "trigger": trigger,
                "elapsed_s": round(time.time() - (self._started_at or time.time()), 2),
                "scanners": requested,
                "results": results,
                "ok_count": sum(1 for r in results.values() if r.get("ok")),
                "failed_count": sum(1 for r in results.values() if not r.get("ok")),
            }
            # merge with prior snapshot so periodic host data persists when an
            # on-demand network scan runs
            if self.last_snapshot:
                merged = dict(self.last_snapshot.get("results") or {})
                merged.update(results)
                snapshot["results"] = merged
            # privacy: scrub the snapshot so the engine actually enforces the
            # policy (no PII/secrets/private keys, data minimization). Fail-soft:
            # a sanitizer error never blocks an already-completed scan.
            snapshot = _privacy_scrub(snapshot, _privacy_policy_obj())
            self.last_snapshot = snapshot
            self.last_run_at = snapshot["ts"]
            # persist a trimmed snapshot (summaries, not full scanner payloads)
            # so it survives restarts without bloating the settings row
            trimmed = {
                **snapshot,
                "results": {
                    k: {kk: vv for kk, vv in res.items() if kk != "data"}
                    for k, res in snapshot["results"].items()
                },
            }
            # page-ready inventory is small and survives a restart so the
            # Hardware/Network/Libraries dashboards show the last real scan
            try:
                current_inv = self.inventory()
                # drift between this cycle and the previous one
                prev_for_drift = self._prev_inventory or self._persisted_prev_inventory()
                drift = self.compute_drift(prev_for_drift, current_inv)
                self.last_drift = drift
                if drift.get("change_count"):
                    self._publish("live_scan.drift",
                                  {"changes": drift["change_count"],
                                   "top": [c for c in drift["changes"][:10]]})
                current_inv["_prev"] = prev_for_drift  # enables drift after restart
                trimmed["inventory"] = current_inv
                self._prev_inventory = current_inv
            except Exception:  # noqa: BLE001
                trimmed["inventory"] = None
            self._persisted = _db_persist(trimmed)
            self._publish("live_scan.completed",
                          {"ts": snapshot["ts"], "elapsed_s": snapshot["elapsed_s"],
                           "ok": snapshot["ok_count"], "failed": snapshot["failed_count"],
                           "scanners": list(snapshot["results"].keys()),
                           "persisted": self._persisted})
            # Realtime pipeline: a completed scan may have changed the inventory
            # (crypto assets, certs, cloud/hardware res). Auto-sync the persisted
            # graph (Neo4j when configured) and publish a precise graph.updated
            # platform event so SSE consumers refresh without polling. Best-effort
            # — a graph/event failure must never fail the scan cycle.
            self._auto_sync_graph(trigger=trigger, requested=requested)
            return {"status": "completed", **snapshot}
        finally:
            self.running = False
            self._started_at = None

    # ------------------------------------------------------------- threading
    def start_cycle(self, **kwargs: Any) -> dict[str, Any]:
        with self._lock:
            if self.running:
                return {"status": "already_running"}
            t = threading.Thread(
                target=self._cycle_guard, kwargs=kwargs, daemon=True,
                name="live-scan-cycle",
            )
            t.start()
        return {"status": "started"}

    def _cycle_guard(self, **kwargs: Any) -> None:
        try:
            self.run_cycle(**kwargs)
        except Exception as exc:  # noqa: BLE001
            self._publish("live_scan.error", {"error": str(exc)})

    def start_periodic(self, interval: int | None = None) -> dict[str, Any]:
        if interval:
            self.interval = max(30, int(interval))
        if self._thread and self._thread.is_alive():
            return {"status": "already_running", "interval": self.interval}
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._periodic_loop, daemon=True, name="live-scan-loop",
        )
        self._thread.start()
        return {"status": "started", "interval": self.interval}

    def stop_periodic(self) -> dict[str, Any]:
        self._stop.set()
        return {"status": "stopping"}

    def load_persisted_snapshot(self) -> bool:
        """Restore the last snapshot from the settings table on startup so the
        UI shows the most recent real scan immediately. Returns True if one
        was loaded."""
        snap = _db_load_snapshot()
        if not snap:
            return False
        self.last_snapshot = snap
        self.last_run_at = snap.get("ts")
        return True

    # ------------------------------------------------------------------ inventory
    def inventory(self) -> dict[str, Any]:
        """Build page-ready structures for the dashboard pages from the most
        recent live snapshot (in-memory with full payloads, else the persisted
        summaries). Real scan data only — empty until a scan runs."""
        snap = self.last_snapshot or {}
        results: dict[str, Any] = snap.get("results") or {}

        def _data(key: str) -> dict[str, Any]:
            res = results.get(key) or {}
            return res.get("data") or {}

        devices: list[dict[str, Any]] = []
        firmware_rows: list[dict[str, Any]] = []
        hw = _data("hardware")
        if hw:
            host = (hw.get("host") or {}).get("hostname") or "this-host"
            cpu = hw.get("cpu") or {}
            tpm = hw.get("tpm") or {}
            hsm = hw.get("hsm") or {}
            sc = hw.get("smartcard") or {}
            caps = []
            if cpu.get("aes_acceleration"):
                caps.append("AES-NI")
            if cpu.get("sha_acceleration"):
                caps.append("SHA-NI")
            if cpu.get("hardware_rng"):
                caps.append("HW-RNG")
            devices.append({
                "id": f"{host}:cpu", "type": "CPU", "host": host,
                "vendor": cpu.get("vendor") or "",
                "firmware": f"microcode {cpu.get('microcode_version') or '?'}",
                "caps": caps,
                "status": "present",
            })
            firmware_rows.append({
                "device": cpu.get("model") or "CPU", "kind": "CPU microcode",
                "version": str(cpu.get("microcode_version") or "?"), "status": "current",
            })
            if tpm.get("present"):
                devices.append({
                    "id": f"{host}:tpm", "type": "TPM", "host": host,
                    "vendor": tpm.get("manufacturer") or "TPM",
                    "firmware": f"TPM {tpm.get('version') or '?'}",
                    "caps": ["key storage", "attestation"], "status": "present",
                })
                firmware_rows.append({
                    "device": f"TPM {tpm.get('version') or ''}".strip(), "kind": "TPM",
                    "version": str(tpm.get("version") or "?"), "status": "current",
                })
            if hsm.get("present"):
                devices.append({
                    "id": f"{host}:hsm", "type": "HSM", "host": host,
                    "vendor": "HSM", "firmware": hsm.get("kind") or "",
                    "caps": ["PKCS#11"], "status": "present",
                })
            if sc.get("present"):
                devices.append({
                    "id": f"{host}:smartcard", "type": "smart_card", "host": host,
                    "vendor": "PC/SC", "firmware": sc.get("interface") or "",
                    "caps": sc.get("pkcs11_middleware") or ["PC/SC"],
                    "status": "middleware (no card)",
                })

        net_assets: list[dict[str, Any]] = []
        certificates: list[dict[str, Any]] = []
        net = _data("network")
        for f in net.get("findings") or []:
            ep = f.get("endpoint") or ""
            crypto = f.get("crypto") or {}
            certs = f.get("certificates") or []
            leaf = certs[0] if certs else {}
            chain = f.get("chain_validation") or {}
            issues = f.get("policy_issues") or []
            net_assets.append({
                "kind": "tls_endpoint", "id": ep, "ip": ep,
                "tls": f"{crypto.get('tls_version') or '?'} {crypto.get('cipher_suite') or ''}".strip(),
                "certs": [c.get("subject") or "" for c in certs[:1]],
                "os": leaf.get("issuer") or "",
                "status": ("OK" if f.get("status") == "OK" and not issues else
                           (";" .join(issues) or f.get("status") or "?")),
                "cert_expiry_days": leaf.get("days_until_expiry"),
                "chain_valid": chain.get("is_valid"),
            })
            for i, c in enumerate(certs):
                days = c.get("days_until_expiry")
                certificates.append({
                    "cn": (c.get("subject") or "").replace("CN=", "").split(",")[0] or c.get("subject"),
                    "sig": c.get("signature_algorithm") or "?",
                    "key": f"{(c.get('public_key_algorithm') or '?')} {c.get('public_key_size') or ''}".strip(),
                    "days": days,
                    "san": ", ".join(c.get("san") or []) or "—",
                    "eku": ", ".join(c.get("extended_key_usage") or []) or ("serverAuth" if i == 0 else "CA"),
                    "owner": c.get("issuer") or "—",
                    "status": ("EXPIRED" if (days is not None and days < 0) else
                               ("EXPIRING" if (days is not None and days < 30) else
                                (c.get("expiry_status") or "VALID"))),
                    "endpoint": ep,
                    "chain_position": i,
                    "chain_length": len(certs),
                })
        # discovery sweep open endpoints — named + risk-scored via the
        # canonical network registry (passive classification, no extra probes)
        if net.get("cidr"):
            services_by_ep = {s.get("endpoint"): s for s in (net.get("services") or [])}
            for ep in net.get("endpoints") or []:
                svc = services_by_ep.get(ep) or {}
                proto = svc.get("protocol")
                status = "discovered"
                if proto:
                    svc_status = str(svc.get("status") or "")
                    sev = str(svc.get("severity") or "")
                    enc = "TLS" if svc.get("encrypted") else "cleartext"
                    status = f"{proto} · {enc} · {svc_status or sev or 'open'}"
                net_assets.append({
                    "kind": "discovered", "id": ep, "ip": ep,
                    "tls": proto or "open", "certs": [],
                    "os": svc.get("category") or "", "status": status,
                    "service": svc,
                })

        # runtime: crypto libraries (page-ready), aggregated from processes
        libraries: list[dict[str, Any]] = []
        rt = _data("runtime")
        lib_agg: dict[tuple, dict[str, Any]] = {}
        for p in rt.get("processes") or []:
            for d in p.get("library_details") or []:
                # ``library`` is the canonical name (e.g. "openssl");
                # ``library_name`` is a display label that may already include
                # the version, so use ``library`` for identity/dedup.
                name = d.get("library") or str(d.get("library_name") or "").split()[0]
                key = (name, d.get("version"))
                entry = lib_agg.setdefault(key, {
                    "name": name,
                    "version": d.get("version"), "status": d.get("status"),
                    "package": d.get("package"), "processes": 0})
                entry["processes"] += 1
        libraries = list(lib_agg.values())

        # runtime: processes + listeners (page-ready for Runtime hosts)
        processes: list[dict[str, Any]] = []
        for p in rt.get("processes") or []:
            statuses = {d.get("status") for d in (p.get("library_details") or [])}
            weak = bool(statuses & {"DISALLOWED", "DEPRECATED", "RESTRICTED"})
            processes.append({
                "pid": p.get("pid"),
                "process": p.get("process_name"),
                "runtime": p.get("runtime"),
                "tls_libraries": p.get("tls_libraries") or [],
                "listening_ports": p.get("listening_ports") or [],
                "containerized": p.get("containerized"),
                "status": "RISK" if weak else "OK",
            })

        # generic scan summaries for the remaining services (best-effort; the
        # summaries are produced per-scanner in _summarize, full payloads are
        # in the snapshot).
        extra: dict[str, Any] = {}
        for key in ("container", "cloud", "ot", "source", "universal"):
            res = results.get(key) or {}
            if res.get("ok"):
                extra[key] = {"summary": res.get("summary") or {},
                              "elapsed_s": res.get("elapsed_s")}

        cert_center = {
            "expired": sum(1 for c in certificates if c["status"] == "EXPIRED"),
            "expiring30": sum(1 for c in certificates if c["status"] == "EXPIRING"),
            "weak_algorithm": sum(1 for c in certificates
                                  if str(c.get("sig")).lower().startswith(("md5", "sha1"))),
            "unknown_owner": sum(1 for c in certificates if not c.get("owner") or c["owner"] == "—"),
            "total": len(certificates),
        }

        counts = {
            "hardware_devices": len(devices),
            "network_assets": len(net_assets),
            "libraries": len(libraries),
            "certificates": len(certificates),
            "processes": len(processes),
        }
        built = {
            "generated_at": snap.get("ts"),
            "host": (hw.get("host") or {}).get("hostname"),
            "counts": counts,
            "hardware": devices,
            "firmware": firmware_rows,
            "network": net_assets,
            "certificates": certificates,
            "cert_center": cert_center,
            "libraries": libraries,
            "processes": processes,
            "scans": extra,
        }
        # After a restart the in-memory snapshot only has summaries (full
        # payloads are not persisted); fall back to the page-ready inventory
        # captured at scan time until a new cycle repopulates full data.
        if sum(counts.values()) == 0 and isinstance(snap.get("inventory"), dict):
            return {k: v for k, v in snap["inventory"].items() if k != "_prev"}
        return built

    # ------------------------------------------------------------------ alerts
    def alerts(self) -> dict[str, Any]:
        """Deterministic, cross-scanner risk aggregation. Derives alerts from
        the page-ready inventory (so it also works after a restart) plus the
        per-scanner summaries/errors in the latest snapshot."""
        inv = self.inventory()
        ts = inv.get("generated_at")
        out: list[dict[str, Any]] = []
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        def add(severity: str, scanner: str, kind: str, title: str,
                detail: str, asset: str = "") -> None:
            out.append({"severity": severity, "scanner": scanner, "kind": kind,
                        "title": title, "detail": detail, "asset": asset, "ts": ts})

        # runtime libraries
        for lib in inv.get("libraries", []):
            st = (lib.get("status") or "").upper()
            if st in ("DISALLOWED",):
                add("CRITICAL", "runtime", "WEAK_LIBRARY",
                    f"Disallowed crypto library {lib.get('name')} {lib.get('version') or ''}".strip(),
                    f"EOL/banned library in use across {lib.get('processes') or 0} process(es)",
                    asset=str(lib.get("package") or ""))
            elif st in ("DEPRECATED", "RESTRICTED"):
                add("HIGH", "runtime", "DEPRECATED_LIBRARY",
                    f"Deprecated library {lib.get('name')} {lib.get('version') or ''}".strip(),
                    f"Near/at end-of-life; plan upgrade ({lib.get('processes') or 0} process(es))",
                    asset=str(lib.get("package") or ""))
            elif st == "UNKNOWN":
                add("LOW", "runtime", "UNMANAGED_LIBRARY",
                    f"Unmanaged {lib.get('name')} library",
                    "Version cannot be resolved (bundled/venv/static) — review manually")

        # runtime processes at risk
        for p in inv.get("processes", []):
            if p.get("status") == "RISK":
                add("HIGH", "runtime", "RISK_PROCESS",
                    f"Process {p.get('process')} (pid {p.get('pid')}) uses a weak library",
                    f"libs: {', '.join(p.get('tls_libraries') or [])}",
                    asset=f"{p.get('process')}:{p.get('pid')}")

        # network endpoints
        for n in inv.get("network", []):
            status = n.get("status") or ""
            asset = n.get("id") or ""
            if "WEAK_TLS" in status or "DISALLOWED_CIPHER" in status:
                add("HIGH", "network", "WEAK_TLS",
                    f"Weak TLS/cipher accepted on {asset}", f"{status}; {n.get('tls')}")
            elif "CBC" in status:
                add("MEDIUM", "network", "CBC_CIPHER",
                    f"CBC-mode ciphers accepted on {asset}",
                    "Lucky13 timing hardening — restrict to GCM/ChaCha20 (TLS 1.2+)")
            if n.get("chain_valid") is False:
                add("HIGH", "network", "CHAIN_INVALID",
                    f"Certificate chain invalid on {asset}", "chain validation failed")

        # certificate inventory (authoritative for expiry/signature alerts)
        for c in inv.get("certificates", []):
            if c.get("status") == "EXPIRED":
                add("CRITICAL", "certificates", "CERT_EXPIRED",
                    f"Expired certificate {c.get('cn')}", f"endpoint {c.get('endpoint')}")
            elif c.get("status") == "EXPIRING":
                add("MEDIUM", "certificates", "CERT_EXPIRING",
                    f"Certificate {c.get('cn')} expiring", f"{c.get('days')} days ({c.get('endpoint')})")
            sig = str(c.get("sig") or "").lower()
            if sig.startswith(("md5", "sha1")):
                add("HIGH", "certificates", "WEAK_SIGNATURE",
                    f"Weak signature on {c.get('cn')}", f"{c.get('sig')} ({c.get('endpoint')})")

        # hardware root-of-trust
        hw_types = {d.get("type") for d in inv.get("hardware", [])}
        if inv.get("hardware") and "TPM" not in hw_types:
            add("LOW", "hardware", "TPM_ABSENT",
                "No TPM detected on host",
                "No hardware root of trust for key storage/attestation (check BIOS)")

        # source/container/universal static findings (counts from summaries)
        scans = inv.get("scans") or {}
        for svc, block in scans.items():
            s = block.get("summary") or {}
            if s.get("high"):
                add("HIGH", svc, "STATIC_FINDINGS",
                    f"{svc} scan: {s.get('high')} high-confidence finding(s)",
                    f"files={s.get('files_scanned') or '?'} findings={s.get('findings') or '?'}")
            elif s.get("findings"):
                add("MEDIUM", svc, "STATIC_FINDINGS",
                    f"{svc} scan: {s.get('findings')} finding(s)",
                    f"files={s.get('files_scanned') or '?'}")

        # failed scanners (operational)
        for key, res in (self.last_snapshot or {}).get("results", {}).items():
            if isinstance(res, dict) and res.get("ok") is False and res.get("error"):
                add("LOW", key, "SCANNER_ERROR",
                    f"{key} scan failed", str(res.get("error"))[:180])

        out.sort(key=lambda a: sev_rank.get(a["severity"], 9))
        counts = {sev: sum(1 for a in out if a["severity"] == sev)
                  for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        return {"generated_at": ts, "counts": counts, "alerts": out, "total": len(out)}


    # ------------------------------------------------------------------ drift
    def compute_drift(self, prev: dict[str, Any] | None,
                      curr: dict[str, Any]) -> dict[str, Any]:
        """Deterministically compare two page-ready inventories and report
        crypto-relevant changes. First scan (no baseline) reports no drift."""
        changes: list[dict[str, Any]] = []
        if not prev:
            return {"baseline": False, "ts": curr.get("generated_at"),
                    "changes": changes, "change_count": 0}

        def _idx(items: list[dict[str, Any]], key: str) -> dict[str, Any]:
            return {str(i.get(key) or i.get("id") or i.get("cn")): i for i in items or []}

        # hardware devices (by id)
        ph = _idx(prev.get("hardware") or [], "id")
        for d in curr.get("hardware") or []:
            if d.get("id") not in ph:
                changes.append({"severity": "MEDIUM", "scanner": "hardware",
                                "kind": "DEVICE_ADDED",
                                "title": f"New hardware device: {d.get('type')} {d.get('id')}",
                                "detail": f"caps: {', '.join(d.get('caps') or [])}"})
        for pid, d in ph.items():
            if pid not in _idx(curr.get("hardware") or [], "id"):
                changes.append({"severity": "HIGH", "scanner": "hardware",
                                "kind": "DEVICE_REMOVED",
                                "title": f"Hardware device removed: {d.get('type')} {pid}",
                                "detail": "a previously-seen crypto device is no longer present"})

        # crypto libraries (by name|version)
        def _libkey(l: dict[str, Any]) -> str:
            return f"{l.get('name')}|{l.get('version')}"
        plibs = {_libkey(l): l for l in prev.get("libraries") or []}
        clibs = {_libkey(l): l for l in curr.get("libraries") or []}
        for k, l in clibs.items():
            if k not in plibs:
                sev = "HIGH" if (l.get("status") in ("DISALLOWED", "RESTRICTED")) else \
                      "MEDIUM" if l.get("status") == "DEPRECATED" else "LOW"
                changes.append({"severity": sev, "scanner": "runtime",
                                "kind": "LIBRARY_ADDED",
                                "title": f"New library in use: {l.get('name')} {l.get('version') or ''}",
                                "detail": f"status={l.get('status')} package={l.get('package') or 'unmanaged'}",
                                "asset": _libkey(l)})
        for k, l in plibs.items():
            if k not in clibs:
                changes.append({"severity": "LOW", "scanner": "runtime",
                                "kind": "LIBRARY_REMOVED",
                                "title": f"Library no longer in use: {l.get('name')} {l.get('version') or ''}",
                                "detail": f"was status={l.get('status')}", "asset": _libkey(l)})
        # status reclassification for the same name+version (e.g. policy update
        # marks a previously-ALLOWED library DEPRECATED). A new *version* of the
        # same library is already covered above as LIBRARY_ADDED/REMOVED.
        for k, l in clibs.items():
            old = plibs.get(k)
            if old and old.get("status") != l.get("status"):
                sev = "HIGH" if l.get("status") in ("DISALLOWED", "RESTRICTED") else "MEDIUM"
                changes.append({"severity": sev, "scanner": "runtime",
                                "kind": "LIBRARY_STATUS_CHANGED",
                                "title": f"{l.get('name')} {l.get('version')} status {old.get('status')} → {l.get('status')}",
                                "detail": f"package {l.get('package')}", "asset": k})

        # network endpoints (by id)
        pnet = _idx(prev.get("network") or [], "id")
        cnet = _idx(curr.get("network") or [], "id")
        for nid, n in cnet.items():
            old = pnet.get(nid)
            if not old:
                changes.append({"severity": "MEDIUM", "scanner": "network",
                                "kind": "ENDPOINT_ADDED",
                                "title": f"New TLS endpoint: {nid}",
                                "detail": n.get("tls") or "", "asset": nid})
            elif old.get("status") != n.get("status"):
                sev = "HIGH" if n.get("status") and n["status"] != "OK" else "LOW"
                changes.append({"severity": sev, "scanner": "network",
                                "kind": "ENDPOINT_STATUS_CHANGED",
                                "title": f"Endpoint posture changed: {nid}",
                                "detail": f"{old.get('status')} → {n.get('status')}", "asset": nid})
        for nid in pnet:
            if nid not in cnet:
                changes.append({"severity": "LOW", "scanner": "network",
                                "kind": "ENDPOINT_REMOVED",
                                "title": f"TLS endpoint gone: {nid}", "detail": "", "asset": nid})

        # certificates (by cn|endpoint)
        def _ckey(c: dict[str, Any]) -> str:
            return f"{c.get('cn')}|{c.get('endpoint')}"
        pcerts = {_ckey(c): c for c in prev.get("certificates") or []}
        for c in curr.get("certificates") or []:
            if _ckey(c) not in pcerts:
                changes.append({"severity": "LOW", "scanner": "certificates",
                                "kind": "CERT_OBSERVED",
                                "title": f"Certificate observed: {c.get('cn')} ({c.get('endpoint')})",
                                "detail": f"{c.get('sig')} · {c.get('days')}d"})

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        changes.sort(key=lambda c: order.get(c["severity"], 9))
        return {"baseline": True, "ts": curr.get("generated_at"),
                "previous_ts": prev.get("generated_at"),
                "changes": changes, "change_count": len(changes)}

    def drift(self) -> dict[str, Any]:
        """Latest drift between consecutive live cycles (persisted-safe)."""
        if self.last_drift:
            return self.last_drift
        snap = self.last_snapshot or {}
        inv = snap.get("inventory") if isinstance(snap.get("inventory"), dict) else None
        prev = (inv or {}).get("_prev") if inv else None
        if prev:
            return self.compute_drift(prev, inv or {})
        return {"baseline": False, "changes": [], "change_count": 0}

    def _persisted_prev_inventory(self) -> dict[str, Any] | None:
        """The previous inventory stored in the persisted snapshot — lets drift
        keep working across an API restart."""
        snap = self.last_snapshot or {}
        inv = snap.get("inventory") if isinstance(snap.get("inventory"), dict) else None
        prev = (inv or {}).get("_prev")
        return prev if isinstance(prev, dict) else None

    # ------------------------------------------------------------------ bom
    def bom(self) -> dict[str, Any]:
        """Cryptographic Bill of Materials (CBOM) and Hardware Bill of Materials
        (HBOM) assembled from the live scans. Real components only; quantum
        verdicts come from the universal crypto classifier (left null where no
        classifier ran, rather than guessed)."""
        snap = self.last_snapshot or {}
        results: dict[str, Any] = snap.get("results") or {}

        def _data(key: str) -> dict[str, Any]:
            return (results.get(key) or {}).get("data") or {}

        components: list[dict[str, Any]] = []

        # 1. algorithms + quantum classifications from the universal scanner
        uni = _data("universal")
        uni_report = uni.get("report") if isinstance(uni.get("report"), dict) else uni
        for algo, klass in (uni_report.get("quantum_classifications") or {}).items():
            components.append({
                "type": "algorithm", "name": algo, "version": "",
                "ref": klass.get("quantum_status"),
                "quantum_status": klass.get("quantum_status"),
                "migration_priority": klass.get("migration_priority"),
                "classical_status": klass.get("classical_status"),
                "source": "universal",
            })

        # 2. crypto libraries observed on the host (runtime)
        inv = self.inventory()
        for lib in inv.get("libraries", []):
            components.append({
                "type": "library", "name": lib.get("name"),
                "version": lib.get("version"), "ref": lib.get("package") or "unmanaged",
                "quantum_status": None, "migration_priority": None,
                "status": lib.get("status"), "source": "runtime",
            })

        # 3. crypto packages found in containers/images
        ctr = _data("container")
        for pkg in ctr.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name") or pkg.get("canonical_name")
            if not name:
                continue
            components.append({
                "type": "package", "name": name,
                "version": pkg.get("version"), "ref": pkg.get("manager") or "image",
                "quantum_status": None, "migration_priority": None,
                "algorithms": pkg.get("algorithms") or [],
                "deprecated": pkg.get("deprecated"), "source": "container",
            })

        # de-duplicate by (type, name, version)
        seen: set[tuple] = set()
        uniq: list[dict[str, Any]] = []
        for c in components:
            k = (c["type"], c.get("name"), c.get("version"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(c)

        def _quantum_bad(c: dict[str, Any]) -> bool:
            q = str(c.get("quantum_status") or "").lower()
            return ("vulnerable" in q or "broken" in q or "at_risk" in q) and "safe" not in q

        quantum_vulnerable = sum(1 for c in uniq if _quantum_bad(c))

        # HBOM: hardware devices
        hbom_components = [
            {"type": d.get("type"), "name": d.get("vendor") or d.get("type"),
             "version": d.get("firmware"), "ref": d.get("host"),
             "caps": d.get("caps"), "source": "hardware"}
            for d in inv.get("hardware", [])
        ]

        return {
            "generated_at": snap.get("ts"),
            "cbom": {
                "components": uniq,
                "counts": {
                    "total": len(uniq),
                    "algorithms": sum(1 for c in uniq if c["type"] == "algorithm"),
                    "libraries": sum(1 for c in uniq if c["type"] == "library"),
                    "packages": sum(1 for c in uniq if c["type"] == "package"),
                    "quantum_vulnerable": quantum_vulnerable,
                },
            },
            "hbom": {
                "components": hbom_components,
                "counts": {"total": len(hbom_components)},
            },
        }

    def _periodic_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_cycle(trigger="scheduled")
            except Exception as exc:  # noqa: BLE001
                self._publish("live_scan.error", {"error": str(exc)})
            # interruptible sleep
            self._stop.wait(timeout=self.interval)


_runner: Optional[LiveScanRunner] = None
_runner_guard = threading.Lock()


def get_live_scan_runner() -> LiveScanRunner:
    global _runner
    if _runner is None:
        with _runner_guard:
            if _runner is None:
                _runner = LiveScanRunner()
    return _runner
