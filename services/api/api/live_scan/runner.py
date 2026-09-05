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
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


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
    except Exception:  # noqa: BLE001
        return None


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
            return {
                "crypto_processes": data.get("crypto_processes"),
                "total_processes_scanned": data.get("total_processes_scanned"),
                "kernel_threads_skipped": data.get("kernel_threads_skipped"),
                "libraries": data.get("current_libraries"),
                "risky_libraries": data.get("risky_libraries"),
                "listening_endpoints": data.get("listening_endpoints"),
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

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        try:
            from api.events.bus import get_event_bus

            get_event_bus().publish(event_type, payload, source="live-scanner")
        except Exception:  # noqa: BLE001 — event failure must never kill a scan
            pass

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
            self._persisted = _db_persist(trimmed)
            self._publish("live_scan.completed",
                          {"ts": snapshot["ts"], "elapsed_s": snapshot["elapsed_s"],
                           "ok": snapshot["ok_count"], "failed": snapshot["failed_count"],
                           "scanners": list(snapshot["results"].keys()),
                           "persisted": self._persisted})
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
