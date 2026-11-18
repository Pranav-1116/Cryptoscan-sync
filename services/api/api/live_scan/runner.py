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

import hashlib
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


def _enabled(value: Any) -> bool:
    """Interpret operator boolean environment flags without treating '0' as on."""
    if value is None or value is False or value == "":
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", "disabled"}
    return bool(value)


# These are scanner families, not just output labels. Keeping the registry in
# the live runner makes an unconfigured/blocked family visible instead of
# silently disappearing from a cycle. The individual scanner still owns its
# result schema and provenance.
LIVE_SCANNER_FAMILIES: tuple[str, ...] = (
    "vendor", "universal", "source", "runtime", "hardware", "network",
    "cloud", "container", "ot", "telecom", "payment", "keyassure",
    "binary", "devsecops",
)


#: well-known app_settings key under which the latest live-scan snapshot is
#: persisted, so results survive an API restart and can feed pages directly.
SNAPSHOT_SETTING_KEY = "live_scan.last_snapshot"


def _setting_key(base: str, tenant_id: str | None) -> str:
    # AppSetting historically has a globally unique key. Namespacing keeps
    # legacy platform settings intact while making worker writes tenant-safe.
    return f"{base}:{tenant_id}" if tenant_id else base


def _persist_live_projection(snapshot: dict[str, Any], tenant_id: str | None) -> None:
    """Persist the normalized cross-scanner projection and event journal.

    This is deliberately fed by the bounded, privacy-scrubbed snapshot rather
    than by a scanner-specific repository. Every source therefore lands in the
    same tenant-scoped replay surface; a scanner cannot silently maintain a
    second realtime truth. No key material is written: only CBOM metadata,
    finding metadata, and evidence references are retained.
    """
    live = snapshot.get("live_cbom") or {}
    cbom = live.get("cbom") if isinstance(live, dict) else {}
    dependency_graph = live.get("dependency_graph") if isinstance(live, dict) else None
    components = cbom.get("components") if isinstance(cbom, dict) else []
    if not isinstance(components, list):
        components = []
    findings = list(snapshot.get("scanner_findings") or [])
    if not isinstance(findings, list):
        findings = []
    alerts = (snapshot.get("alerts") or {}).get("alerts") if isinstance(snapshot.get("alerts"), dict) else []
    if isinstance(alerts, list):
        findings.extend({"scanner": alert.get("scanner") or "live-alert", **alert} for alert in alerts)
    from db.connection.session import SessionLocal
    from db.repositories.crypto_repository import CryptoRepository
    from db.models.crypto_live import CryptoLiveState
    from sqlalchemy import delete

    # Storage asset ids are tenant-qualified because older deployments have a
    # global unique constraint on crypto_live_states.asset_id. The original
    # scanner asset remains in the CBOM payload and API detail.
    prefix = tenant_id or "platform"
    live_prefix = f"{prefix}:live:"
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        source = str(component.get("source") or "unknown")
        kind = str(component.get("type") or "crypto-asset")
        name = str(component.get("name") or "")
        version = str(component.get("version") or "")
        if not name:
            continue
        groups.setdefault((source, kind, name, version), []).append(component)

    with SessionLocal() as session:
        # Current-state rows from the API live plane are replaced atomically;
        # the immutable event rows below preserve replay/history.
        session.execute(delete(CryptoLiveState).where(
            CryptoLiveState.asset_id.like(f"{live_prefix}%"),
            CryptoLiveState.tenant_id == tenant_id if tenant_id is not None
            else CryptoLiveState.tenant_id.is_(None),
        ))
        session.flush()
        repo = CryptoRepository(session)
        for (source, kind, name, version), rows in groups.items():
            asset_id = f"{live_prefix}{source}:{kind}:{name}:{version}"[:200]
            state = {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "cbom_version": int(cbom.get("version") or 1) if isinstance(cbom, dict) else 1,
                "algorithms": [row.get("name") for row in rows if row.get("type") == "algorithm"],
                "quantum_status": {row.get("name"): row.get("quantum_status")
                                   for row in rows if row.get("quantum_status")},
                "capabilities": [row for row in rows if row.get("type") == "capability"],
                "usage": {"scanner": source, "component_type": kind, "component_name": name},
                "protocols": [row for row in rows if row.get("type") == "protocol"],
                "certificates": [row for row in rows if row.get("type") == "certificate"],
                "libraries": [row for row in rows if row.get("type") in {"library", "package", "dependency"}],
                "readiness": None,
                "agility": None,
                "cbom": {"components": rows, "source": source, "asset_id": asset_id,
                         "dependency_graph": dependency_graph},
                "last_event": "SCANNER_OBSERVED",
                "last_seen": snapshot.get("ts"),
            }
            repo.upsert_state(state)
            for row in rows:
                repo.append_event({
                    "tenant_id": tenant_id,
                    "event_type": "SCANNER_OBSERVED",
                    "asset_id": asset_id,
                    "source": source,
                    "observed_at": row.get("observed_at") or snapshot.get("ts"),
                    "cbom_version": state["cbom_version"],
                    "payload": {"component": row, "evidence_reference": row.get("evidence_reference")},
                })
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            source = str(finding.get("scanner") or finding.get("source") or "unknown")
            asset = str(finding.get("asset_id") or finding.get("asset") or source)
            repo.append_event({
                "tenant_id": tenant_id,
                "event_type": "SCANNER_FINDING",
                "asset_id": f"{prefix}:{source}:{asset}"[:200],
                "source": source,
                "observed_at": finding.get("observed_at") or snapshot.get("ts"),
                "cbom_version": int(cbom.get("version") or 1) if isinstance(cbom, dict) else 1,
                "risk_score": finding.get("risk_score"),
                "payload": finding,
            })
        session.commit()


def _db_persist(snapshot: dict[str, Any], tenant_id: str | None = None) -> bool:
    """Write settings and normalized live state. Never claim durable success
    unless both the tenant snapshot and the cross-scanner journal commit."""
    settings_ok = False
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            SettingsRepository(session).set(
                _setting_key(SNAPSHOT_SETTING_KEY, tenant_id),
                snapshot,
                updated_by="live-scanner",
                tenant_id=tenant_id,
            )
            session.commit()
        settings_ok = True
    except Exception as exc:  # noqa: BLE001
        logger.warning("live_snapshot_persist_failed", extra={"error_type": type(exc).__name__})
        return False
    try:
        _persist_live_projection(snapshot, tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("live_projection_persist_failed", extra={"error_type": type(exc).__name__})
        return False
    return settings_ok


def _db_load_snapshot(tenant_id: str | None = None) -> dict[str, Any] | None:
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            snap = SettingsRepository(session).get(
                _setting_key(SNAPSHOT_SETTING_KEY, tenant_id),
                tenant_id=tenant_id,
            )
        return snap if isinstance(snap, dict) else None
    except Exception as _handler_exc:  # noqa: BLE001
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


def _merge_network_data(prev: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Union of two network observation payloads keyed by stable identity.

    A targeted scan replaces the same endpoint's prior observation and adds
    new endpoints, so the dashboards accumulate every real observation
    instead of showing only the most recent call. Lists are capped so a
    long-lived estate cannot grow the settings row without bound.
    """
    merged = dict(new)
    for field, ident_key, cap in (("findings", "endpoint", 1000),
                                  ("services", "endpoint", 1000),
                                  ("certificates", "fingerprint_sha256", 500)):
        combined: dict[str, Any] = {}
        order: list[str] = []
        for item in (prev.get(field) or []) + (new.get(field) or []):
            if not isinstance(item, dict):
                continue
            ident = item.get(ident_key)
            if not ident:
                continue
            if ident not in combined:
                order.append(ident)
            combined[ident] = item
        if combined:
            merged[field] = [combined[k] for k in order[-cap:]]
    endpoints = list(dict.fromkeys(
        (prev.get("endpoints") or []) + (new.get("endpoints") or [])))[:1000]
    if endpoints:
        merged["endpoints"] = endpoints
    if prev.get("cidr") and not new.get("cidr"):
        merged["cidr"] = prev["cidr"]
    return merged


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
        self._cancel_requested = threading.Event()
        self.interval: int = int(os.environ.get("CRYPTOSCAN_LIVE_INTERVAL", "900"))
        self.last_snapshot: dict[str, Any] | None = None
        self._tenant_snapshots: dict[str, dict[str, Any]] = {}
        self.last_run_at: str | None = None
        self.running: bool = False
        self._started_at: float | None = None
        self._run_tenant_id: str | None = None
        self._loaded_tenant_id: str | None = None
        self._periodic_tenant_id: str | None = None
        self._persisted: bool = False
        self._prev_inventory: dict[str, Any] | None = None
        self.last_drift: dict[str, Any] | None = None

    @staticmethod
    def _tenant_cache_key(tenant_id: str | None) -> str:
        return tenant_id or "__platform__"

    def snapshot_for_tenant(self, tenant_id: str | None = None) -> dict[str, Any] | None:
        """Return only the requested tenant's in-memory snapshot."""
        return self._tenant_snapshots.get(self._tenant_cache_key(tenant_id))

    def _snapshot_for_current_run(self) -> dict[str, Any] | None:
        return self.last_snapshot

    # ------------------------------------------------------------------ specs
    def _specs(
        self,
        *,
        only: list[str] | None = None,
        targets: dict[str, Any] | None = None,
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
            argv = [py, "-m", "network_scanner.realtime_cli", net_target]
            if _enabled(targets.get("network_ipsec")) or _enabled(env.get("CRYPTOSCAN_LIVE_NETWORK_IPSEC")):
                argv += ["--ipsec"]
            if _enabled(targets.get("network_dnssec")) or _enabled(env.get("CRYPTOSCAN_LIVE_NETWORK_DNSSEC")):
                argv += ["--dnssec"]
            if _enabled(targets.get("network_full")) or _enabled(env.get("CRYPTOSCAN_LIVE_NETWORK_FULL")):
                argv += ["--full"]
            specs.append(ScannerSpec(
                "network", argv,
                cwd=str(root / "services/network_scanner"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_NETWORK_TARGET")),
                needs_target=True, timeout=120,
            ))
        ctr_target = targets.get("container") or env.get("CRYPTOSCAN_LIVE_CONTAINER_TARGET")
        if ctr_target:
            specs.append(ScannerSpec(
                "container",
                [py, "-m", "container_scanner.main", ctr_target],
                cwd=str(root / "services/container_scanner"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_CONTAINER_TARGET")),
                needs_target=True, timeout=300,
            ))
        ot_target = targets.get("ot_logs") or env.get("CRYPTOSCAN_LIVE_OT_TARGET")
        if ot_target:
            specs.append(ScannerSpec(
                "ot",
                [py, "-m", "ot_scanner.main", ot_target],
                cwd=str(root / "services/ot_scanner"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_OT_TARGET")),
                needs_target=True, timeout=180,
            ))
        # telecom: registry-backed 3GPP/TLS/IPsec posture scan. The scanner
        # itself distinguishes observed, unavailable and operator-ingest-only
        # IPsec evidence; the runner does not synthesize NFs.
        telecom_registry = targets.get("telecom") or env.get("CRYPTOSCAN_LIVE_TELECOM")
        if telecom_registry:
            telecom_argv = [py, "-m", "telecom_scanner.main", "--json"]
            if str(telecom_registry) not in {"1", "true", "TRUE"}:
                telecom_argv += ["--registry", str(telecom_registry)]
            specs.append(ScannerSpec(
                "telecom", telecom_argv,
                cwd=str(root / "services/telecom_scanner"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_TELECOM")),
                needs_target=True, timeout=300,
            ))
        # payment/HSM: a real operator-supplied audit-feed adapter. The feed
        # config is passed by path so credentials never enter scan snapshots.
        payment_config = targets.get("payment") or env.get("CRYPTOSCAN_LIVE_PAYMENT_CONFIG")
        if payment_config:
            specs.append(ScannerSpec(
                "payment",
                [py, "-m", "payment_crypto.cli", "--config", str(payment_config)],
                cwd=str(root / "services/payment_crypto"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_PAYMENT_CONFIG")),
                needs_target=True, timeout=180,
            ))
        keyassure_config = targets.get("keyassure") or env.get("CRYPTOSCAN_LIVE_KEYASSURE_TARGET")
        if keyassure_config:
            specs.append(ScannerSpec(
                "keyassure",
                [py, "-m", "keyassure.realtime_cli", "--config", str(keyassure_config)],
                cwd=str(root / "services/keyassure"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_KEYASSURE_TARGET")),
                needs_target=True, timeout=180,
            ))
        binary_target = targets.get("binary") or env.get("CRYPTOSCAN_LIVE_BINARY_TARGET")
        if binary_target:
            specs.append(ScannerSpec(
                "binary",
                [py, "-m", "devsecops.realtime_cli", str(binary_target)],
                cwd=str(root / "services/devsecops"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_BINARY_TARGET")),
                needs_target=True, timeout=600,
            ))
        devsecops_target = targets.get("devsecops") or env.get("CRYPTOSCAN_LIVE_DEVSECOPS_TARGET")
        if devsecops_target:
            specs.append(ScannerSpec(
                "devsecops",
                [py, "-m", "devsecops.realtime_cli", str(devsecops_target)],
                cwd=str(root / "services/devsecops"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_DEVSECOPS_TARGET")),
                needs_target=True, timeout=600,
            ))
        # cloud: live read-only scan — needs cloud creds in the API env
        if _enabled(targets.get("cloud_live")) or _enabled(env.get("CRYPTOSCAN_LIVE_CLOUD")):
            specs.append(ScannerSpec(
                "cloud",
                [py, "-m", "cloud_scanner.main", ".", "--live"],
                cwd=str(root / "services/cloud_scanner"),
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_CLOUD")),
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
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_SOURCE_TARGET")),
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
                periodic=_enabled(env.get("CRYPTOSCAN_LIVE_UNIVERSAL_TARGET")),
                needs_target=True, timeout=600,
            ))
        if only:
            specs = [s for s in specs if s.key in only]
        return specs

    def _periodic_specs(self) -> list[ScannerSpec]:
        # include only scanners configured to repeat (host set + env targets)
        return [s for s in self._specs() if s.periodic]

    @staticmethod
    def _scanner_availability(
        targets: dict[str, Any] | None = None,
        *,
        only: list[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Report configuration state for every crypto scanner family.

        ``UNCONFIGURED`` is intentionally different from ``FAIL`` and
        ``UNAVAILABLE``. A family is never represented by an empty fabricated
        result just because its operator has not supplied a target or a
        credential/configuration reference.
        """
        configured = {"vendor": True, "hardware": True, "runtime": True}
        targets = targets or {}
        env = os.environ
        target_keys = {
            "network": (targets.get("network") or env.get("CRYPTOSCAN_LIVE_NETWORK_TARGET")),
            "cloud": (targets.get("cloud_live") or env.get("CRYPTOSCAN_LIVE_CLOUD")),
            "container": (targets.get("container") or env.get("CRYPTOSCAN_LIVE_CONTAINER_TARGET")),
            "ot": (targets.get("ot_logs") or env.get("CRYPTOSCAN_LIVE_OT_TARGET")),
            "source": (targets.get("source") or env.get("CRYPTOSCAN_LIVE_SOURCE_TARGET")),
            "universal": (targets.get("universal") or env.get("CRYPTOSCAN_LIVE_UNIVERSAL_TARGET")),
            "telecom": (targets.get("telecom") or env.get("CRYPTOSCAN_LIVE_TELECOM")),
            "payment": (targets.get("payment") or env.get("CRYPTOSCAN_LIVE_PAYMENT_CONFIG")),
            "keyassure": (targets.get("keyassure") or env.get("CRYPTOSCAN_LIVE_KEYASSURE_TARGET")),
            "binary": (targets.get("binary") or env.get("CRYPTOSCAN_LIVE_BINARY_TARGET")),
            "devsecops": (targets.get("devsecops") or env.get("CRYPTOSCAN_LIVE_DEVSECOPS_TARGET")),
        }
        configured.update({key: _enabled(value) for key, value in target_keys.items()})
        result: dict[str, dict[str, Any]] = {}
        for family in LIVE_SCANNER_FAMILIES:
            if configured.get(family):
                result[family] = {"status": "CONFIGURED", "reason": None}
            else:
                result[family] = {
                    "status": "UNCONFIGURED",
                    "reason": "operator target, registry, credential, or scanner configuration not supplied",
                }
        if only:
            unknown = sorted(set(only) - set(LIVE_SCANNER_FAMILIES))
            for family in unknown:
                result[family] = {"status": "UNAVAILABLE", "reason": "unknown scanner family"}
        return result

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
                # Some real adapters emit a structured FAIL/BLOCKED result
                # and use a non-zero exit code. Preserve that payload so
                # unavailable, blocked and failed remain distinguishable.
                if proc.returncode != 0 and out_dir is None:
                    try:
                        structured = json.loads(proc.stdout) if proc.stdout.strip() else None
                    except json.JSONDecodeError:
                        structured = None
                    if isinstance(structured, dict) and structured.get("scan_status"):
                        scan_status = str(structured.get("scan_status")).upper()
                        return {
                            "scanner": spec.key,
                            "ok": scan_status in {"PASS", "DEGRADED"},
                            "status": scan_status,
                            "elapsed_s": elapsed,
                            "summary": self._summarize(spec.key, structured),
                            "data": structured,
                            "error": structured.get("error"),
                        }
                    return {"scanner": spec.key, "ok": False, "status": "FAIL",
                            "error": (proc.stderr or "non-zero exit").strip()[-400:],
                            "elapsed_s": elapsed}
                data: dict[str, Any] = {}
                if out_dir is not None:
                    files = sorted(Path(out_dir).glob(spec.output_glob),
                                   key=lambda p: p.stat().st_mtime, reverse=True)
                    if not files:
                        return {"scanner": spec.key, "ok": False, "status": "FAIL",
                                "error": "scanner produced no output file",
                                "elapsed_s": elapsed}
                    data = json.loads(files[0].read_text())
                else:
                    data = json.loads(proc.stdout) if proc.stdout.strip() else {}
                scan_status = str(
                    data.get("scan_status") or data.get("result_status") or "PASS"
                ).upper() if isinstance(data, dict) else "PASS"
                if isinstance(data, dict) and data.get("blocked_reason"):
                    scan_status = "BLOCKED"
                elif isinstance(data, dict) and data.get("stopped"):
                    scan_status = "BLOCKED"
                return {"scanner": spec.key, "ok": scan_status in {"PASS", "DEGRADED"},
                        "status": scan_status, "elapsed_s": elapsed,
                        "summary": self._summarize(spec.key, data), "data": data}
            except subprocess.TimeoutExpired:
                return {"scanner": spec.key, "ok": False, "status": "FAIL",
                        "error": f"timed out after {spec.timeout}s",
                        "elapsed_s": spec.timeout}
            except FileNotFoundError as exc:
                return {"scanner": spec.key, "ok": False, "status": "UNAVAILABLE",
                        "error": f"scanner not found: {exc}", "elapsed_s": 0.0}
            except json.JSONDecodeError as exc:
                return {"scanner": spec.key, "ok": False, "status": "FAIL",
                        "error": f"scanner did not emit JSON: {exc}",
                        "elapsed_s": round(time.time() - started, 2)}

        try:
            if spec.output_dir:
                with tempfile.TemporaryDirectory(prefix="cryptoscan-live-") as td:
                    return _execute(td)
            return _execute(None)
        except Exception as exc:  # noqa: BLE001 — never let one scanner kill the cycle
            return {"scanner": spec.key, "ok": False, "status": "FAIL",
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
        if key == "telecom":
            rows = data.get("rows") or []
            return {
                "targets_registered": data.get("targets_registered"),
                "observations": len(rows),
                "events": len(data.get("events") or []),
                "critical": sum(1 for row in rows if str(row.get("severity") or "").lower() == "critical"),
                "high": sum(1 for row in rows if str(row.get("severity") or "").lower() == "high"),
            }
        if key == "payment":
            return {
                "observations": len(data.get("observations") or []),
                "findings": len(data.get("findings") or []),
                "accepted": data.get("accepted"),
                "cursor": data.get("cursor"),
            }
        if key in {"keyassure", "binary", "devsecops"}:
            return {
                "observations": len(data.get("observations") or data.get("findings") or []),
                "findings": len(data.get("findings") or []),
            }
        if key == "ot":
            return {"events": data.get("events_count") or len(data.get("events") or [])}
        return {}

    @staticmethod
    def _extract_scanner_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize explicit findings/alerts without inventing evidence."""
        findings: list[dict[str, Any]] = []
        for scanner, result in results.items():
            if not isinstance(result, dict):
                continue
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            for key in ("findings", "alerts", "policy_findings", "vulnerabilities"):
                values = data.get(key) or []
                if isinstance(values, dict):
                    values = [values]
                if not isinstance(values, list):
                    continue
                for item in values:
                    if isinstance(item, dict):
                        findings.append({"scanner": scanner, **item})
                    elif item not in (None, ""):
                        findings.append({"scanner": scanner, "message": str(item)})
            if not result.get("ok"):
                findings.append({
                    "scanner": scanner,
                    "status": result.get("status") or "FAIL",
                    "message": result.get("error") or "scanner did not complete",
                })
        return findings

    @staticmethod
    def _scanner_checkpoints(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Retain only operator-safe cursors/checkpoints emitted by scanners."""
        fields = ("cursor", "next_cursor", "checkpoint", "sequence", "watermark", "state")
        checkpoints: dict[str, dict[str, Any]] = {}
        for scanner, result in results.items():
            data = result.get("data") if isinstance(result, dict) else None
            data = data if isinstance(data, dict) else {}
            checkpoints[scanner] = {
                "status": result.get("status") or ("PASS" if result.get("ok") else "FAIL"),
                **{name: data.get(name) for name in fields if data.get(name) not in (None, "", [], {})},
            }
        return checkpoints

    #: Lifecycle/result events also become audit rows. Every event is written
    #: to the Redis stream by EventBus in production; only these important
    #: milestones are additionally retained in monitor_events for audit/history.
    _DURABLE_EVENTS = frozenset({
        "live_scan.started", "live_scan.completed", "live_scan.error",
        "live_scan.drift", "live_scan.alert", "live_scan.cancelled",
        "universal_vendor.event",
    })

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        try:
            from api.events.bus import get_event_bus
            from api.events.platform_events import emit_platform_event

            if event_type in self._DURABLE_EVENTS:
                detail = payload.get("error") or payload.get("trigger") or event_type
                emit_platform_event(
                    event_type, str(detail), payload, target_name="live-scan",
                    tenant_id=self._run_tenant_id,
                )
            else:
                get_event_bus().publish(
                    event_type, payload, source="live-scanner",
                    tenant_id=self._run_tenant_id,
                )
        except Exception as exc:  # noqa: BLE001 — health/audit records the fault
            logger.error("live_scan_event_publish_failed", extra={"error_type": type(exc).__name__})

    def _auto_sync_graph(self, *, trigger: str, requested: list[str],
                         tenant_id: str | None = None) -> None:
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
                    target_name="graph", tenant_id=tenant_id,
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
                target_name="graph", tenant_id=tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("graph_update_event_failed: %s", exc)

    def run_cycle(
        self,
        *,
        only: list[str] | None = None,
        targets: dict[str, Any] | None = None,
        trigger: str = "manual",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute one scan cycle (blocking). Publishes SSE events and stores
        the merged snapshot. Callers on the request thread should use
        start_cycle() to run it in the background."""
        with self._lock:
            if self.running:
                return {"status": "already_running"}
            self.running = True
            self._started_at = time.time()
            self._run_tenant_id = tenant_id
            self.last_snapshot = self._tenant_snapshots.get(
                self._tenant_cache_key(tenant_id)
            )
        try:
            specs = self._specs(only=only, targets=targets)
            availability = self._scanner_availability(targets, only=only)
            # Universal vendor monitoring is a real source poll, not a
            # synthetic scanner command. It reads tenant-scoped connector
            # metadata and vault leases, then feeds source evidence into the
            # canonical vendor engine and the same SSE/audit path.
            vendor_enabled = only is None or "vendor" in only
            if only is None:
                requested = (["vendor"] if vendor_enabled else []) + [s.key for s in specs]
            else:
                # Keep explicitly requested unconfigured families visible as
                # BLOCKED/UNAVAILABLE records instead of silently dropping
                # them from the cycle.
                requested = list(dict.fromkeys(only))
            self._publish("live_scan.started",
                          {"trigger": trigger, "scanners": requested,
                           "scanner_availability": availability})
            results: dict[str, Any] = {}
            spec_keys = {spec.key for spec in specs}
            if only is not None:
                for family in requested:
                    if family == "vendor" or family in spec_keys:
                        continue
                    state = availability.get(family) or {
                        "status": "UNAVAILABLE", "reason": "unknown scanner family"
                    }
                    status = str(state.get("status") or "UNAVAILABLE")
                    if status == "CONFIGURED":
                        status = "UNAVAILABLE"
                        reason = "scanner family has no live adapter in this deployment"
                    else:
                        reason = state.get("reason")
                    results[family] = {
                        "scanner": family, "ok": False, "status": status,
                        "error": reason, "elapsed_s": 0.0,
                    }
                    self._publish("live_scan.scanner_completed", {
                        "scanner": family, "ok": False, "status": status,
                        "elapsed_s": 0.0, "error": reason,
                    })
            if vendor_enabled:
                self._publish("live_scan.scanner_started", {"scanner": "vendor"})
                from api.live_scan.vendor_realtime import run_vendor_realtime

                vendor_result = run_vendor_realtime(
                    tenant_id=getattr(self, "_run_tenant_id", None),
                    persist_events=False,
                )
                results["vendor"] = vendor_result
                for vendor_event in ((vendor_result.get("data") or {}).get("events") or []):
                    self._publish("universal_vendor.event", {
                        "event": vendor_event,
                        "tenant_id": getattr(self, "_run_tenant_id", None),
                    })
                vendor_result["vendor_status"] = vendor_result.get("status")
                vendor_result["status"] = (
                    "PASS" if vendor_result.get("ok") else
                    "UNAVAILABLE" if str(vendor_result.get("status") or "").lower() == "unavailable"
                    else "FAIL"
                )
                self._publish(
                    "live_scan.scanner_completed",
                    {"scanner": "vendor", "ok": vendor_result.get("ok"),
                     "status": vendor_result.get("status"),
                     "elapsed_s": vendor_result.get("elapsed_s"),
                     "summary": vendor_result.get("summary"),
                     "error": vendor_result.get("error")},
                )
            for spec in specs:
                if self._cancel_requested.is_set():
                    self._publish("live_scan.cancelled", {"trigger": trigger,
                                                           "scanners": list(results)})
                    return {"status": "cancelled", "trigger": trigger,
                            "results": results}
                self._publish("live_scan.scanner_started",
                              {"scanner": spec.key})
                res = self._run_spec(spec)
                results[spec.key] = res
                self._publish(
                    "live_scan.scanner_completed",
                    {"scanner": spec.key, "ok": res.get("ok"),
                     "status": res.get("status"),
                     "elapsed_s": res.get("elapsed_s"),
                     "summary": res.get("summary"),
                     "error": res.get("error")},
                )
                if self._cancel_requested.is_set():
                    self._publish("live_scan.cancelled", {"trigger": trigger,
                                                           "scanners": list(results)})
                    return {"status": "cancelled", "trigger": trigger,
                            "results": results}
            snapshot = {
                "ts": _now(),
                "trigger": trigger,
                "elapsed_s": round(time.time() - (self._started_at or time.time()), 2),
                "scanners": requested,
                "scanner_availability": availability,
                "results": results,
                "ok_count": sum(1 for r in results.values() if r.get("ok")),
                "failed_count": sum(1 for r in results.values()
                                     if not r.get("ok") and r.get("status") not in {"BLOCKED", "UNCONFIGURED"}),
                "blocked_count": sum(1 for r in results.values() if r.get("status") == "BLOCKED"),
                "unconfigured_count": sum(1 for r in results.values() if r.get("status") == "UNCONFIGURED"),
                "scanner_findings": self._extract_scanner_findings(results),
                "scanner_checkpoints": self._scanner_checkpoints(results),
            }
            vendor_data = (results.get("vendor") or {}).get("data") or {}
            if isinstance(vendor_data.get("cbom"), dict):
                # Keep the canonical CBOM independently of the full scanner
                # payload so it survives the trimmed durable snapshot.
                snapshot["vendor_cbom"] = vendor_data["cbom"]
            vendor_engine = vendor_data.get("engine")
            if isinstance(vendor_engine, dict):
                snapshot["vendor_evidence"] = vendor_engine.get("evidence") or []
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
            # Materialize one cross-scanner CBOM while full scanner payloads
            # are still present; the bounded snapshot retains this evidence
            # backed projection across restart.
            self.last_snapshot = snapshot
            try:
                snapshot["live_cbom"] = self.bom()
            except Exception as exc:  # noqa: BLE001
                logger.warning("live_cbom_aggregation_failed", extra={
                    "error_type": type(exc).__name__,
                })
            snapshot = _privacy_scrub(snapshot, _privacy_policy_obj())
            self.last_snapshot = snapshot
            self._tenant_snapshots[self._tenant_cache_key(self._run_tenant_id)] = snapshot
            self._loaded_tenant_id = self._run_tenant_id
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
                alert_report = self.alerts(tenant_id=self._run_tenant_id)
                trimmed["alerts"] = alert_report
                for alert in (alert_report.get("alerts") or []):
                    self._publish("live_scan.alert", {
                        "scanner": alert.get("scanner"),
                        "severity": alert.get("severity"),
                        "kind": alert.get("kind"),
                        "title": alert.get("title"),
                        "asset": alert.get("asset"),
                    })
                self._prev_inventory = current_inv
            except Exception:  # noqa: BLE001
                trimmed["inventory"] = None
            self._persisted = _db_persist(trimmed, tenant_id=self._run_tenant_id)
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
            self._auto_sync_graph(trigger=trigger, requested=requested,
                                   tenant_id=tenant_id)
            return {"status": "completed", **snapshot}
        finally:
            self.running = False
            self._started_at = None
            self._run_tenant_id = None
            self._cancel_requested.clear()

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

    def start_periodic(
        self,
        interval: int | None = None,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        if interval:
            self.interval = max(30, int(interval))
        if self._thread and self._thread.is_alive():
            return {"status": "already_running", "interval": self.interval}
        # The loop outlives the request ContextVar. Pin the authorized tenant
        # explicitly so its worker cannot fall back to the first organization.
        self._periodic_tenant_id = tenant_id
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._periodic_loop, daemon=True, name="live-scan-loop",
        )
        self._thread.start()
        return {"status": "started", "interval": self.interval}

    def stop_periodic(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        if (
            self._thread and self._thread.is_alive()
            and self._periodic_tenant_id not in (None, tenant_id)
        ):
            return {"status": "not_owner"}
        self._stop.set()
        return {"status": "stopping"}

    def request_cancel(self) -> bool:
        """Request cancellation of the active manual cycle.

        Scanner subprocesses finish their current bounded operation; the next
        scanner is not started and the durable orchestrator state records the
        cancellation. This avoids pretending a process was killed when it was
        only asked to stop.
        """
        with self._lock:
            active = self.running
            if active:
                self._cancel_requested.set()
            return active

    def load_persisted_snapshot(self, tenant_id: str | None = None) -> bool:
        """Restore a tenant's last snapshot from durable settings."""
        snap = _db_load_snapshot(tenant_id=tenant_id)
        cache_key = self._tenant_cache_key(tenant_id)
        self._loaded_tenant_id = tenant_id
        if not snap:
            self._tenant_snapshots.pop(cache_key, None)
            if not self.running:
                self.last_snapshot = None
                self.last_run_at = None
            return False
        self._tenant_snapshots[cache_key] = snap
        if not self.running:
            self.last_snapshot = snap
            self.last_run_at = snap.get("ts")
        return True

    # ------------------------------------------------------------------ inventory
    def record_network_result(self, result: dict[str, Any], *, tenant_id: str | None = None) -> None:
        """Fold a targeted network observation (POST /network-scans, discovery
        sweeps) into the tenant snapshot so the Network/Certificate dashboards
        reflect every real scan — not only full live-scan cycles.

        Dashboard projection over already-persisted scan evidence: failures
        are logged, never raised to the scan path.
        """
        try:
            with self._lock:
                key = self._tenant_cache_key(tenant_id)
                base = (self._tenant_snapshots.get(key)
                        or _db_load_snapshot(tenant_id=tenant_id) or {})
                snap = dict(base)
                results = dict(snap.get("results") or {})
                prev_data = (results.get("network") or {}).get("data") or {}
                merged = _merge_network_data(prev_data if isinstance(prev_data, dict) else {}, result)
                results["network"] = {
                    "status": "OK",
                    "ok": True,
                    "summary": {
                        "endpoints": len(merged.get("findings") or []),
                        "discovered": len(merged.get("endpoints") or []),
                        "certificates": len(merged.get("certificates") or []),
                    },
                    "data": merged,
                }
                snap["results"] = results
                snap["ts"] = datetime.now(timezone.utc).isoformat()
                self._tenant_snapshots[key] = snap
                if not self.running:
                    self.last_snapshot = snap
                    self.last_run_at = snap["ts"]
                current_inv = self.inventory(tenant_id=tenant_id)
                # Sections whose scanner payloads were trimmed from a restored
                # snapshot keep their last page-ready rows; network and
                # certificate sections are always rebuilt from the merged
                # observation above.
                prev_inv = base.get("inventory") if isinstance(base.get("inventory"), dict) else {}
                for section, value in prev_inv.items():
                    if section in {"network", "certificates", "cert_center", "_prev", "scans"}:
                        continue
                    if not current_inv.get(section) and value:
                        current_inv[section] = value
                trimmed = {
                    **snap,
                    "results": {
                        k: {kk: vv for kk, vv in res.items() if kk != "data"}
                        for k, res in snap["results"].items()
                        if isinstance(res, dict)
                    },
                    "inventory": current_inv,
                }
                trimmed = _privacy_scrub(trimmed, _privacy_policy_obj())
                _db_persist(trimmed, tenant_id=tenant_id)
                self._publish("live_scan.inventory_updated", {
                    "source": "network-scan",
                    "endpoints": len(merged.get("findings") or []),
                })
        except Exception as exc:  # noqa: BLE001 — projection must not sink the scan
            logger.warning("network_snapshot_bridge_failed",
                           extra={"error_type": type(exc).__name__})

    def inventory(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Build page-ready structures for the dashboard pages from the most
        recent live snapshot (in-memory with full payloads, else the persisted
        summaries). Real scan data only — empty until a scan runs."""
        snap = (self.snapshot_for_tenant(tenant_id) if tenant_id is not None
                else self.last_snapshot) or {}
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
        vendor_cbom = snap.get("vendor_cbom") if isinstance(snap.get("vendor_cbom"), dict) else None
        vendor_evidence = snap.get("vendor_evidence") if isinstance(snap.get("vendor_evidence"), list) else []

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
            "vendor_cbom": vendor_cbom,
            "vendor_evidence": vendor_evidence,
        }
        # After a restart the in-memory snapshot only has summaries (full
        # payloads are not persisted); fall back to the page-ready inventory
        # captured at scan time until a new cycle repopulates full data.
        if sum(counts.values()) == 0 and isinstance(snap.get("inventory"), dict):
            return {k: v for k, v in snap["inventory"].items() if k != "_prev"}
        return built

    # ------------------------------------------------------------------ alerts
    def alerts(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Deterministic, cross-scanner risk aggregation. Derives alerts from
        the page-ready inventory (so it also works after a restart) plus the
        per-scanner summaries/errors in the latest snapshot."""
        inv = self.inventory(tenant_id=tenant_id)
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

    def drift(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Latest drift between consecutive live cycles (persisted-safe)."""
        if tenant_id is None and self.last_drift:
            return self.last_drift
        snap = (self.snapshot_for_tenant(tenant_id) if tenant_id is not None
                else self.last_snapshot) or {}
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
    @staticmethod
    def _bom_value(value: Any) -> list[Any]:
        if value in (None, "", [], {}):
            return []
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return [value]

    @classmethod
    def _scanner_cbom_components(
        cls,
        scanner: str,
        payload: Any,
    ) -> list[dict[str, Any]]:
        """Project explicit crypto records from every live scanner payload.

        Scanner schemas differ, but this projection only emits values that the
        scanner actually reported. A package/resource/finding without an
        explicit crypto field is not turned into an ``unknown`` algorithm.
        """
        output: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        def text(value: Any) -> str | None:
            if isinstance(value, dict):
                value = (field(value, "name", "algorithm", "protocol",
                               "cipher_suite", "id", "key_id", "serial_number",
                               "kind", "manufacturer", "model", "device")
                         or field(value, "value", "type"))
            if value in (None, "", [], {}):
                return None
            return str(value)

        def field(record: dict[str, Any], *names: str) -> Any:
            wanted = {"".join(char for char in name.lower() if char.isalnum())
                      for name in names}
            for actual, value in record.items():
                normalized = "".join(char for char in str(actual).lower() if char.isalnum())
                if normalized in wanted and value not in (None, "", [], {}):
                    return value
            return None

        def evidence(record: dict[str, Any]) -> str | None:
            value = field(
                record, "evidence_reference", "source_evidence_reference",
                "evidenceReference", "sourceEvidenceReference", "evidence_id",
                "evidenceId", "content_hash", "contentHash", "hash", "sha256",
            )
            if value not in (None, ""):
                return str(value)
            observed_evidence = field(record, "evidence", "evidence_items")
            if observed_evidence not in (None, "", [], {}):
                # Content-address the evidence supplied by the scanner. This
                # is not a guessed source location and is never created for a
                # record that lacks explicit evidence.
                digest = hashlib.sha256(json.dumps(
                    observed_evidence, sort_keys=True, default=str,
                ).encode("utf-8")).hexdigest()
                return f"sha256:{digest}"
            return None

        def emit(kind: str, name: Any, record: dict[str, Any], **extra: Any) -> None:
            normalized = text(name)
            if not normalized or normalized.lower() in {"unknown", "none", "null"}:
                return
            version = field(record, "version", "product_version", "library_version")
            key = (kind, normalized, str(version or ""))
            if key in seen:
                return
            seen.add(key)
            component: dict[str, Any] = {
                "type": kind,
                "name": normalized,
                "version": version,
                "source": scanner,
                "evidence_reference": evidence(record),
            }
            # Retain scanner-specific metadata without assuming a schema. The
            # aliases cover the source, runtime, network, cloud, container,
            # OT, telecom, payment, hardware and vendor adapters; unknown
            # fields remain in the raw scanner payload rather than being
            # guessed into a CBOM component.
            metadata_aliases = {
                "mode": ("mode",), "padding": ("padding",),
                "key_size": ("key_size", "key_bits", "key_length"),
                "curve": ("curve", "named_curve"),
                "algorithm_oid": ("algorithm_oid", "algorithm_oid_name"),
                "protocol_version": ("protocol_version", "tls_version", "version"),
                "cipher_suites": ("cipher_suites", "ciphers", "cipher_offers"),
                "library": ("library", "library_name", "tls_library"),
                "package": ("package", "package_name"),
                "status": ("status", "posture", "state"),
                "severity": ("severity", "risk", "risk_level"),
                "quantum_status": ("quantum_status", "pqc_status"),
                "quantum_safe_status": ("quantum_safe_status", "pqc_ready"),
                "migration_priority": ("migration_priority",),
                "pqc_alternatives": ("pqc_alternatives",),
                "compliance": ("compliance", "compliance_status"),
                "asset_id": ("asset_id", "asset", "device_id"),
                "endpoint": ("endpoint", "host", "target"),
                "file_path": ("file_path", "path", "location", "where"),
                "line_number": ("line_number", "line"),
                "resource_id": ("resource_id", "resource", "arn", "uri"),
                "observed_at": ("observed_at", "timestamp", "occurred_at"),
                "observation_id": ("observation_id", "observationId"),
                "evidence": ("evidence", "evidence_items"),
            }
            for output_name, aliases in metadata_aliases.items():
                value = field(record, *aliases)
                if value not in (None, "", [], {}):
                    component[output_name] = value
            component.update({key: value for key, value in extra.items()
                             if value not in (None, "", [], {})})
            output.append(component)

        def walk(node: Any, depth: int = 0) -> None:
            if depth > 5:
                return
            if isinstance(node, list):
                for item in node:
                    walk(item, depth + 1)
                return
            if not isinstance(node, dict):
                return
            record = node
            crypto = field(record, "crypto", "cryptography", "crypto_metadata")
            crypto_records = crypto if isinstance(crypto, dict) else {}
            merged = {**record, **crypto_records}

            # Universal/source findings and network crypto objects. Every
            # alias is an observed field name; the walker never promotes a
            # generic asset/resource/finding label into an algorithm.
            algorithms: list[Any] = []
            for key in ("algorithm", "crypto_algorithm", "signature_algorithm",
                        "key_exchange", "cipher_suite", "cipher",
                        "encryption_algorithm", "encryptionAlgorithm",
                        "signing_algorithm", "key_spec", "key_type",
                        "negotiated_group", "group", "hash_algorithm",
                        "digest_algorithm", "mac_algorithm"):
                algorithms.extend(cls._bom_value(field(merged, key)))
            algorithms.extend(cls._bom_value(field(merged, "algorithms", "crypto_algorithms")))
            for algorithm in algorithms:
                algorithm_record = {**merged, **algorithm} if isinstance(algorithm, dict) else merged
                emit("algorithm", algorithm, algorithm_record)
            protocols = (cls._bom_value(field(merged, "protocol", "protocol_name"))
                         + cls._bom_value(field(merged, "protocols", "protocol_observations")))
            for protocol in protocols:
                protocol_record = {**merged, **protocol} if isinstance(protocol, dict) else merged
                protocol_name = (field(protocol_record, "protocol", "protocol_name", "name")
                                 if isinstance(protocol, dict) else text(protocol))
                if not protocol_name and isinstance(protocol, dict):
                    version = field(protocol, "protocol_version", "tls_version", "version")
                    version_text = str(version or "").upper()
                    if version_text.startswith(("TLS", "SSH", "IKE", "IPSEC", "QUIC")):
                        protocol_name = version_text.split("/", 1)[0]
                if not protocol_name:
                    continue
                emit("protocol", protocol_name, protocol_record,
                     protocol_version=field(protocol_record, "protocol_version", "tls_version", "version"),
                     cipher_suites=field(protocol_record, "cipher_suites", "ciphers", "cipher_offers"))

            # Certificates and public-key metadata are separate CBOM assets.
            certificates = (cls._bom_value(field(merged, "certificate", "cert"))
                            + cls._bom_value(field(merged, "certificates", "certificate_chain", "chain")))
            for certificate in certificates:
                if isinstance(certificate, dict):
                    emit("certificate", field(certificate, "serial_number", "serial", "subject",
                                               "fingerprint_sha256", "fingerprint"),
                         {**merged, **certificate})
            key_values = (cls._bom_value(field(merged, "key_id", "keyId"))
                          + cls._bom_value(field(merged, "key", "key_metadata", "keys"))
                          + cls._bom_value(field(merged, "key_material", "key_reference")))
            for key_value in key_values:
                if isinstance(key_value, dict):
                    emit("key", field(key_value, "id", "name", "type", "key_id", "key_type"),
                         {**merged, **key_value})
                else:
                    emit("key", key_value, merged)

            # Libraries/packages/services are only projected when their source
            # record explicitly labels them as such.
            libraries = (cls._bom_value(field(merged, "library", "library_details"))
                         + cls._bom_value(field(merged, "tls_library", "tls_libraries"))
                         + cls._bom_value(field(merged, "crypto_library", "libraries")))
            for library in libraries:
                library_record = {**merged, **library} if isinstance(library, dict) else merged
                emit("library", library, library_record)
            packages = (cls._bom_value(field(merged, "package", "packages"))
                        + cls._bom_value(field(merged, "crypto_package", "crypto_packages")))
            for package in packages:
                package_record = {**merged, **package} if isinstance(package, dict) else merged
                # A package is a CBOM component only when the scanner has
                # explicitly marked it crypto-bearing or supplied algorithms.
                if isinstance(package, dict) and not (
                    field(package, "algorithm", "algorithms", "crypto", "crypto_capable")
                    or field(merged, "algorithm", "algorithms", "crypto")
                ):
                    continue
                emit("package", package, package_record)
            dependencies = (cls._bom_value(field(merged, "dependency", "dependencies"))
                            + cls._bom_value(field(merged, "library_dependencies")))
            for dependency in dependencies:
                dependency_record = {**merged, **dependency} if isinstance(dependency, dict) else merged
                emit("dependency", dependency, dependency_record)
            services = (cls._bom_value(field(merged, "crypto_service", "crypto_services"))
                        + cls._bom_value(field(merged, "kms", "kms_service", "hsm")))
            for service in services:
                service_record = {**merged, **service} if isinstance(service, dict) else merged
                emit("service", service, service_record)
            rngs = (cls._bom_value(field(merged, "rng", "random_number_generator", "hardware_rng"))
                    + cls._bom_value(field(merged, "random_source", "random_source_type")))
            for rng in rngs:
                rng_record = {**merged, **rng} if isinstance(rng, dict) else merged
                emit("rng", rng, rng_record)

            # Hardware capabilities are not usage. Keep them as capabilities
            # so AES-NI/RDRAND/TPM presence cannot become a fabricated AES or
            # key observation.
            extensions = cls._bom_value(field(merged, "instruction_extensions", "crypto_extensions"))
            for extension in extensions:
                emit("capability", extension, merged,
                     capability_kind="hardware_instruction_extension")
            for capability in ("aes_acceleration", "sha_acceleration", "hardware_rng",
                               "trusted_execution", "tpm_present", "hsm_present"):
                if field(merged, capability) is True:
                    emit("capability", capability, merged, capability_kind="hardware_presence")
            if field(merged, "secret_type", "secret_kind") not in (None, ""):
                emit("secret", field(merged, "secret_type", "secret_kind"), merged)

            for value in record.values():
                if isinstance(value, (dict, list)):
                    walk(value, depth + 1)

        walk(payload)
        return output

    def bom(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Cryptographic Bill of Materials (CBOM) and Hardware Bill of Materials
        (HBOM) assembled from the live scans. Real components only; quantum
        verdicts come from the universal crypto classifier (left null where no
        classifier ran, rather than guessed)."""
        snap = (self.snapshot_for_tenant(tenant_id) if tenant_id is not None
                else self.last_snapshot) or {}
        persisted_cbom = snap.get("live_cbom")
        if isinstance(persisted_cbom, dict):
            if "dependency_graph" not in persisted_cbom:
                from api.live_scan.dependency_graph import build_live_dependency_graph

                persisted_cbom = dict(persisted_cbom)
                persisted_cbom["dependency_graph"] = build_live_dependency_graph(
                    ((persisted_cbom.get("cbom") or {}).get("components") or [])
                )
            return persisted_cbom
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
        inv = self.inventory(tenant_id=tenant_id)
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
            # Container inventory can include every OS package. Only a
            # scanner-labelled crypto package or one with explicit algorithm
            # metadata belongs in the CBOM.
            if not (pkg.get("algorithms") or pkg.get("crypto") or
                    pkg.get("crypto_capable") is True):
                continue
            components.append({
                "type": "package", "name": name,
                "version": pkg.get("version"), "ref": pkg.get("manager") or "image",
                "quantum_status": None, "migration_priority": None,
                "algorithms": pkg.get("algorithms") or [],
                "deprecated": pkg.get("deprecated"), "source": "container",
            })

        # 4. canonical components materialized by the realtime vendor engine.
        # They are already evidence-backed and persisted separately from the
        # trimmed scanner payload.
        vendor_bom = snap.get("vendor_cbom") if isinstance(snap.get("vendor_cbom"), dict) else {}
        for component in vendor_bom.get("components") or []:
            if isinstance(component, dict):
                props = {
                    str(item.get("name")): item.get("value")
                    for item in component.get("properties") or []
                    if isinstance(item, dict)
                }
                crypto = component.get("cryptoProperties") or {}
                algorithm_properties = crypto.get("algorithmProperties") or {}
                library_properties = crypto.get("libraryProperties") or {}
                components.append({
                    "type": crypto.get("assetType") or component.get("type") or "crypto-asset",
                    "name": component.get("name"),
                    "version": component.get("version"),
                    "ref": component.get("bom-ref"),
                    "algorithm": props.get("algorithm") or algorithm_properties.get("algorithm"),
                    "protocol": props.get("protocol") or crypto.get("protocol"),
                    "library": props.get("library") or library_properties.get("name"),
                    "quantum_status": crypto.get("nistDesignation"),
                    "quantum_vulnerable": crypto.get("quantumVulnerable"),
                    "source": "vendor-realtime",
                    "evidence_reference": props.get("evidence_reference")
                    or crypto.get("evidenceReference"),
                })

        # 5. Every API scanner result class contributes its explicit crypto
        # records (network, cloud, container, telecom, OT, runtime, source,
        # and universal). The vendor engine above already owns its canonical
        # CBOM, so do not re-project that payload here.
        for scanner_key, result in results.items():
            if scanner_key == "vendor":
                continue
            data = (result or {}).get("data") if isinstance(result, dict) else None
            components.extend(self._scanner_cbom_components(scanner_key, data or {}))

        # de-duplicate by (type, name, version)
        seen: set[tuple] = set()
        uniq: list[dict[str, Any]] = []
        for c in components:
            k = (
                c["type"], c.get("name"), c.get("version"), c.get("ref"),
                c.get("algorithm"), c.get("protocol"), c.get("library"),
            )
            if k in seen:
                continue
            seen.add(k)
            uniq.append(c)

        def _quantum_bad(c: dict[str, Any]) -> bool:
            q = str(c.get("quantum_status") or c.get("quantum_safe_status") or "").lower()
            return ("vulnerable" in q or "broken" in q or "at_risk" in q) and "safe" not in q

        quantum_vulnerable = sum(1 for c in uniq if _quantum_bad(c))
        type_counts: dict[str, int] = {}
        for component in uniq:
            kind = str(component.get("type") or "unknown")
            type_counts[kind] = type_counts.get(kind, 0) + 1

        # Every live crypto observation receives a bounded dependency/cascade
        # projection. The graph is derived only from explicit scanner metadata
        # and shared identifiers; unresolved references remain visible.
        from api.live_scan.dependency_graph import build_live_dependency_graph

        dependency_graph = build_live_dependency_graph(uniq)

        # HBOM: hardware devices
        hbom_components = [
            {"type": d.get("type"), "name": d.get("vendor") or d.get("type"),
             "version": d.get("firmware"), "ref": d.get("host"),
             "caps": d.get("caps"), "source": "hardware"}
            for d in inv.get("hardware", [])
        ]

        return {
            "generated_at": snap.get("ts"),
            "dependency_graph": dependency_graph,
            "cbom": {
                "components": uniq,
                "counts": {
                    "total": len(uniq),
                    "algorithms": sum(1 for c in uniq if c["type"] == "algorithm"),
                    "libraries": sum(1 for c in uniq if c["type"] == "library"),
                    "packages": sum(1 for c in uniq if c["type"] == "package"),
                    "protocols": sum(1 for c in uniq if c["type"] == "protocol"),
                    "certificates": sum(1 for c in uniq if c["type"] == "certificate"),
                    "keys": sum(1 for c in uniq if c["type"] == "key"),
                    "services": sum(1 for c in uniq if c["type"] == "service"),
                    "rngs": sum(1 for c in uniq if c["type"] == "rng"),
                    "by_type": type_counts,
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
                self.run_cycle(
                    trigger="scheduled",
                    tenant_id=self._periodic_tenant_id,
                )
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
