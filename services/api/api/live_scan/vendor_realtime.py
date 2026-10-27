"""Bridge persisted tenant vendor connectors into the realtime vendor engine.

This module is intentionally an API-process adapter.  It reads only the
non-secret connector metadata from onboarding and resolves a credential through
the existing control-plane vault adapter at request time.  The universal
vendor package never receives a database session or persisted secret.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

_ENGINE_CACHE: dict[str, tuple[str, Any]] = {}
_ENGINE_LOCK = threading.Lock()
_VENDOR_STATE_KEY = "live_vendor.realtime_state"


def _tenant_state_key(tenant_id: str | None) -> str:
    # AppSetting keys are globally unique in older installations; namespace the
    # state key while also writing the explicit tenant_id column.
    return f"{_VENDOR_STATE_KEY}:{tenant_id}" if tenant_id else _VENDOR_STATE_KEY


def _load_engine_state(tenant_id: str | None) -> dict[str, Any] | None:
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            state = SettingsRepository(session).get(
                _tenant_state_key(tenant_id), tenant_id=tenant_id,
            )
        return state if isinstance(state, dict) else None
    except Exception as exc:  # DB may be absent on an edge process
        logger.warning("vendor_realtime_state_load_failed", extra={
            "error_type": type(exc).__name__,
        })
        return None


def _persist_engine_state(
    tenant_id: str | None,
    engine: Any,
    events: list[dict[str, Any]],
    *,
    persist_events: bool = True,
) -> str | None:
    """Persist source cursors/CBOM and the append-only observation journal."""
    try:
        from db.connection.session import SessionLocal
        from db.models.monitor import MonitorEvent
        from db.repositories.settings_repository import SettingsRepository

        with SessionLocal() as session:
            if persist_events:
                for event in events:
                    session.add(MonitorEvent(
                        tenant_id=tenant_id,
                        target_name=f"vendor:{event.get('asset_id') or event.get('vendor') or 'unknown'}",
                        # The audit column is legacy-sized; the full canonical
                        # event type remains in the JSON payload.
                        event_type=str(event.get("event_type") or "UNKNOWN")[:30],
                        detail="vendor realtime observation",
                        payload=event,
                    ))
            SettingsRepository(session).set(
                _tenant_state_key(tenant_id),
                engine.export_state(),
                updated_by="vendor-live-scanner",
                tenant_id=tenant_id,
            )
            session.commit()
        return None
    except Exception as exc:  # do not report durable success when state is lost
        logger.exception("vendor_realtime_state_persist_failed")
        return f"durable realtime state unavailable: {type(exc).__name__}"


def _credential_resolver(credential: Any):
    """Return a callback that obtains a short-lived, read-only vault value."""
    credential_dict = credential.to_dict()

    def resolve() -> str | None:
        from control_plane.credentials import assess_credential
        from control_plane.vault import lease_credential

        health = assess_credential(credential_dict)
        if not health.healthy:
            raise RuntimeError(f"credential unavailable: {health.detail}")
        lease = lease_credential(credential_dict, require_value=True)
        if not lease.read_only:
            raise PermissionError("vendor realtime connector requires a read-only credential lease")
        # Persist the access audit before the lease is used for a source call.
        from db.connection.session import SessionLocal
        from db.repositories.control_plane_repository import ControlPlaneRepository

        with SessionLocal() as session:
            ControlPlaneRepository(session).record_credential_access(credential_dict["id"])
            session.commit()
        return lease.value

    return resolve


def _host_in_authorized_scope(endpoint: str, scope_targets: list[str]) -> bool:
    """Require a configured source to point at an explicitly authorized scope."""
    parsed = urllib.parse.urlsplit(endpoint)
    host = (parsed.hostname or endpoint).strip().lower().rstrip(".")
    for raw_target in scope_targets:
        target = str(raw_target or "").strip().lower().rstrip(".")
        if not target:
            continue
        if target == host or host.endswith("." + target):
            return True
        try:
            if "/" in target and ipaddress.ip_address(host) in ipaddress.ip_network(target, strict=False):
                return True
        except ValueError:
            continue
    return False


def _persisted_sources(tenant_id: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load tenant-scoped source metadata and vault callbacks from production DB."""
    from db.connection.session import SessionLocal
    from db.repositories.control_plane_repository import ControlPlaneRepository
    from db.repositories.onboarding_repository import OnboardingRepository

    with SessionLocal() as session:
        onboarding = OnboardingRepository(session)
        # This code runs on a worker thread, outside the request ContextVar;
        # the explicit filter is therefore mandatory for tenant isolation.
        org = onboarding.get_default_org(tenant_id=tenant_id)
        if org is None:
            return [], {}
        scope_targets = [
            str(entry.target) for entry in onboarding.list_scope(org.id)
            if getattr(entry, "enabled", True)
        ]
        credentials = ControlPlaneRepository(session).list_credentials(tenant_id)
        by_ref: dict[str, Any] = {}
        for credential in credentials:
            # auth_ref/vault_ref is an opaque locator, never a secret value.
            by_ref[str(credential.id)] = credential
            by_ref[str(credential.name)] = credential
        rows: list[dict[str, Any]] = []
        resolvers: dict[str, Any] = {}
        for connector in onboarding.list_connectors(org.id):
            config = dict(connector.config or {})
            # Only explicitly configured realtime source records enter this
            # path. A plain onboarding host/role is not treated as API evidence.
            if not any(config.get(key) for key in (
                "endpoint", "api_endpoint", "event_file", "syslog_path", "telemetry_file",
                "listen_port", "syslog_port", "telemetry_port",
            )):
                continue
            source_endpoint = str(config.get("endpoint") or config.get("api_endpoint") or "")
            scope_target = str(config.get("scope_target") or "").strip()
            authorized = (
                scope_target in scope_targets
                if scope_target else (
                    _host_in_authorized_scope(source_endpoint, scope_targets)
                    if source_endpoint else False
                )
            )
            row = {
                "config": config,
                "vendor": config.get("vendor"),
                "product": config.get("product"),
                "asset_id": config.get("asset_id") or config.get("asset"),
                "method": connector.method,
                "status": connector.status,
                "authorized": authorized,
            }
            auth_ref = str(config.get("auth_ref") or config.get("vault_ref") or "").strip()
            if auth_ref:
                credential = by_ref.get(auth_ref)
                if credential is None:
                    # Keep the connector in the monitor so its unavailable
                    # reason is visible rather than silently dropping it.
                    row["auth_ref"] = auth_ref
                else:
                    row["auth_ref"] = auth_ref
                    row["auth_status"] = credential.status
                    row["auth_updated_at"] = (
                        credential.updated_at.isoformat()
                        if getattr(credential, "updated_at", None) else None
                    )
                    resolvers[auth_ref] = _credential_resolver(credential)
            rows.append(row)
        return rows, resolvers


def _event_projection(event: Any) -> dict[str, Any]:
    """SSE/audit projection; raw API evidence stays behind its hash."""
    record = event.to_dict()
    metadata = dict(record.get("vendor_metadata") or {})
    for key in ("artifact", "scan_context"):
        metadata.pop(key, None)
    record["vendor_metadata"] = metadata
    return record


def _source_configuration_key(configurations: list[dict[str, Any]],
                               source_origin: str) -> str:
    """Stable non-secret key used to retain connector state between polls."""
    sensitive_tokens = ("password", "secret", "token", "private", "credential", "authorization")

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): "<redacted>" if any(token in str(key).lower() for token in sensitive_tokens)
                else scrub(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    return json.dumps({"origin": source_origin, "sources": scrub(configurations)},
                      sort_keys=True, default=str, separators=(",", ":"))


def _get_engine(*, tenant_id: str | None, source_origin: str,
                configurations: list[dict[str, Any]],
                resolvers: dict[str, Any]):
    from universal_vendor.live.engine import LiveVendorEngine
    from universal_vendor.live.monitoring import LiveVendorMonitor
    from universal_vendor.plugins import build_registry
    from universal_vendor.scan_modes import UniversalVendorScanner

    cache_key = tenant_id or "__unscoped__"
    config_key = _source_configuration_key(configurations, source_origin)
    with _ENGINE_LOCK:
        cached = _ENGINE_CACHE.get(cache_key)
        if cached and cached[0] == config_key:
            return cached[1]
        monitor = LiveVendorMonitor.from_configurations(
            configurations, tenant_id=tenant_id,
            credential_resolvers=resolvers,
        )
        engine = LiveVendorEngine(
            monitor=monitor,
            tenant_id=tenant_id,
            scanner=UniversalVendorScanner(registry=build_registry()),
        )
        _ENGINE_CACHE[cache_key] = (config_key, engine)
        return engine


def run_vendor_realtime(
    *,
    tenant_id: str | None = None,
    persist_events: bool = True,
) -> dict[str, Any]:
    """Poll configured production vendor sources once and run real evidence scans."""
    try:
        if tenant_id is None:
            try:
                from db.tenancy import current_tenant

                tenant_id = current_tenant()
            except (ImportError, RuntimeError):
                tenant_id = None
        from universal_vendor.live.engine import LiveVendorEngine
        from universal_vendor.live.monitoring import LiveVendorMonitor
        from universal_vendor.plugins import build_registry
        from universal_vendor.scan_modes import UniversalVendorScanner

        try:
            configurations, resolvers = _persisted_sources(tenant_id)
            source_origin = "tenant_persistence"
            monitor = LiveVendorMonitor.from_configurations(
                configurations, tenant_id=tenant_id,
                credential_resolvers=resolvers,
            )
        except Exception as exc:  # DB may be absent on an isolated edge process
            logger.warning("vendor_source_configuration_unavailable", extra={
                "error_type": type(exc).__name__,
            })
            monitor = LiveVendorMonitor.from_environment(tenant_id=tenant_id)
            source_origin = "runtime_environment"
            if not monitor.connectors():
                monitor.add_configuration_error(
                    "tenant connector persistence could not be loaded"
                )

        if source_origin == "tenant_persistence":
            engine = _get_engine(
                tenant_id=tenant_id, source_origin=source_origin,
                configurations=configurations, resolvers=resolvers,
            )
        else:
            # Environment-backed sources are constructed by the cache as well;
            # use their non-secret records as the state key so polling is
            # incremental across cycles.
            env_key = _source_configuration_key(
                [{"asset_id": c.asset_id, "vendor": c.vendor,
                  "product": c.product, "mechanism": c.mechanism}
                 for c in monitor.connectors()], source_origin,
            )
            with _ENGINE_LOCK:
                cached = _ENGINE_CACHE.get(tenant_id or "__unscoped__")
                if not cached or cached[0] != env_key:
                    _ENGINE_CACHE[tenant_id or "__unscoped__"] = (env_key, LiveVendorEngine(
                        monitor=monitor, tenant_id=tenant_id,
                        scanner=UniversalVendorScanner(registry=build_registry()),
                    ))
                engine = _ENGINE_CACHE[tenant_id or "__unscoped__"][1]
        persisted_state = _load_engine_state(tenant_id)
        if persisted_state:
            engine.restore_state(persisted_state)
        before = len(engine.gateway)
        outcome = engine.tick(deep_scan=True)
        events = engine.gateway.events(since_index=before)
        projected = [_event_projection(event) for event in events]
        unavailable = any(
            (event.vendor_metadata or {}).get("availability") == "UNAVAILABLE"
            for event in events
        )
        status = monitor.status()
        persistence_error = _persist_engine_state(
            tenant_id, engine, projected, persist_events=persist_events,
        )
        ok = bool(monitor.connectors()) and not unavailable and persistence_error is None
        errors = list(status.get("configuration_errors") or [])
        if persistence_error:
            errors.append(persistence_error)
        return {
            "scanner": "vendor",
            "ok": ok,
            "status": "completed" if ok else "unavailable",
            "source_origin": source_origin,
            "summary": {
                "configured_sources": len(monitor.connectors()),
                "events": len(events),
                "source_status": status,
                "event_ids": [event.get("event_id") for event in projected],
                "state_persisted": persistence_error is None,
            },
            "data": {
                "engine": outcome,
                "events": projected,
                "cbom": engine.cbom.generate_document(name="live-vendor-cbom"),
            },
            "error": None if ok else "; ".join(errors or [
                "configured vendor source returned no usable evidence",
            ]),
        }
    except Exception as exc:  # never let one realtime domain kill the cycle
        logger.exception("vendor_realtime_cycle_failed")
        return {
            "scanner": "vendor", "ok": False, "status": "error",
            "summary": {"configured_sources": 0, "events": 0},
            "error": f"vendor realtime unavailable: {type(exc).__name__}",
        }


__all__ = ["run_vendor_realtime"]
