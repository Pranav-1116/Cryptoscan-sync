"""Repository for the onboarding aggregate (org / environments / scope /
connectors / discovery runs). All writes scrub secret material defensively.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.onboarding import (
    CONNECTOR_KINDS,
    CONNECTOR_METHODS,
    ENVIRONMENT_TYPES,
    SCOPE_KINDS,
    SECRET_KEY_HINTS,
    Connector,
    DiscoveryRun,
    Environment,
    Organization,
    ScopeEntry,
)


def maintenance_window_open(env: Environment, now: datetime | None = None) -> bool:
    """Return True if active probing is permitted for this environment right now.

    Safety model: an OT/ICS/DR environment with maintenance windows enabled is
    *closed* to active probing except inside a declared weekly window. Passive
    (read-only observation) scanning is always permitted. Environments without
    windows enabled are always open (IT default).
    """
    if not env.maintenance_window_enabled or not env.maintenance_windows:
        return True
    now = now or datetime.now(timezone.utc)
    weekday = now.strftime("%a").lower()  # mon/tue/...
    for window in env.maintenance_windows or []:
        if not isinstance(window, dict):
            continue
        if str(window.get("day", "")).lower() not in {weekday, weekday[:3], "*"}:
            continue
        try:
            sh, sm = (int(x) for x in str(window.get("start", "00:00")).split(":")[:2])
            duration = int(window.get("duration_minutes", 60))
        except (ValueError, TypeError):
            continue
        start_min = sh * 60 + sm
        cur_min = now.hour * 60 + now.minute
        if start_min <= cur_min < start_min + duration:
            return True
    return False


def scrub_secrets(config: dict[str, Any] | None) -> dict[str, Any]:
    """Never persist secret material — drop any key that looks sensitive."""
    if not isinstance(config, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, value in config.items():
        lk = str(key).lower()
        if any(hint in lk for hint in SECRET_KEY_HINTS):
            clean[key] = "<redacted-secret-not-stored>"
            continue
        clean[key] = value
    return clean


class OnboardingRepository:
    def __init__(self, session: Session):
        self.session = session

    # ----------------------------------------------------------- organization
    def list_orgs(self) -> list[Organization]:
        return list(self.session.execute(select(Organization).order_by(Organization.name)).scalars().all())

    def get_org(self, org_id: str) -> Organization | None:
        return self.session.execute(select(Organization).where(Organization.id == org_id)).scalars().first()

    def get_default_org(self, tenant_id: str | None = None) -> Organization | None:
        """Return the oldest organization visible to the optional tenant.

        Background workers do not inherit the request tenant context, so
        realtime adapters must pass the tenant explicitly instead of relying
        on the ORM request guard.
        """
        stmt = select(Organization)
        if tenant_id is not None:
            stmt = stmt.where(Organization.tenant_id == tenant_id)
        return self.session.execute(
            stmt.order_by(Organization.created_at.asc()).limit(1)
        ).scalars().first()

    def create_org(self, name: str, sector: str = "generic", **fields) -> Organization:
        org = Organization(name=name, sector=sector, **fields)
        self.session.add(org)
        self.session.flush()
        return org

    def update_org(self, org_id: str, **fields) -> Organization | None:
        org = self.get_org(org_id)
        if org is None:
            return None
        for key, value in fields.items():
            if hasattr(org, key) and value is not None:
                setattr(org, key, value)
        self.session.flush()
        return org

    # ------------------------------------------------------------- environment
    def list_environments(self, org_id: str) -> list[Environment]:
        return list(self.session.execute(
            select(Environment).where(Environment.org_id == org_id).order_by(Environment.name)
        ).scalars().all())

    def add_environment(self, org_id: str, name: str, env_type: str = "production", **fields) -> Environment:
        env_type = env_type if env_type in ENVIRONMENT_TYPES else "production"
        env = Environment(org_id=org_id, name=name, env_type=env_type, **fields)
        self.session.add(env)
        self.session.flush()
        return env

    def get_environment(self, env_id: str) -> Environment | None:
        return self.session.execute(select(Environment).where(Environment.id == env_id)).scalars().first()

    def update_environment(self, env_id: str, **fields) -> Environment | None:
        env = self.get_environment(env_id)
        if env is None:
            return None
        for key, value in fields.items():
            if hasattr(env, key) and value is not None:
                setattr(env, key, value)
        self.session.flush()
        return env

    # ------------------------------------------------------------------- scope
    def list_scope(self, org_id: str, env_id: str | None = None) -> list[ScopeEntry]:
        stmt = select(ScopeEntry).where(ScopeEntry.org_id == org_id)
        if env_id:
            stmt = stmt.where(ScopeEntry.env_id == env_id)
        return list(self.session.execute(stmt.order_by(ScopeEntry.kind)).scalars().all())

    def add_scope(self, org_id: str, kind: str, target: str, env_id: str | None = None,
                  detail: dict | None = None) -> ScopeEntry:
        kind = kind if kind in SCOPE_KINDS else "application"
        entry = ScopeEntry(org_id=org_id, env_id=env_id, kind=kind, target=target,
                           detail=detail or {})
        self.session.add(entry)
        self.session.flush()
        return entry

    def scope_summary(self, org_id: str) -> dict[str, Any]:
        entries = self.list_scope(org_id)
        by_kind: dict[str, list[str]] = {k: [] for k in SCOPE_KINDS}
        for e in entries:
            by_kind.setdefault(e.kind, []).append(e.target)
        counts = {}
        for kind, targets in by_kind.items():
            # cloud scope is declared as accounts; network as CIDRs, etc.
            counts[kind] = len(targets)
        return {
            "network_cidrs": by_kind.get("network", []),
            "cloud_targets": by_kind.get("cloud", []),
            "application_targets": by_kind.get("application", []),
            "hardware_targets": by_kind.get("hardware", []),
            "entries": [
                {"id": e.id, "kind": e.kind, "target": e.target,
                 "env_id": e.env_id, "enabled": e.enabled}
                for e in entries
            ],
            "counts": counts,
            "total": len(entries),
        }

    def get_scope_entry(self, entry_id: str) -> ScopeEntry | None:
        return self.session.execute(select(ScopeEntry).where(ScopeEntry.id == entry_id)).scalars().first()

    def delete_scope_entry(self, entry_id: str) -> bool:
        entry = self.get_scope_entry(entry_id)
        if entry is None:
            return False
        self.session.delete(entry)
        self.session.flush()
        return True

    # --------------------------------------------------------------- connectors
    def list_connectors(self, org_id: str) -> list[Connector]:
        return list(self.session.execute(
            select(Connector).where(Connector.org_id == org_id).order_by(Connector.kind, Connector.name)
        ).scalars().all())

    def get_connector(self, connector_id: str) -> Connector | None:
        return self.session.execute(select(Connector).where(Connector.id == connector_id)).scalars().first()

    def add_connector(self, org_id: str, kind: str, name: str, method: str = "api",
                      mode: str = "passive", config: dict | None = None,
                      env_id: str | None = None, agent_id: str | None = None) -> Connector:
        kind = kind if kind in CONNECTOR_KINDS else "other"
        method = method if method in CONNECTOR_METHODS else "api"
        clean = scrub_secrets(config)
        # agent connectors carry an agent_id (in the dedicated column) so
        # heartbeats can find them; accept it explicitly or via config reference.
        agent_id = agent_id or clean.get("agent_id")
        connector = Connector(
            org_id=org_id, env_id=env_id, kind=kind, name=name, method=method,
            mode=mode if mode in ("passive", "active") else "passive",
            config=clean, status="configured",
            agent_id=str(agent_id) if agent_id else None,
        )
        self.session.add(connector)
        self.session.flush()
        return connector

    def set_connector_status(self, connector_id: str, status: str,
                             test_result: dict | None = None, agent_healthy: bool | None = None) -> Connector | None:
        connector = self.get_connector(connector_id)
        if connector is None:
            return None
        connector.status = status
        connector.last_tested_at = datetime.now(timezone.utc).isoformat()
        if test_result is not None:
            connector.test_result = test_result
        if agent_healthy is not None:
            connector.agent_healthy = agent_healthy
        self.session.flush()
        return connector

    def delete_connector(self, connector_id: str) -> bool:
        connector = self.get_connector(connector_id)
        if connector is None:
            return False
        self.session.delete(connector)
        self.session.flush()
        return True

    def agent_heartbeat(self, agent_id: str, *, version: str | None = None,
                        healthy: bool = True, link: str = "encrypted") -> Connector | None:
        """Record an agent check-in over its encrypted link. Agents are used for
        unreachable/air-gapped environments and send normalized observations."""
        connector = self.session.execute(
            select(Connector).where(Connector.agent_id == agent_id)
        ).scalars().first()
        if connector is None:
            return None
        connector.agent_last_seen_at = datetime.now(timezone.utc)
        connector.agent_healthy = healthy
        connector.agent_link = link if link in {"disconnected", "connecting", "encrypted"} else "encrypted"
        if version:
            connector.agent_version = version
        if healthy and connector.status in {"pending", "configured", "error"}:
            connector.status = "connected"
        self.session.flush()
        return connector

    # -------------------------------------------------------------- discovery
    def create_discovery_run(self, org_id: str, run_type: str = "initial",
                             triggered_by: str | None = None,
                             plan: dict | None = None) -> DiscoveryRun:
        run = DiscoveryRun(org_id=org_id, run_type=run_type, status="planned",
                           triggered_by=triggered_by, plan=plan)
        self.session.add(run)
        self.session.flush()
        return run

    def get_discovery_run(self, run_id: str) -> DiscoveryRun | None:
        return self.session.execute(select(DiscoveryRun).where(DiscoveryRun.id == run_id)).scalars().first()

    def list_discovery_runs(self, org_id: str) -> list[DiscoveryRun]:
        return list(self.session.execute(
            select(DiscoveryRun).where(DiscoveryRun.org_id == org_id)
            .order_by(DiscoveryRun.created_at.desc())
        ).scalars().all())

    def mark_discovery_running(self, run_id: str) -> DiscoveryRun | None:
        run = self.get_discovery_run(run_id)
        if run is None:
            return None
        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        self.session.flush()
        return run

    def complete_discovery_run(self, run_id: str, summary: dict, assets: int,
                               targets: int = 0, status: str = "complete") -> DiscoveryRun | None:
        run = self.session.execute(select(DiscoveryRun).where(DiscoveryRun.id == run_id)).scalars().first()
        if run is None:
            return None
        run.status = status
        run.summary = summary
        run.assets_discovered = assets
        run.targets_registered = targets
        run.finished_at = datetime.now(timezone.utc)
        self.session.flush()
        return run
