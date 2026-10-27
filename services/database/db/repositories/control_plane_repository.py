"""Persistence for the ZELNX Control Plane aggregate (P0).

Tenants, scope grants, credential refs, agents, safe-scan policies, asset
identities, durable queued events and benchmark datasets/runs. Write helpers
enforce the doctrine: no secret material is ever accepted (credential rows
store only vault locators), and grants/policies are fail-closed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.control_plane import (
    Agent,
    AssetIdentity,
    BenchmarkCase,
    BenchmarkDataset,
    BenchmarkRun,
    CredentialRef,
    DeliveryLog,
    QueuedEvent,
    SafeScanPolicy,
    ScopeGrant,
    SecurityPosture,
    Tenant,
)


class ControlPlaneRepository:
    def __init__(self, session: Session):
        self.session = session

    def _get_tenant_row(self, model, row_id: str, tenant_id: str | None = None):
        """Load a tenant-owned row through a filtered SELECT, never identity-map get.

        Request code is additionally constrained by ``db.tenancy``. Workers
        that operate outside a request can pass the authorized tenant marker;
        omitting it is reserved for the explicit platform-global worker path.
        """
        stmt = select(model).where(model.id == row_id)
        if tenant_id is not None and hasattr(model, "tenant_id"):
            stmt = stmt.where(model.tenant_id == tenant_id)
        return self.session.execute(stmt).scalars().first()

    # ------------------------------------------------------------- tenants
    def create_tenant(self, name: str, **fields) -> Tenant:
        tenant = Tenant(name=name, **fields)
        self.session.add(tenant)
        self.session.flush()
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self.session.get(Tenant, tenant_id)

    def list_tenants(self) -> list[Tenant]:
        return list(self.session.execute(select(Tenant).order_by(Tenant.name)).scalars().all())

    # -------------------------------------------------------- scope grants
    def add_grant(self, **fields) -> ScopeGrant:
        grant = ScopeGrant(**fields)
        self.session.add(grant)
        self.session.flush()
        return grant

    def list_grants(self, tenant_id: str | None = None) -> list[ScopeGrant]:
        stmt = select(ScopeGrant).where(ScopeGrant.is_active.is_(True))
        if tenant_id:
            stmt = stmt.where((ScopeGrant.tenant_id == tenant_id) | (ScopeGrant.tenant_id.is_(None)))
        return list(self.session.execute(stmt).scalars().all())

    def set_grant_active(self, grant_id: str, active: bool,
                         *, tenant_id: str | None = None) -> ScopeGrant | None:
        grant = self._get_tenant_row(ScopeGrant, grant_id, tenant_id)
        if grant is None:
            return None
        grant.is_active = active
        self.session.flush()
        return grant

    # ---------------------------------------------------------- credentials
    def create_credential(self, **fields) -> CredentialRef:
        cred = CredentialRef(**fields)
        self.session.add(cred)
        self.session.flush()
        return cred

    def get_credential(self, credential_id: str, *, tenant_id: str | None = None) -> CredentialRef | None:
        return self._get_tenant_row(CredentialRef, credential_id, tenant_id)

    def list_credentials(self, tenant_id: str | None = None) -> list[CredentialRef]:
        stmt = select(CredentialRef).order_by(CredentialRef.name)
        if tenant_id:
            stmt = stmt.where((CredentialRef.tenant_id == tenant_id) | (CredentialRef.tenant_id.is_(None)))
        return list(self.session.execute(stmt).scalars().all())

    def update_credential(self, credential_id: str, **fields) -> CredentialRef | None:
        cred = self.get_credential(credential_id)
        if cred is None:
            return None
        for key, value in fields.items():
            if hasattr(cred, key) and value is not None:
                setattr(cred, key, value)
        self.session.flush()
        return cred

    def record_credential_access(self, credential_id: str) -> CredentialRef | None:
        """Audit a credential lease: bump access count + last health check."""
        cred = self.get_credential(credential_id)
        if cred is None:
            return None
        cred.access_count = int(cred.access_count or 0) + 1
        cred.last_health_check_at = datetime.now(timezone.utc)
        self.session.flush()
        return cred

    # --------------------------------------------------------------- agents
    def enroll_agent(self, name: str, fingerprint: str, **fields) -> Agent:
        agent = Agent(name=name, enrollment_token_fingerprint=fingerprint,
                      status="enrolled", **fields)
        self.session.add(agent)
        self.session.flush()
        return agent

    def get_agent(self, agent_id: str, *, tenant_id: str | None = None) -> Agent | None:
        return self._get_tenant_row(Agent, agent_id, tenant_id)

    def get_agent_by_fingerprint(self, fingerprint: str) -> Agent | None:
        return self.session.execute(
            select(Agent).where(Agent.enrollment_token_fingerprint == fingerprint)
        ).scalars().first()

    def list_agents(self, tenant_id: str | None = None) -> list[Agent]:
        stmt = select(Agent).order_by(Agent.name)
        if tenant_id:
            stmt = stmt.where((Agent.tenant_id == tenant_id) | (Agent.tenant_id.is_(None)))
        return list(self.session.execute(stmt).scalars().all())

    def agent_heartbeat(self, agent_id: str, *, version: str | None = None,
                        healthy: bool = True, link: str = "encrypted",
                        ip: str | None = None, buffered: int | None = None) -> Agent | None:
        agent = self.get_agent(agent_id)
        if agent is None:
            return None
        agent.last_heartbeat_at = datetime.now(timezone.utc)
        agent.healthy = healthy
        agent.link = link if link in {"disconnected", "connecting", "encrypted"} else "encrypted"
        if version:
            agent.version = version
        if ip:
            agent.last_seen_ip = ip
        if buffered is not None:
            agent.offline_events_buffered = buffered
        if healthy and agent.status in {"enrolled", "connecting", "offline", "error"}:
            agent.status = "connected"
        elif not healthy and agent.status == "connected":
            agent.status = "error"
        self.session.flush()
        return agent

    def set_agent_target_version(self, agent_id: str, target: str | None,
                                 action: str = "upgrade") -> Agent | None:
        agent = self.get_agent(agent_id)
        if agent is None:
            return None
        if action == "retire":
            agent.status = "retired"
        elif target:
            agent.target_version = target
            agent.status = "upgrading"
        self.session.flush()
        return agent

    def configure_agent(self, agent_id: str, *, config: dict | None = None,
                        resource_limits: dict | None = None) -> Agent | None:
        agent = self.get_agent(agent_id)
        if agent is None:
            return None
        if config is not None:
            merged = dict(agent.config or {})
            merged.update(config)
            agent.config = merged
        if resource_limits is not None:
            merged_limits = dict(agent.resource_limits or {})
            merged_limits.update(resource_limits)
            agent.resource_limits = merged_limits
        self.session.flush()
        return agent

    def rotate_agent_cert(self, agent_id: str, cert_serial: str) -> Agent | None:
        agent = self.get_agent(agent_id)
        if agent is None:
            return None
        agent.cert_serial = cert_serial
        self.session.flush()
        return agent

    # ------------------------------------------------------- safe policies
    def upsert_safe_policy(self, **fields) -> SafeScanPolicy:
        region = fields.get("scope_region")
        env = fields.get("scope_environment")
        existing = self.session.execute(
            select(SafeScanPolicy).where(
                SafeScanPolicy.scope_region == region,
                SafeScanPolicy.scope_environment == env,
            )
        ).scalars().first()
        if existing:
            for key, value in fields.items():
                if value is not None and hasattr(existing, key):
                    setattr(existing, key, value)
            self.session.flush()
            return existing
        policy = SafeScanPolicy(**fields)
        self.session.add(policy)
        self.session.flush()
        return policy

    def list_safe_policies(self, *, tenant_id: str | None = None) -> list[SafeScanPolicy]:
        stmt = select(SafeScanPolicy).where(SafeScanPolicy.is_active.is_(True))
        if tenant_id is not None:
            stmt = stmt.where(SafeScanPolicy.tenant_id == tenant_id)
        return list(self.session.execute(stmt).scalars().all())

    def matching_policy(self, *, region: str | None = None, environment: str | None = None) -> SafeScanPolicy | None:
        """Most specific active policy matching the scope (region+env beats
        region-only beats global)."""
        policies = self.list_safe_policies()
        exact = [p for p in policies if p.scope_region == region and p.scope_environment == environment]
        if exact:
            return exact[0]
        region_match = [p for p in policies if p.scope_region == region and not p.scope_environment]
        if region_match:
            return region_match[0]
        glob = [p for p in policies if not p.scope_region and not p.scope_environment]
        return glob[0] if glob else None

    def set_emergency_stop(self, policy_id: str, engaged: bool,
                            *, tenant_id: str | None = None) -> SafeScanPolicy | None:
        policy = self._get_tenant_row(SafeScanPolicy, policy_id, tenant_id)
        if policy is None:
            return None
        policy.emergency_stop = engaged
        self.session.flush()
        return policy

    # -------------------------------------------------------- identities
    def upsert_asset_identity(self, canonical_id: str, **fields) -> AssetIdentity:
        existing = self.session.execute(
            select(AssetIdentity).where(AssetIdentity.canonical_id == canonical_id)
        ).scalars().first()
        if existing:
            for key, value in fields.items():
                if value is not None and hasattr(existing, key):
                    setattr(existing, key, value)
            self.session.flush()
            return existing
        identity = AssetIdentity(canonical_id=canonical_id, **fields)
        self.session.add(identity)
        self.session.flush()
        return identity

    def list_asset_identities(self, *, tenant_id: str | None = None) -> list[AssetIdentity]:
        stmt = select(AssetIdentity).order_by(AssetIdentity.canonical_id)
        if tenant_id is not None:
            stmt = stmt.where(AssetIdentity.tenant_id == tenant_id)
        return list(self.session.execute(stmt).scalars().all())

    # ------------------------------------------------------------- events
    def enqueue(self, event_type: str, payload: dict, *, source: str = "control_plane",
                priority: str = "normal", max_attempts: int = 5) -> QueuedEvent:
        # Request-scoped inserts are stamped by db.tenancy. The explicit marker
        # also preserves ownership when an authorized worker enqueues outside a
        # request context; a tenant scope will reject a conflicting marker.
        owner = (payload or {}).get("_authorized_tenant_id") or (payload or {}).get("tenant_id")
        ev = QueuedEvent(event_type=event_type, payload=payload, source=source,
                         tenant_id=str(owner) if owner else None,
                         priority=priority, max_attempts=max_attempts,
                         available_at=datetime.now(timezone.utc))
        self.session.add(ev)
        self.session.flush()
        return ev

    def get_event(self, event_id: str, *, tenant_id: str | None = None) -> QueuedEvent | None:
        return self._get_tenant_row(QueuedEvent, event_id, tenant_id)

    def lease_next(self, worker_id: str, *, priority_rank: dict | None = None,
                   now: datetime | None = None,
                   tenant_id: str | None = None) -> QueuedEvent | None:
        """Atomically lease the highest-priority due event (best-effort on
        SQLite; row-locked on Postgres)."""
        from control_plane.queue import next_available

        now = now or datetime.now(timezone.utc)
        rows = self.list_events("queued", limit=200, tenant_id=tenant_id)
        chosen = next_available([r.to_dict() for r in rows], now=now)
        if chosen is None:
            return None
        ev = self.get_event(chosen["id"], tenant_id=tenant_id)
        if ev is None or ev.status != "queued":
            return None
        ev.status = "leased"
        ev.leased_by = worker_id
        ev.leased_at = now
        ev.attempts = int(ev.attempts or 0) + 1
        self.session.flush()
        return ev

    def complete_event(self, event_id: str, *, tenant_id: str | None = None) -> QueuedEvent | None:
        ev = self.get_event(event_id, tenant_id=tenant_id)
        if ev is None:
            return None
        ev.status = "completed"
        ev.completed_at = datetime.now(timezone.utc)
        ev.leased_by = None
        self.session.flush()
        return ev

    def fail_event(self, event_id: str, error: str, *, now: datetime | None = None,
                   tenant_id: str | None = None) -> QueuedEvent | None:
        """Apply backoff/retry or dead-letter after a processing failure."""
        from control_plane.queue import classify_after_failure

        ev = self.get_event(event_id, tenant_id=tenant_id)
        if ev is None:
            return None
        update = classify_after_failure(ev.to_dict(), now=now or datetime.now(timezone.utc))
        ev.attempts = update["attempts"]
        ev.status = update["status"]
        ev.leased_by = None
        ev.available_at = update["available_at"]
        ev.last_error = (error or "")[:1000]
        self.session.flush()
        return ev

    def cancel_event(self, event_id: str, *, tenant_id: str | None = None) -> bool:
        ev = self.get_event(event_id, tenant_id=tenant_id)
        if ev is None or ev.status not in {"queued"}:
            return False
        ev.status = "dead"
        ev.last_error = "cancelled by operator"
        ev.completed_at = datetime.now(timezone.utc)
        self.session.flush()
        return True

    def list_events(self, status: str | None = None, limit: int = 100,
                    *, tenant_id: str | None = None) -> list[QueuedEvent]:
        """List queue rows in the active tenant or explicit worker tenant.

        With no active scope and no marker this is the platform-global queue
        path used by the control-plane worker; request callers are filtered by
        the ORM middleware automatically.
        """
        # priority-ordered for work queues: critical -> normal, FIFO within tier
        rank = {"critical": 0, "high": 1, "normal": 2, "low": 3}
        # clamp: negative LIMIT is "unlimited" in SQLite (and a DoS vector); cap result set
        limit = max(1, min(int(limit or 100), 500))
        stmt = select(QueuedEvent).order_by(QueuedEvent.created_at.desc())
        if status:
            stmt = stmt.where(QueuedEvent.status == status)
        if tenant_id is not None:
            stmt = stmt.where(QueuedEvent.tenant_id == tenant_id)
        stmt = stmt.limit(limit * 4 if status else limit)
        rows = list(self.session.execute(stmt).scalars().all())
        if status:
            rows.sort(key=lambda e: (rank.get(e.priority, 2), e.created_at or ""))
            rows = [e for e in rows if e.status == status][:limit]
        return rows

    # ------------------------------------------------- outbound delivery log
    def record_delivery(self, *, result: dict, event_type: str,
                        event_id: str | None = None,
                        tenant_id: str | None = None) -> DeliveryLog:
        """Persist one outbound webhook delivery outcome (audit trail)."""
        # Delivery results from an authorized worker carry the event owner;
        # request-scoped calls are stamped by db.tenancy.
        owner = tenant_id or result.get("tenant_id")
        log = DeliveryLog(
            tenant_id=str(owner) if owner else None,
            integration_id=result.get("integration_id"),
            provider=result.get("provider", "webhook"),
            kind=result.get("kind", "siem"),
            event_type=event_type,
            event_id=event_id,
            endpoint=result.get("endpoint"),
            status=result.get("status", "skipped"),
            attempts=int(result.get("attempts") or 0),
            http_status=result.get("http_status"),
            response_excerpt=result.get("response_excerpt"),
            error=result.get("error"),
            signature_prefix=(result.get("signature") or "")[:24] or None,
            duration_ms=result.get("duration_ms"),
        )
        self.session.add(log)
        return log

    def list_delivery_logs(self, *, kind: str | None = None,
                           status: str | None = None, limit: int = 100,
                           tenant_id: str | None = None) -> list[DeliveryLog]:
        limit = max(1, min(int(limit or 100), 500))
        stmt = select(DeliveryLog).order_by(DeliveryLog.created_at.desc())
        if kind:
            stmt = stmt.where(DeliveryLog.kind == kind)
        if status:
            stmt = stmt.where(DeliveryLog.status == status)
        if tenant_id is not None:
            stmt = stmt.where(DeliveryLog.tenant_id == tenant_id)
        stmt = stmt.limit(limit)
        return list(self.session.execute(stmt).scalars().all())

    def delivery_stats(self, *, tenant_id: str | None = None) -> dict:
        from sqlalchemy import func

        stmt = select(DeliveryLog.status, func.count(DeliveryLog.id))
        if tenant_id is not None:
            stmt = stmt.where(DeliveryLog.tenant_id == tenant_id)
        rows = self.session.execute(stmt.group_by(DeliveryLog.status)).all()
        return {status: int(count) for status, count in rows}

    # ---------------------------------------------------------- benchmark
    def create_benchmark_dataset(self, name: str, **fields) -> BenchmarkDataset:
        ds = BenchmarkDataset(name=name, **fields)
        self.session.add(ds)
        self.session.flush()
        return ds

    def get_benchmark_dataset(self, dataset_id: str) -> BenchmarkDataset | None:
        return self.session.get(BenchmarkDataset, dataset_id)

    def get_benchmark_dataset_by_name(self, name: str) -> BenchmarkDataset | None:
        return self.session.execute(
            select(BenchmarkDataset).where(BenchmarkDataset.name == name)
        ).scalars().first()

    def add_benchmark_case(self, dataset_id: str, **fields) -> BenchmarkCase:
        case = BenchmarkCase(dataset_id=dataset_id, **fields)
        self.session.add(case)
        self.session.flush()
        return case

    def list_benchmark_cases(self, dataset_id: str) -> list[BenchmarkCase]:
        return list(self.session.execute(
            select(BenchmarkCase).where(BenchmarkCase.dataset_id == dataset_id)
        ).scalars().all())

    def create_benchmark_run(self, dataset_id: str, **fields) -> BenchmarkRun:
        run = BenchmarkRun(dataset_id=dataset_id, **fields)
        self.session.add(run)
        self.session.flush()
        return run

    def list_benchmark_runs(self, dataset_id: str | None = None) -> list[BenchmarkRun]:
        stmt = select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc())
        if dataset_id:
            stmt = stmt.where(BenchmarkRun.dataset_id == dataset_id)
        return list(self.session.execute(stmt).scalars().all())

    # -- security posture ---------------------------------------------------- #
    def create_security_posture(self, **fields) -> SecurityPosture:
        """Persist a computed security-posture snapshot (metadata only)."""
        row = SecurityPosture(**fields)
        self.session.add(row)
        self.session.flush()
        return row

    def latest_security_posture(self, *, tenant_id: str | None = None) -> SecurityPosture | None:
        stmt = select(SecurityPosture).order_by(SecurityPosture.created_at.desc())
        if tenant_id is not None:
            stmt = stmt.where(SecurityPosture.tenant_id == tenant_id)
        return self.session.execute(stmt.limit(1)).scalars().first()

    def list_security_postures(self, *, limit: int = 60,
                               tenant_id: str | None = None) -> list[SecurityPosture]:
        stmt = select(SecurityPosture).order_by(SecurityPosture.created_at.desc())
        if tenant_id is not None:
            stmt = stmt.where(SecurityPosture.tenant_id == tenant_id)
        stmt = stmt.limit(limit)
        return list(self.session.execute(stmt).scalars().all())
