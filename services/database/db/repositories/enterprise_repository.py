"""Persistence for the P1 enterprise layer."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.control_plane import QueuedEvent
from db.models.enterprise import (
    ComplianceControl,
    ComplianceStatus,
    CryptoKnowledgeEntry,
    Integration,
    PolicyDocument,
    PolicyEvaluation,
    Region,
    Ticket,
)


class EnterpriseRepository:
    def __init__(self, session: Session):
        self.session = session

    # -------------------------------------------------------------- policies
    def upsert_policy(self, *, name: str, version: str, **fields) -> PolicyDocument:
        existing = self.session.execute(
            select(PolicyDocument).where(PolicyDocument.name == name)
        ).scalars().first()
        if existing:
            existing.version = version
            for k, v in fields.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, v)
            self.session.flush()
            return existing
        doc = PolicyDocument(name=name, version=version, **fields)
        self.session.add(doc)
        self.session.flush()
        return doc

    def list_policies(self) -> list[PolicyDocument]:
        return list(self.session.execute(
            select(PolicyDocument).where(PolicyDocument.is_active.is_(True))
        ).scalars().all())

    def record_evaluation(self, **fields) -> PolicyEvaluation:
        rec = PolicyEvaluation(**fields)
        self.session.add(rec)
        self.session.flush()
        return rec

    # ------------------------------------------------------------ compliance
    def upsert_control(self, *, framework: str, control_id: str, **fields) -> ComplianceControl:
        existing = self.session.execute(
            select(ComplianceControl).where(
                ComplianceControl.framework == framework,
                ComplianceControl.control_id == control_id)
        ).scalars().first()
        if existing:
            for k, v in fields.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, v)
            self.session.flush()
            return existing
        c = ComplianceControl(framework=framework, control_id=control_id, **fields)
        self.session.add(c)
        self.session.flush()
        return c

    def list_controls(self, framework: str | None = None) -> list[ComplianceControl]:
        stmt = select(ComplianceControl)
        if framework:
            stmt = stmt.where(ComplianceControl.framework == framework)
        return list(self.session.execute(stmt).scalars().all())

    def record_compliance_status(self, **fields) -> ComplianceStatus:
        rec = ComplianceStatus(**fields)
        self.session.add(rec)
        self.session.flush()
        return rec

    # ------------------------------------------------------------------ ITSM
    def create_ticket(self, *, title: str, created_by: str | None = None, **fields) -> Ticket:
        ticket = Ticket(title=title, **fields)
        ticket.history = [{"at": datetime.now(timezone.utc).isoformat(),
                           "from": None, "to": "open", "by": created_by or "system"}]
        self.session.add(ticket)
        self.session.flush()
        return ticket

    def get_ticket(self, ticket_id: str) -> Ticket | None:
        return self.session.get(Ticket, ticket_id)

    def transition_ticket(self, ticket_id: str, new_state: str, actor: str) -> Ticket | None:
        ticket = self.session.get(Ticket, ticket_id)
        if ticket is None:
            return None
        history = list(ticket.history or [])
        history.append({"at": datetime.now(timezone.utc).isoformat(),
                        "from": ticket.state, "to": new_state, "by": actor})
        ticket.state = new_state
        ticket.history = history
        self.session.flush()
        return ticket

    def list_tickets(self) -> list[Ticket]:
        return list(self.session.execute(
            select(Ticket).order_by(Ticket.created_at.desc())).scalars().all())

    # ------------------------------------------------------------ integrations
    def upsert_integration(self, *, kind: str, provider: str, name: str, **fields) -> Integration:
        existing = self.session.execute(
            select(Integration).where(Integration.kind == kind, Integration.name == name)
        ).scalars().first()
        if existing:
            existing.provider = provider
            for k, v in fields.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, v)
            self.session.flush()
            return existing
        i = Integration(kind=kind, provider=provider, name=name, **fields)
        self.session.add(i)
        self.session.flush()
        return i

    def list_integrations(self) -> list[Integration]:
        return list(self.session.execute(select(Integration)).scalars().all())

    def mark_integration_synced(self, integration_id: str, status: str) -> None:
        i = self.session.get(Integration, integration_id)
        if i:
            i.last_sync_at = datetime.now(timezone.utc).isoformat()
            i.last_sync_status = status
            self.session.flush()

    def enqueue_siem_event(self, normalized: dict) -> QueuedEvent:
        ev = QueuedEvent(event_type=f"siem.{normalized.get('category', 'event')}",
                         payload=normalized, source=f"siem:{normalized.get('provider')}",
                         priority="high" if normalized.get("category") == "alert" else "normal",
                         available_at=datetime.now(timezone.utc))
        self.session.add(ev)
        self.session.flush()
        return ev

    # -------------------------------------------------------------- regions
    def upsert_region(self, *, code: str, **fields) -> Region:
        existing = self.session.execute(
            select(Region).where(Region.code == code)).scalars().first()
        if existing:
            for k, v in fields.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, v)
            self.session.flush()
            return existing
        r = Region(code=code, **fields)
        self.session.add(r)
        self.session.flush()
        return r

    def list_regions(self) -> list[Region]:
        return list(self.session.execute(select(Region)).scalars().all())

    # ------------------------------------------------------------- crypto KB
    def upsert_kb_entry(self, *, algorithm: str, **fields) -> CryptoKnowledgeEntry:
        existing = self.session.execute(
            select(CryptoKnowledgeEntry).where(CryptoKnowledgeEntry.algorithm == algorithm)
        ).scalars().first()
        if existing:
            for k, v in fields.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, v)
            self.session.flush()
            return existing
        e = CryptoKnowledgeEntry(algorithm=algorithm, **fields)
        self.session.add(e)
        self.session.flush()
        return e

    def get_kb_entry(self, algorithm: str) -> CryptoKnowledgeEntry | None:
        from control_plane.knowledge import _normalize

        return self.session.execute(
            select(CryptoKnowledgeEntry).where(CryptoKnowledgeEntry.algorithm == _normalize(algorithm))
        ).scalars().first()

    def list_kb_entries(self) -> list[CryptoKnowledgeEntry]:
        return list(self.session.execute(select(CryptoKnowledgeEntry)).scalars().all())

    # ------------------------------------------------- live findings access
    def live_findings(self, limit: int = 500) -> list[dict]:
        """Read live scanner findings (runtime) as plain dicts for policy
        evaluation. Works even when the runtime table is empty."""
        try:
            from db.models.runtime_finding import RuntimeFinding

            rows = list(self.session.execute(
                select(RuntimeFinding).order_by(RuntimeFinding.last_seen_at.desc()).limit(limit)
            ).scalars())
            return [r.to_dict() if hasattr(r, "to_dict") else dict(r.__dict__) for r in rows]
        except Exception:
            return []
