"""Governance tickets: state, authorisations and the hash-chained audit document.

The workflow engine lives in :mod:`shared_models.governance` (roles, mandatory
expiries, append-only audit). This table is its storage: the ticket's queryable
identity (id, subject, state, assignee) plus the full document — authorisations
and the audit chain — because the chain is verified as written, never rebuilt
from rows that could drift.

A ticket row is written only through the workflow's own transitions: there is no
update path that sets ``state`` directly, because a state that skipped its audit
event is a state that never happened.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class GovernanceTicket(BaseModel):
    __tablename__ = "governance_tickets"
    __table_args__ = (
        Index("ix_governance_ticket_state", "state"),
    )

    #: the ticket's human id (GOV-1 …), distinct from the row id
    ticket_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True,
                                           index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False, default="OPEN")
    assignee: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    #: the whole workflow document: authorisations, evidence ids, audit chain
    document: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
