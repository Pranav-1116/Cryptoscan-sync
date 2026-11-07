"""Roadmap operations tables: governance tickets, deployment attestations,
custody map, discovery qualifications, external validation filings, coverage
batches.

These are the storage behind the roadmap's last three lines: governance
workflows (ticket + hash-chained audit document), deployment/control readiness
(attestations + the bank's custody map), discovery qualification (what each
collector may actually claim), external validation (acts performed OUTSIDE the
platform, filed here as evidence), and estate coverage (per-collection batches
so a missing asset never silently becomes a clean result).

Revision ID: 0135
Revises: 0134
Create Date: 2026-11-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0135"
down_revision = "0134"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "governance_tickets",
        sa.Column("ticket_id", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("assignee", sa.String(length=120), nullable=True),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_governance_ticket_ticket_id", "governance_tickets",
                    ["ticket_id"], unique=True)
    op.create_index("ix_governance_ticket_state", "governance_tickets", ["state"])

    op.create_table(
        "deployment_attestations",
        sa.Column("control", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_deployment_attestation_control", "deployment_attestations",
                    ["control"])
    op.create_index("ix_deployment_attestation_control_observed",
                    "deployment_attestations", ["control", "observed_at"])

    op.create_table(
        "deployment_custody_entries",
        sa.Column("custody_class", sa.String(length=40), nullable=False),
        sa.Column("controller", sa.String(length=120), nullable=False),
        sa.Column("location", sa.String(length=255), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_deployment_custody_entry_class",
                    "deployment_custody_entries", ["custody_class"])

    op.create_table(
        "discovery_qualifications",
        sa.Column("collector", sa.String(length=120), nullable=False),
        sa.Column("family", sa.String(length=120), nullable=False),
        sa.Column("state", sa.String(length=30), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_discovery_qualification_collector", "discovery_qualifications",
                    ["collector"])
    op.create_index("ix_discovery_qualification_family", "discovery_qualifications",
                    ["family"])
    op.create_index("ix_discovery_qualification_collector_family",
                    "discovery_qualifications", ["collector", "family"])

    op.create_table(
        "external_validations",
        sa.Column("kind", sa.String(length=60), nullable=False),
        sa.Column("performed_by", sa.String(length=200), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("performed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scope", sa.String(length=500), nullable=False),
        sa.Column("result", sa.String(length=20), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_external_validation_kind", "external_validations", ["kind"])
    op.create_index("ix_external_validation_kind_performed", "external_validations",
                    ["kind", "performed_at"])

    op.create_table(
        "coverage_reports",
        sa.Column("batch_id", sa.String(length=80), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_targets", sa.Integer(), nullable=True),
        sa.Column("discovered_assets", sa.Integer(), nullable=True),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_coverage_report_batch_id", "coverage_reports",
                    ["batch_id"], unique=True)
    op.create_index("ix_coverage_report_captured", "coverage_reports", ["captured_at"])


def downgrade() -> None:
    op.drop_table("coverage_reports")
    op.drop_table("external_validations")
    op.drop_table("discovery_qualifications")
    op.drop_table("deployment_custody_entries")
    op.drop_table("deployment_attestations")
    op.drop_table("governance_tickets")
