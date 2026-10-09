"""Optimistic scan-job locking, policy rule overrides, drift task source (audit 04/05/03).

1. ``scan_jobs.version`` — optimistic-lock counter. Job status updates are
   compare-and-set on the version the writer read, and terminal states
   (COMPLETED/FAILED/CANCELLED) are never left by a non-forced update, so the
   worker-vs-reaper race (audit 04's "lost updates on ScanJob") resolves to a
   detected conflict instead of a silent overwrite.
2. ``policy_rule_overrides`` — tenant-scoped runtime overrides for the YAML
   policy pack (audit 05's missing rule-management surface): disable a rule
   or change its severity per tenant, without editing the reviewed pack.
3. ``remediation_tasks.source``/``source_ref`` — provenance for tasks, so
   drift acknowledgement can auto-open remediation tasks (audit 03's
   drift→remediation link) and they stay queryable afterwards.

Revision ID: 0074
Revises: 0073
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0074"
down_revision = "0073"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "policy_rule_overrides",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("rule_id", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="system"),
        sa.UniqueConstraint("tenant_id", "rule_id", name="uq_policy_rule_override"),
    )
    op.create_index("ix_policy_rule_overrides_tenant", "policy_rule_overrides", ["tenant_id"])
    op.create_index("ix_policy_rule_overrides_rule", "policy_rule_overrides", ["rule_id"])

    op.add_column(
        "remediation_tasks",
        sa.Column("source", sa.String(20), nullable=False, server_default="manual"),
    )
    op.add_column("remediation_tasks", sa.Column("source_ref", sa.String(64), nullable=True))
    op.create_index("ix_remediation_tasks_source_ref", "remediation_tasks", ["source_ref"])


def downgrade() -> None:
    op.drop_index("ix_remediation_tasks_source_ref", table_name="remediation_tasks")
    op.drop_column("remediation_tasks", "source_ref")
    op.drop_column("remediation_tasks", "source")
    op.drop_index("ix_policy_rule_overrides_rule", table_name="policy_rule_overrides")
    op.drop_index("ix_policy_rule_overrides_tenant", table_name="policy_rule_overrides")
    op.drop_table("policy_rule_overrides")
    op.drop_column("scan_jobs", "version")
