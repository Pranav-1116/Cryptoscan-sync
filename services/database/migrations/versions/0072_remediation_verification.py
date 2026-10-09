"""Remediation task tracking + verification store (audit 62 / GAP-006).

Two tables:

1. ``remediation_tasks`` — tracked remediation of one non-compliant finding.
   The finding is snapshotted into ``original_finding`` at creation time so
   the verification verdict can never be rewritten by later evidence pruning.
2. ``remediation_verifications`` — one row per verification run: the result
   enum (VERIFIED | PARTIAL | FAILED | REGRESSION | INCONCLUSIVE), the rescan
   compared against, and the full machine-readable comparison.

Revision ID: 0072
Revises: 0071
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0072"
down_revision = "0071"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("evidence_id", sa.String(64), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("rule_id", sa.String(80), nullable=False),
        sa.Column("category", sa.String(40), nullable=True),
        sa.Column("priority", sa.String(4), nullable=True),
        sa.Column("replace_with", sa.String(80), nullable=True),
        sa.Column("original_finding", sa.JSON(), nullable=False),
        sa.Column("target_location", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("owner", sa.String(200), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_remediation_tasks_tenant", "remediation_tasks", ["tenant_id"])
    op.create_index("ix_remediation_tasks_evidence", "remediation_tasks", ["evidence_id"])
    op.create_index("ix_remediation_tasks_scan", "remediation_tasks", ["scan_id"])
    op.create_index("ix_remediation_tasks_status", "remediation_tasks", ["status"])

    op.create_table(
        "remediation_verifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("task_id", sa.String(36), nullable=False),
        sa.Column("rescan_id", sa.String(36), nullable=True),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("comparison", sa.JSON(), nullable=True),
        sa.Column("verified_by", sa.String(100), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_remediation_ver_tenant", "remediation_verifications", ["tenant_id"])
    op.create_index("ix_remediation_ver_task", "remediation_verifications", ["task_id"])
    op.create_index("ix_remediation_ver_result", "remediation_verifications", ["result"])


def downgrade() -> None:
    op.drop_index("ix_remediation_ver_result", table_name="remediation_verifications")
    op.drop_index("ix_remediation_ver_task", table_name="remediation_verifications")
    op.drop_index("ix_remediation_ver_tenant", table_name="remediation_verifications")
    op.drop_table("remediation_verifications")
    op.drop_index("ix_remediation_tasks_status", table_name="remediation_tasks")
    op.drop_index("ix_remediation_tasks_scan", table_name="remediation_tasks")
    op.drop_index("ix_remediation_tasks_evidence", table_name="remediation_tasks")
    op.drop_index("ix_remediation_tasks_tenant", table_name="remediation_tasks")
    op.drop_table("remediation_tasks")
