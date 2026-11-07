"""Acceptance gate filings (gap analysis §6).

The twelve product acceptance gates pass on filed evidence only. External
gates (RECOVERY, COLLECTOR_QUALIFICATION) are performed outside this platform
and filed here; synthetic evidence never passes them.

Revision ID: 0136
Revises: 0135
Create Date: 2026-11-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0136"
down_revision = "0135"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gate_filings",
        sa.Column("gate", sa.String(length=60), nullable=False),
        sa.Column("performed_by", sa.String(length=200), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("performed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.String(length=20), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_gate_filing_gate", "gate_filings", ["gate"])
    op.create_index("ix_gate_filing_gate_performed", "gate_filings",
                    ["gate", "performed_at"])


def downgrade() -> None:
    op.drop_table("gate_filings")
