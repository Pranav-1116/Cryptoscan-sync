"""Audit log hash chain (Week 57-58): tamper-evident audit trail.

Revision ID: 0025
Revises: 0024
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("chain_sequence", sa.Integer(), nullable=True))
    op.add_column("audit_log", sa.Column("previous_hash", sa.String(64), nullable=True))
    op.add_column("audit_log", sa.Column("entry_hash", sa.String(64), nullable=True))
    op.create_index("ix_audit_log_chain_sequence", "audit_log", ["chain_sequence"])
    op.create_index("ix_audit_log_entry_hash", "audit_log", ["entry_hash"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_entry_hash", table_name="audit_log")
    op.drop_index("ix_audit_log_chain_sequence", table_name="audit_log")
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "previous_hash")
    op.drop_column("audit_log", "chain_sequence")
