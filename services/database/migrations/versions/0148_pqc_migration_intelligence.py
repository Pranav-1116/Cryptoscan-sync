"""pqc migration intelligence — waves, blockers, interop notes, progress records

Revision ID: 0148
Revises: 0147
Create Date: 2026-11-11
"""

import sqlalchemy as sa
from alembic import op

revision = "0148"
down_revision = "0147"
branch_labels = None
depends_on = None


def _timestamps() -> list:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "pqc_migration_waves",
        sa.Column("id", sa.String(length=36), nullable=False),
        *_timestamps(),
        sa.Column("wave_key", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("scope_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("planned_window", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False,
                  server_default="planned"),
        sa.Column("status_note", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("wave_key"),
    )
    op.create_index("ix_pqc_wave_status_planned", "pqc_migration_waves",
                    ["status", "planned_window"])

    op.create_table(
        "pqc_migration_blockers",
        sa.Column("id", sa.String(length=36), nullable=False),
        *_timestamps(),
        sa.Column("wave_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("state", sa.String(length=20), nullable=False,
                  server_default="open"),
        sa.Column("raised_by", sa.String(length=200), nullable=False),
        sa.Column("raised_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_by", sa.String(length=200), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_note", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["wave_id"], ["pqc_migration_waves.id"]),
    )
    op.create_index("ix_pqc_blocker_wave_state", "pqc_migration_blockers",
                    ["wave_id", "state"])

    op.create_table(
        "pqc_interop_notes",
        sa.Column("id", sa.String(length=36), nullable=False),
        *_timestamps(),
        sa.Column("wave_id", sa.String(length=36), nullable=False),
        sa.Column("peer_system", sa.String(length=200), nullable=False),
        sa.Column("protocol", sa.String(length=120), nullable=False,
                  server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence_ids", sa.JSON(), nullable=False,
                  server_default=sa.text("'[]'")),
        sa.Column("recorded_by", sa.String(length=200), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["wave_id"], ["pqc_migration_waves.id"]),
    )
    op.create_index("ix_pqc_interop_wave_peer", "pqc_interop_notes",
                    ["wave_id", "peer_system"])

    op.create_table(
        "pqc_progress_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        *_timestamps(),
        sa.Column("wave_id", sa.String(length=36), nullable=False),
        sa.Column("claim", sa.Text(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False,
                  server_default=sa.text("'[]'")),
        sa.Column("recorded_by", sa.String(length=200), nullable=False),
        sa.Column("verification_status", sa.String(length=20), nullable=False,
                  server_default="recorded"),
        sa.Column("verified_by", sa.String(length=200), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_note", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["wave_id"], ["pqc_migration_waves.id"]),
    )
    op.create_index("ix_pqc_progress_wave_verif", "pqc_progress_records",
                    ["wave_id", "verification_status"])


def downgrade() -> None:
    op.drop_table("pqc_progress_records")
    op.drop_table("pqc_interop_notes")
    op.drop_table("pqc_migration_blockers")
    op.drop_table("pqc_migration_waves")
