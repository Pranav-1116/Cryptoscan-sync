"""CryptoLog event store (docs/cryptolog/01_PRODUCT_SPEC.md).

Four tables: canonical events (originals immutable), corrections with
their own provenance, alerts with an append-only transition history, and
signed integrity checkpoints. NULL tenant_id means platform estate.

Revision ID: 0137
Revises: 0136
Create Date: 2026-11-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0137"
down_revision = "0136"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cryptolog_events",
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("partition_id", sa.String(length=120), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("deduplication_key", sa.String(length=200), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("category", sa.String(length=40), nullable=False),
        sa.Column("logging_kind", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("investigation_status", sa.String(length=40), nullable=False),
        sa.Column("telemetry_mode", sa.String(length=20), nullable=False),
        sa.Column("approval_ref", sa.String(length=120), nullable=True),
        sa.Column("asset_id", sa.String(length=80), nullable=False),
        sa.Column("business_system_id", sa.String(length=80), nullable=True),
        sa.Column("source", sa.JSON(), nullable=False),
        sa.Column("cryptographic_context", sa.JSON(), nullable=False),
        sa.Column("observation", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("relationships", sa.JSON(), nullable=False),
        sa.Column("processing", sa.JSON(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cryptolog_events_event_id", "cryptolog_events", ["event_id"], unique=True)
    op.create_index("ix_cryptolog_events_partition_id", "cryptolog_events", ["partition_id"])
    op.create_index("ix_cryptolog_events_event_hash", "cryptolog_events", ["event_hash"])
    op.create_index("ix_cryptolog_events_deduplication_key", "cryptolog_events", ["deduplication_key"])
    op.create_index("ix_cryptolog_events_event_type", "cryptolog_events", ["event_type"])
    op.create_index("ix_cryptolog_events_category", "cryptolog_events", ["category"])
    op.create_index("ix_cryptolog_events_severity", "cryptolog_events", ["severity"])
    op.create_index("ix_cryptolog_events_asset_id", "cryptolog_events", ["asset_id"])
    op.create_index("ix_cryptolog_events_business_system_id", "cryptolog_events", ["business_system_id"])
    op.create_index("ix_cryptolog_events_tenant_created", "cryptolog_events",
                    ["tenant_id", "created_at"])

    op.create_table(
        "cryptolog_event_corrections",
        sa.Column("corrects_event_id", sa.String(length=64), nullable=False),
        sa.Column("original_hash", sa.String(length=64), nullable=False),
        sa.Column("corrected_event", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cryptolog_event_corrections_corrects_event_id",
                    "cryptolog_event_corrections", ["corrects_event_id"])

    op.create_table(
        "cryptolog_alerts",
        sa.Column("alert_id", sa.String(length=80), nullable=False),
        sa.Column("rule_id", sa.String(length=20), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("asset_id", sa.String(length=80), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("state", sa.String(length=30), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("basis", sa.JSON(), nullable=False),
        sa.Column("what_is_proven", sa.JSON(), nullable=False),
        sa.Column("what_is_not_proven", sa.JSON(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.String(length=40), nullable=False),
        sa.Column("transitions", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cryptolog_alerts_alert_id", "cryptolog_alerts", ["alert_id"], unique=True)
    op.create_index("ix_cryptolog_alerts_rule_id", "cryptolog_alerts", ["rule_id"])
    op.create_index("ix_cryptolog_alerts_event_id", "cryptolog_alerts", ["event_id"])
    op.create_index("ix_cryptolog_alerts_asset_id", "cryptolog_alerts", ["asset_id"])
    op.create_index("ix_cryptolog_alerts_severity", "cryptolog_alerts", ["severity"])
    op.create_index("ix_cryptolog_alerts_state", "cryptolog_alerts", ["state"])
    op.create_index("ix_cryptolog_alerts_occurred_at", "cryptolog_alerts", ["occurred_at"])

    op.create_table(
        "cryptolog_checkpoints",
        sa.Column("checkpoint_ref", sa.String(length=80), nullable=False),
        sa.Column("algorithm", sa.String(length=20), nullable=False),
        sa.Column("leaf_count", sa.Integer(), nullable=False),
        sa.Column("merkle_root", sa.String(length=64), nullable=False),
        sa.Column("head_hash", sa.String(length=64), nullable=False),
        sa.Column("chain_head_event_id", sa.String(length=64), nullable=True),
        sa.Column("window", sa.JSON(), nullable=False),
        sa.Column("signer_id", sa.String(length=120), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("retention_ref", sa.String(length=120), nullable=False),
        sa.Column("previous_checkpoint", sa.JSON(), nullable=False),
        sa.Column("verification_notes", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cryptolog_checkpoints_checkpoint_ref", "cryptolog_checkpoints",
                    ["checkpoint_ref"], unique=True)


def downgrade() -> None:
    op.drop_table("cryptolog_checkpoints")
    op.drop_table("cryptolog_alerts")
    op.drop_table("cryptolog_event_corrections")
    op.drop_table("cryptolog_events")
