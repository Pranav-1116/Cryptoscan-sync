"""P2 deterministic enterprise features: marketplace, data lake, anomaly,
governance approvals and migration validation.

Revision ID: 0046
Revises: 0045
Create Date: 2026-09-03

All five tables are created by the application's schema reconciliation too
(create_all idempotency); this migration keeps the alembic-head schema in
exact parity with the ORM models for fresh/upgraded production databases.
No AI/ML — the columns store metadata, hashes, and rule outputs only.
"""
import sqlalchemy as sa
from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def _audit_cols():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    ]


def upgrade() -> None:
    op.create_table(
        "plugin_packages",
        *_audit_cols(),
        sa.Column("plugin_id", sa.String(128), nullable=False, index=True),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("plugin_type", sa.String(32), nullable=False),
        sa.Column("name", sa.String(200), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("content_sha256", sa.String(64), nullable=False, index=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("signer_key_id", sa.String(128), nullable=True),
        sa.Column("min_platform", sa.String(32), nullable=False, server_default="0.0.0"),
        sa.Column("state", sa.String(20), nullable=False, server_default="UPLOADED", index=True),
        sa.Column("trusted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("author", sa.String(200), nullable=False, server_default=""),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("verify_errors", sa.JSON(), nullable=True),
        sa.Column("enabled_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "lake_export_batches",
        *_audit_cols(),
        sa.Column("lake_id", sa.String(128), nullable=False, index=True),
        sa.Column("batch_id", sa.Integer(), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("record_hashes", sa.JSON(), nullable=False),
        sa.Column("batch_digest", sa.String(64), nullable=False),
        sa.Column("previous_digest", sa.String(64), nullable=True),
        sa.Column("chain_digest", sa.String(64), nullable=False, index=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("signer_key_id", sa.String(128), nullable=True),
        sa.Column("export_kind", sa.String(40), nullable=False, server_default="findings"),
        sa.Column("status", sa.String(20), nullable=False, server_default="SEALED"),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("records", sa.JSON(), nullable=True),
    )

    op.create_table(
        "anomaly_flags",
        *_audit_cols(),
        sa.Column("rule", sa.String(40), nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False, index=True),
        sa.Column("metric", sa.String(128), nullable=False, server_default="", index=True),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("value", sa.Float(), nullable=False, server_default="0"),
        sa.Column("explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("context", sa.JSON(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="OPEN", index=True),
        sa.Column("acknowledged_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "migration_validations",
        *_audit_cols(),
        sa.Column("migration_project_id", sa.String(36), nullable=True, index=True),
        sa.Column("system_id", sa.String(36), nullable=True, index=True),
        sa.Column("stage", sa.String(20), nullable=False, server_default="PRE"),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING", index=True),
        sa.Column("findings_before", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_after", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("regressions", sa.JSON(), nullable=True),
        sa.Column("coverage_delta", sa.JSON(), nullable=True),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("validated_by", sa.String(100), nullable=True),
    )

    op.create_table(
        "governance_approvals",
        *_audit_cols(),
        sa.Column("request_type", sa.String(60), nullable=False, index=True),
        sa.Column("request_ref", sa.String(128), nullable=True, index=True),
        sa.Column("requested_by", sa.String(100), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING", index=True),
        sa.Column("decision", sa.String(20), nullable=True),
        sa.Column("decided_by", sa.String(100), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("policy_rules", sa.JSON(), nullable=True),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="LOW"),
        sa.Column("payload", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("governance_approvals")
    op.drop_table("migration_validations")
    op.drop_table("anomaly_flags")
    op.drop_table("lake_export_batches")
    op.drop_table("plugin_packages")
