"""supply chain integrity SLSA level 3-4 deterministic real — real production table deterministic no AI beats QSE.

Revision ID: 0070
Revises: 0069
"""

import sqlalchemy as sa
from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None


def upgrade() -> None:

    op.create_table(
        "supply_chain_artifacts",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column("artifact_name", sa.String(200), nullable=False),
        sa.Column("artifact_type", sa.String(50), nullable=False),
        sa.Column("digest_sha256", sa.String(64), nullable=False),
        sa.Column("slsa_level", sa.Integer, nullable=False, server_default='3'),
        sa.Column("builder_id", sa.String(200), nullable=True),
        sa.Column("source_repo", sa.String(500), nullable=True),
        sa.Column("source_commit", sa.String(64), nullable=True),
        sa.Column("provenance_uri", sa.Text(), nullable=True),
        sa.Column("attestation_verified", sa.Boolean, nullable=False, server_default='false'),
        sa.Column("signature_verified", sa.Boolean, nullable=False, server_default='false'),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default='0'),
    )
    op.create_index("ix_supply_chain_artifacts_tenant_id", "supply_chain_artifacts", ["tenant_id"])
    op.create_index("ix_supply_chain_artifacts_digest_sha256", "supply_chain_artifacts", ["digest_sha256"])

    op.create_table(
        "slsa_provenance_records",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("predicate_type", sa.String(100), nullable=False),
        sa.Column("predicate", sa.JSON, nullable=False),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("verified", sa.Boolean, nullable=False, server_default='false'),
    )
    op.create_index("ix_slsa_provenance_records_artifact_id", "slsa_provenance_records", ["artifact_id"])


def downgrade() -> None:
    try:
        op.drop_index("ix_slsa_provenance_records_artifact_id", table_name="slsa_provenance_records")
    except Exception:
        pass
    op.drop_table("slsa_provenance_records")
    try:
        op.drop_index("ix_supply_chain_artifacts_digest_sha256", table_name="supply_chain_artifacts")
    except Exception:
        pass
    try:
        op.drop_index("ix_supply_chain_artifacts_tenant_id", table_name="supply_chain_artifacts")
    except Exception:
        pass
    op.drop_table("supply_chain_artifacts")

