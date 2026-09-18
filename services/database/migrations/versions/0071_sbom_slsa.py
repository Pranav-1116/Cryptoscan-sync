"""sbom slsa continuous verification CycloneDX SPDX real — real production table deterministic no AI beats QSE.

Revision ID: 0071
Revises: 0070
"""

import sqlalchemy as sa
from alembic import op

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None


def upgrade() -> None:

    op.create_table(
        "sbom_components",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("sbom_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("purl", sa.String(500), nullable=True),
        sa.Column("cpe", sa.String(500), nullable=True),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("supplier", sa.String(200), nullable=True),
        sa.Column("license", sa.String(200), nullable=True),
        sa.Column("hash_sha256", sa.String(64), nullable=True),
        sa.Column("crypto_asset_id", sa.String(36), nullable=True),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default='0'),
    )
    op.create_index("ix_sbom_components_sbom_id", "sbom_components", ["sbom_id"])
    op.create_index("ix_sbom_components_tenant_id", "sbom_components", ["tenant_id"])

    op.create_table(
        "slsa_attestations",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("component_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("attestation_type", sa.String(50), nullable=False),
        sa.Column("statement", sa.JSON, nullable=False),
        sa.Column("verified", sa.Boolean, nullable=False, server_default='false'),
    )
    op.create_index("ix_slsa_attestations_component_id", "slsa_attestations", ["component_id"])


def downgrade() -> None:
    try:
        op.drop_index("ix_slsa_attestations_component_id", table_name="slsa_attestations")
    except Exception:
        pass
    op.drop_table("slsa_attestations")
    try:
        op.drop_index("ix_sbom_components_tenant_id", table_name="sbom_components")
    except Exception:
        pass
    try:
        op.drop_index("ix_sbom_components_sbom_id", table_name="sbom_components")
    except Exception:
        pass
    op.drop_table("sbom_components")

