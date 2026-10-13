"""Durable compliance records (§4.3, round 47).

Persisted evidence packs (content-addressed, served verbatim) and reviewer
attestations (JWS over an exact pinned pack, re-verified on read) so the
requirements register can map each requirement to exact evidence, gaps,
expiry and reviewer sign-off — none of which can live in request memory.
"""

from alembic import op
import sqlalchemy as sa

revision = "0091"
down_revision = "0090"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_evidence_packs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("pack_sha256", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.UniqueConstraint("pack_sha256", name="uq_compliance_pack_sha"),
    )
    op.create_index("ix_compliance_evidence_packs_pack_sha256", "compliance_evidence_packs", ["pack_sha256"])
    op.create_index("ix_compliance_evidence_packs_tenant_id", "compliance_evidence_packs", ["tenant_id"])

    op.create_table(
        "compliance_attestations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "pack_id", sa.String(36), sa.ForeignKey("compliance_evidence_packs.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("pack_sha256", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(120), nullable=False),
        sa.Column("signed_by", sa.String(120), nullable=False),
        sa.Column("jws", sa.Text(), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
    )
    op.create_index("ix_compliance_attestations_pack_id", "compliance_attestations", ["pack_id"])
    op.create_index("ix_compliance_attestations_pack_sha256", "compliance_attestations", ["pack_sha256"])
    op.create_index("ix_compliance_attestations_tenant_id", "compliance_attestations", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_compliance_attestations_tenant_id", table_name="compliance_attestations")
    op.drop_index("ix_compliance_attestations_pack_sha256", table_name="compliance_attestations")
    op.drop_index("ix_compliance_attestations_pack_id", table_name="compliance_attestations")
    op.drop_table("compliance_attestations")
    op.drop_index("ix_compliance_evidence_packs_tenant_id", table_name="compliance_evidence_packs")
    op.drop_index("ix_compliance_evidence_packs_pack_sha256", table_name="compliance_evidence_packs")
    op.drop_table("compliance_evidence_packs")
