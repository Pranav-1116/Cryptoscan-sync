"""Evidence dispositions (§4.2 P0, round 40).

Append-only operator decision records for scans whose historical
evidence still contains fields the safe response projection strips
(raw snippets, raw transformations, detector extras). Recording a
disposition never mutates finding_data, chain links, manifests or
signatures — physical purge at rest stays an operator/DBA action with
backup rotation; this table is the auditable tombstone trail.
"""

from alembic import op
import sqlalchemy as sa

revision = "0088"
down_revision = "0087"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_dispositions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False),
        sa.Column("decided_by", sa.String(120), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("triggering_fields", sa.JSON(), nullable=True),
        sa.Column("affected_records", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
    )
    op.create_index("ix_evidence_dispositions_scan_id",
                    "evidence_dispositions", ["scan_id"])
    op.create_index("ix_evidence_dispositions_tenant_id",
                    "evidence_dispositions", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_evidence_dispositions_scan_id", table_name="evidence_dispositions")
    op.drop_table("evidence_dispositions")
