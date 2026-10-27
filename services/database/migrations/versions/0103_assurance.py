"""Partial collection receipts and exact-estate immutable assurance revisions."""
from alembic import op
import sqlalchemy as sa

revision = "0103"
down_revision = "0102"
branch_labels = depends_on = None


def base():
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("tenant_id", sa.String(36))]


def upgrade():
    scope = "scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END"
    op.create_table("assurance_revisions", *base(),
        sa.Column("scope_key", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("subject_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False), sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False), sa.Column("previous_sha256", sa.String(64)),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.CheckConstraint(scope, name="ck_assurance_scope"),
        sa.UniqueConstraint("scope_key", "kind", "subject_id", "revision", name="uq_assurance_revision"))
    op.create_table("assurance_blobs", *base(),
        sa.Column("scope_key", sa.String(80), nullable=False), sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("byte_count", sa.Integer, nullable=False), sa.Column("data", sa.LargeBinary, nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False), sa.CheckConstraint(scope, name="ck_assurance_blob_scope"))
    op.create_table("collection_phase_receipts", *base(),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False), sa.Column("endpoint", sa.Text, nullable=False),
        sa.Column("phase", sa.String(40), nullable=False), sa.Column("state", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("observation_succeeded", sa.Boolean), sa.Column("observation", sa.JSON),
        sa.Column("observation_sha256", sa.String(64)), sa.Column("reason", sa.String(80)),
        sa.UniqueConstraint("job_id", "ordinal", name="uq_collection_phase_ordinal"))
    for name, columns in {
        "assurance_revisions": ["tenant_id", "scope_key", "kind", "subject_id"],
        "assurance_blobs": ["tenant_id", "scope_key"],
        "collection_phase_receipts": ["tenant_id", "job_id"],
    }.items():
        for column in columns:
            op.create_index(f"ix_{name}_{column}", name, [column])


def downgrade():
    for name in ("collection_phase_receipts", "assurance_blobs", "assurance_revisions"):
        op.drop_table(name)
