"""Retained relationship lifecycle, monotonic source receipts and event journal."""
from alembic import op
import sqlalchemy as sa

revision = "0099"
down_revision = "0098"
branch_labels = None
depends_on = None
TABLES = ("system_dependencies", "release_sbom_bindings", "software_deployments")


def _base():
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
            sa.Column("scope_key", sa.String(80), nullable=False, index=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now())]


def upgrade():
    op.add_column("graph_snapshots", sa.Column("relationship_policy", sa.JSON(), nullable=True))
    op.add_column("graph_snapshots", sa.Column("lifecycle_as_of", sa.DateTime(timezone=True), nullable=True))
    for table in TABLES:
        for col in [sa.Column("lifecycle_state", sa.String(20), nullable=False, server_default="ACTIVE"),
                    sa.Column("lifecycle_source", sa.String(120), nullable=False, server_default="manual"),
                    sa.Column("lifecycle_revision", sa.Integer(), nullable=False, server_default="0"),
                    sa.Column("valid_until", sa.DateTime(timezone=True)),
                    sa.Column("last_confirmed_at", sa.DateTime(timezone=True)),
                    sa.Column("lifecycle_reason", sa.String(500)),
                    sa.Column("lifecycle_evidence_ref", sa.String(500)),
                    sa.Column("last_reconciliation_id", sa.String(36))]:
            op.add_column(table, col)
        op.create_index(f"ix_{table}_lifecycle_source", table, ["lifecycle_source"])
    op.create_table("relationship_sources", *_base(),
                    sa.Column("record_kind", sa.String(30), nullable=False),
                    sa.Column("source_id", sa.String(120), nullable=False),
                    sa.Column("last_sequence", sa.Integer(), nullable=False),
                    sa.UniqueConstraint("scope_key", "record_kind", "source_id", name="uq_relationship_source"),
                    sa.CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END", name="ck_relationship_source_scope"))
    op.create_table("relationship_collections", *_base(),
                    sa.Column("record_kind", sa.String(30), nullable=False),
                    sa.Column("source_id", sa.String(120), nullable=False),
                    sa.Column("collection_key", sa.String(120), nullable=False),
                    sa.Column("sequence", sa.Integer(), nullable=False),
                    sa.Column("outcome", sa.String(20), nullable=False),
                    sa.Column("payload_hash", sa.String(64), nullable=False),
                    sa.Column("result", sa.JSON(), nullable=False),
                    sa.Column("created_by", sa.String(100), nullable=False),
                    sa.UniqueConstraint("scope_key", "record_kind", "source_id", "collection_key", name="uq_relationship_collection_key"),
                    sa.UniqueConstraint("scope_key", "record_kind", "source_id", "sequence", name="uq_relationship_collection_sequence"),
                    sa.CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END", name="ck_relationship_collection_scope"))
    op.create_table("relationship_lifecycle_events", *_base(),
                    sa.Column("record_kind", sa.String(30), nullable=False, index=True),
                    sa.Column("record_id", sa.String(36), nullable=False, index=True),
                    sa.Column("collection_id", sa.String(36), nullable=True, index=True),
                    sa.Column("identity", sa.JSON(), nullable=False),
                    sa.Column("before", sa.JSON(), nullable=False),
                    sa.Column("after", sa.JSON(), nullable=False),
                    sa.Column("reason", sa.String(500), nullable=False),
                    sa.Column("evidence_ref", sa.String(500), nullable=False),
                    sa.Column("created_by", sa.String(100), nullable=False),
                    sa.CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END", name="ck_relationship_event_scope"))


def downgrade():
    with op.batch_alter_table("graph_snapshots") as batch:
        batch.drop_column("relationship_policy")
        batch.drop_column("lifecycle_as_of")
    for table in ("relationship_lifecycle_events", "relationship_collections", "relationship_sources"):
        op.drop_table(table)
    for table in TABLES:
        op.drop_index(f"ix_{table}_lifecycle_source", table_name=table)
        with op.batch_alter_table(table) as batch:
            for col in ("lifecycle_state", "lifecycle_source", "lifecycle_revision", "valid_until", "last_confirmed_at",
                        "lifecycle_reason", "lifecycle_evidence_ref", "last_reconciliation_id"):
                batch.drop_column(col)
