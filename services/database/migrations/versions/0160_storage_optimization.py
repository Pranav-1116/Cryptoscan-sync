"""Storage optimization: content-addressed evidence store and friends.

Revision ID: 0160
Revises: 0159

Spec 2.1/7 — continuous scanning re-collects the same cryptographic
evidence every run. These tables are the storage architecture that keeps
that affordable WITHOUT destroying provenance:

* ``content_objects`` / ``content_object_bodies`` — content-addressed
  storage (SHA-256), zstd-compressed, envelope-encrypted, chunked for
  large evidence. Metadata separate from bytes (the body backend can be
  bank-approved object storage instead of the database). (tenant_id,
  sha256) unique: deduplication is per tenant and never a cross-tenant
  side channel.
* ``evidence_content_links`` — provenance-preserving dedup links. Every
  collection event gets its own row even when the bytes hash identically:
  owners, collection times, source locations and authorization contexts
  are NEVER merged.
* ``snapshot_deltas`` — incremental scan snapshots: deltas between runs,
  unchanged content referenced by hash (shared, stored once), historical
  states preserved by never rewriting a stored delta.
* ``storage_policies`` / ``storage_quotas`` — retention + lifecycle
  policy per evidence category; per-tenant and per-job budgets.
* ``restore_test_records`` — evidence that archived evidence was
  actually recovered and verified.

RLS + grants follow 0151/0152/0157: new tenant tables do not start life
unprotected. tenant_id-is-NULL rows (platform policies) are readable
alongside tenant rows — platform defaults are not secrets.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0160"
down_revision = "0159"
branch_labels = None
depends_on = None

RLS_TABLES = (
    "content_objects",
    "content_object_bodies",
    "evidence_content_links",
    "snapshot_deltas",
    "storage_quotas",
    "restore_test_records",
)
POLICY_TABLE = "storage_policies"


def _tenant_rls(table: str, nullable_tenant: bool) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    null_ok = "tenant_id IS NULL OR " if nullable_tenant else ""
    own = (f"({null_ok}tenant_id::text = cryptoscan_current_tenant() OR "
           "cryptoscan_current_tenant() = '*')")
    op.execute(f"CREATE POLICY tenant_isolation_select ON {table} "
               f"FOR SELECT USING {own}")
    op.execute(f"CREATE POLICY tenant_isolation_insert ON {table} "
               f"FOR INSERT WITH CHECK {own}")
    op.execute(f"CREATE POLICY tenant_isolation_update ON {table} "
               f"FOR UPDATE USING {own} WITH CHECK {own}")
    op.execute(f"CREATE POLICY tenant_isolation_delete ON {table} "
               f"FOR DELETE USING {own}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} "
               "TO cryptoscan_tenant, cryptoscan_platform")


def upgrade() -> None:
    op.create_table(
        "content_objects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("codec", sa.String(12), nullable=False),
        sa.Column("plain_size", sa.BigInteger(), nullable=False),
        sa.Column("stored_size", sa.BigInteger(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("chunk_refs", sa.JSON(), nullable=True),
        sa.Column("parent_sha256", sa.String(64), nullable=True),
        sa.Column("storage_tier", sa.String(12), nullable=False),
        sa.Column("ref_count", sa.BigInteger(), nullable=False),
        sa.Column("body_dropped_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("uq_content_objects_tenant_sha", "content_objects",
                    ["tenant_id", "sha256"], unique=True)
    op.create_index("ix_content_objects_tenant_category", "content_objects",
                    ["tenant_id", "category"])
    op.create_index("ix_content_objects_tenant_tier", "content_objects",
                    ["tenant_id", "storage_tier"])

    op.create_table(
        "content_object_bodies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("object_sha256", sa.String(64), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("bytes_size", sa.BigInteger(), nullable=False),
    )
    op.create_index("uq_content_object_bodies_tenant_sha", "content_object_bodies",
                    ["tenant_id", "object_sha256"], unique=True)

    op.create_table(
        "evidence_content_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("evidence_record_id", sa.String(36),
                  sa.ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=True),
        sa.Column("observation_ref", sa.String(200), nullable=True),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collector", sa.String(120), nullable=False),
        sa.Column("source_location", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(120), nullable=False),
        sa.Column("authorization_context", sa.JSON(), nullable=True),
    )
    op.create_index("ix_evidence_content_links_tenant_sha", "evidence_content_links",
                    ["tenant_id", "content_sha256"])
    op.create_index("ix_evidence_content_links_record", "evidence_content_links",
                    ["evidence_record_id"])

    op.create_table(
        "snapshot_deltas",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("snapshot_id", sa.String(64), nullable=False),
        sa.Column("base_snapshot_id", sa.String(64), nullable=True),
        sa.Column("snapshot_kind", sa.String(32), nullable=False),
        sa.Column("delta_content_sha256", sa.String(64), nullable=False),
        sa.Column("added_count", sa.BigInteger(), nullable=False),
        sa.Column("removed_count", sa.BigInteger(), nullable=False),
        sa.Column("changed_count", sa.BigInteger(), nullable=False),
        sa.Column("unchanged_count", sa.BigInteger(), nullable=False),
        sa.Column("unchanged_refs", sa.JSON(), nullable=True),
    )
    op.create_index("uq_snapshot_deltas_tenant_snapshot", "snapshot_deltas",
                    ["tenant_id", "snapshot_id"], unique=True)
    op.create_index("ix_snapshot_deltas_tenant_base", "snapshot_deltas",
                    ["tenant_id", "base_snapshot_id"])

    op.create_table(
        "storage_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column("hot_days", sa.Integer(), nullable=False),
        sa.Column("warm_days", sa.Integer(), nullable=False),
        sa.Column("compress", sa.Boolean(), nullable=False),
        sa.Column("expired_action", sa.String(12), nullable=False),
    )
    op.create_index("uq_storage_policies_tenant_category", "storage_policies",
                    ["tenant_id", "category"], unique=True)

    op.create_table(
        "storage_quotas",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope", sa.String(12), nullable=False),
        sa.Column("job_id", sa.String(64), nullable=True),
        sa.Column("max_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_objects", sa.BigInteger(), nullable=False),
    )
    op.create_index("uq_storage_quotas_tenant_scope_job", "storage_quotas",
                    ["tenant_id", "scope", "job_id"], unique=True)

    op.create_table(
        "restore_test_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("object_sha256", sa.String(64), nullable=False),
        sa.Column("restored_from_tier", sa.String(12), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("bytes_verified", sa.BigInteger(), nullable=False),
        sa.Column("tested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.String(500), nullable=False),
    )
    op.create_index("ix_restore_test_records_tenant_sha", "restore_test_records",
                    ["tenant_id", "object_sha256"])

    for table in RLS_TABLES:
        _tenant_rls(table, nullable_tenant=False)
    _tenant_rls(POLICY_TABLE, nullable_tenant=True)


def downgrade() -> None:
    for table in (*RLS_TABLES, POLICY_TABLE):
        if op.get_bind().dialect.name == "postgresql":
            for name in ("tenant_isolation_select", "tenant_isolation_insert",
                         "tenant_isolation_update", "tenant_isolation_delete"):
                op.execute(f"DROP POLICY IF EXISTS {name} ON {table}")
    op.drop_index("ix_restore_test_records_tenant_sha", table_name="restore_test_records")
    op.drop_table("restore_test_records")
    op.drop_index("uq_storage_quotas_tenant_scope_job", table_name="storage_quotas")
    op.drop_table("storage_quotas")
    op.drop_index("uq_storage_policies_tenant_category", table_name="storage_policies")
    op.drop_table("storage_policies")
    op.drop_index("ix_snapshot_deltas_tenant_base", table_name="snapshot_deltas")
    op.drop_index("uq_snapshot_deltas_tenant_snapshot", table_name="snapshot_deltas")
    op.drop_table("snapshot_deltas")
    op.drop_index("ix_evidence_content_links_record", table_name="evidence_content_links")
    op.drop_index("ix_evidence_content_links_tenant_sha", table_name="evidence_content_links")
    op.drop_table("evidence_content_links")
    op.drop_index("uq_content_object_bodies_tenant_sha", table_name="content_object_bodies")
    op.drop_table("content_object_bodies")
    op.drop_index("ix_content_objects_tenant_tier", table_name="content_objects")
    op.drop_index("ix_content_objects_tenant_category", table_name="content_objects")
    op.drop_index("uq_content_objects_tenant_sha", table_name="content_objects")
    op.drop_table("content_objects")
