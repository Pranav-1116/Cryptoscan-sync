"""Snapshots and findings from the security control integration layer.

Revision 0133. Creates ``security_control_snapshots`` and ``security_control_findings``.

Guide 181 proved the layer against recorded fixtures and kept its evidence on disk. Guide 182
points it at live controls, and a live read raises the question the file store cannot answer
by itself: *which* read produced this finding, was its chain intact when we read it, and who
collected it?

Two tables answer it.

``security_control_snapshots`` is the chain: one row per read, with the body's content digest,
a per-tenant sequence, the previous row's entry hash, and the worst section state. It is what
``verify`` walks and what ``diff`` compares. The body is *not* stored here — a device
configuration is megabytes, and a row is the wrong place for it; the row points at the body.

``security_control_findings`` is the statements: one row per claim, carrying its fact classes
and its evidence ids. ``CONFIGURED``, ``OBSERVED`` and ``RUNTIME_OBSERVED`` are stored as the
list they are, because the whole point of the three classes is that they do not merge.

Neither table has an update path in the API. A closed snapshot is evidence, and evidence that
can be edited is not evidence.

Revision ID: 0133
Revises: 0132
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0133"
down_revision = "0132"
branch_labels = None
depends_on = None

SNAPSHOTS = "security_control_snapshots"
FINDINGS = "security_control_findings"

#: The policy shape 0132 created, re-stated here rather than copied by import: an alembic
#: revision is a document about one moment, and a migration that depends on another
#: revision's module has a second head the day that module changes. 0132 walked the
#: catalogue and applied its policy to the tables that existed then; these two did not.
SETTING = "cryptoscan.tenant_id"
POLICY = "tenant_isolation"
TENANT_ROLE = "cryptoscan_tenant"
PLATFORM_ROLE = "cryptoscan_platform"


def _apply_tenant_policy(connection, table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {POLICY} ON {table}")
    op.execute(
        f"""
        CREATE POLICY {POLICY} ON {table}
        USING (
            tenant_id IS NULL
            OR tenant_id::text = cryptoscan_current_tenant()
            OR cryptoscan_current_tenant() = '*'
        )
        WITH CHECK (
            tenant_id IS NULL
            OR tenant_id::text = cryptoscan_current_tenant()
            OR cryptoscan_current_tenant() = '*'
        )
        """
    )


def upgrade() -> None:
    op.create_table(
        SNAPSHOTS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("digest", sa.String(80), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("previous_hash", sa.String(80), nullable=False, server_default=""),
        sa.Column("entry_hash", sa.String(80), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("controls", sa.JSON(), nullable=True),
        sa.Column("counts", sa.JSON(), nullable=True),
        sa.Column("body_digest", sa.String(80), nullable=False, server_default=""),
        sa.Column("body_location", sa.String(400), nullable=False, server_default=""),
        sa.Column("body_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("collector", sa.String(120), nullable=False, server_default=""),
        sa.Column("read_state", sa.String(40), nullable=False, server_default="OK"),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("refusals", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("tenant_id", "sequence", name="uq_security_control_snapshot_seq"),
        sa.UniqueConstraint("tenant_id", "digest", name="uq_security_control_snapshot_digest"),
    )
    op.create_index("ix_security_control_snapshots_digest", SNAPSHOTS, ["digest"])
    op.create_index("ix_security_control_snapshot_tenant_captured", SNAPSHOTS,
                    ["tenant_id", "captured_at"])

    op.create_table(
        FINDINGS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("snapshot_id", sa.String(36),
                  sa.ForeignKey(f"{SNAPSHOTS}.id", ondelete="CASCADE"), nullable=False),
        sa.Column("control", sa.String(40), nullable=False),
        sa.Column("vendor", sa.String(120), nullable=True),
        sa.Column("subject", sa.String(400), nullable=True),
        sa.Column("kind", sa.String(40), nullable=False, server_default="STATE"),
        sa.Column("state", sa.String(40), nullable=False),
        sa.Column("facts", sa.JSON(), nullable=True),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("expected", sa.JSON(), nullable=True),
        sa.Column("observed", sa.JSON(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("reason", sa.String(1000), nullable=True),
    )
    op.create_index("ix_security_control_findings_control", FINDINGS, ["control"])
    op.create_index("ix_security_control_findings_state", FINDINGS, ["state"])
    op.create_index("ix_security_control_findings_subject", FINDINGS, ["subject"])
    op.create_index("ix_security_control_finding_snapshot", FINDINGS, ["snapshot_id"])
    op.create_index("ix_security_control_finding_tenant_control", FINDINGS,
                    ["tenant_id", "control", "state"])

    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        for table in (SNAPSHOTS, FINDINGS):
            _apply_tenant_policy(connection, table)
            op.execute(f"DO $$ BEGIN "
                       f"IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{TENANT_ROLE}') "
                       f"THEN GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {TENANT_ROLE}; "
                       f"END IF; END $$")
            op.execute(f"DO $$ BEGIN "
                       f"IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{PLATFORM_ROLE}') "
                       f"THEN GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO "
                       f"{PLATFORM_ROLE}; END IF; END $$")


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        for table in (SNAPSHOTS, FINDINGS):
            op.execute(f"DROP POLICY IF EXISTS {POLICY} ON {table}")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    op.drop_index("ix_security_control_finding_tenant_control", table_name=FINDINGS)
    op.drop_index("ix_security_control_finding_snapshot", table_name=FINDINGS)
    op.drop_index("ix_security_control_findings_subject", table_name=FINDINGS)
    op.drop_index("ix_security_control_findings_state", table_name=FINDINGS)
    op.drop_index("ix_security_control_findings_control", table_name=FINDINGS)
    op.drop_table(FINDINGS)
    op.drop_index("ix_security_control_snapshot_tenant_captured", table_name=SNAPSHOTS)
    op.drop_index("ix_security_control_snapshots_digest", table_name=SNAPSHOTS)
    op.drop_table(SNAPSHOTS)
