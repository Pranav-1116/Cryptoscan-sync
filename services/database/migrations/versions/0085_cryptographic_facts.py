"""Cryptographic fact rows (advanced/51 P0#1 write-side step, round 35).

One row per cryptographic fact — (algorithm, purpose, file, key size,
mode) — with observation counters and evidence references. Derived and
fully rebuildable from the evidence table; identity matches
``db.fact_projection.fact_key`` exactly.
"""

from alembic import op
import sqlalchemy as sa

revision = "0085"
down_revision = "0084"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cryptographic_facts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("algorithm", sa.String(80), nullable=False),
        sa.Column("purpose", sa.String(50), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("mode", sa.String(50), nullable=True),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanners", sa.JSON(), nullable=True),
        sa.Column("hardcoded_key_observations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("rebuilt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "algorithm", "purpose", "file_path", "key_size", "mode",
            name="uq_fact_identity"),
    )
    op.create_index("ix_facts_algorithm", "cryptographic_facts", ["algorithm"])
    op.create_index("ix_facts_file", "cryptographic_facts", ["file_path"])


def downgrade() -> None:
    op.drop_index("ix_facts_file", table_name="cryptographic_facts")
    op.drop_index("ix_facts_algorithm", table_name="cryptographic_facts")
    op.drop_table("cryptographic_facts")
