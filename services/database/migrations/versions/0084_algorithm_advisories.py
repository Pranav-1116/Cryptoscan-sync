"""Crypto threat-intel advisories (deep/30, round 31).

Algorithm advisories (deprecation/restriction/attack-update/key-size/
implementation/disclosure) with authority provenance and effective
dates; unique per (source, advisory_id) so re-importing a feed bundle
is idempotent.
"""

from alembic import op
import sqlalchemy as sa

revision = "0084"
down_revision = "0083"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "algorithm_advisories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("advisory_id", sa.String(120), nullable=False),
        sa.Column("source", sa.String(80), nullable=False),
        sa.Column("advisory_type", sa.String(30), nullable=False),
        sa.Column("algorithm", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False,
                  server_default="MEDIUM"),
        sa.Column("title", sa.String(400), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("url", sa.String(600), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("effective_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("source", "advisory_id", name="uq_advisory_source_id"),
    )
    op.create_index("ix_advisories_algorithm", "algorithm_advisories", ["algorithm"])
    op.create_index("ix_advisories_effective", "algorithm_advisories", ["effective_date"])


def downgrade() -> None:
    op.drop_index("ix_advisories_effective", table_name="algorithm_advisories")
    op.drop_index("ix_advisories_algorithm", table_name="algorithm_advisories")
    op.drop_table("algorithm_advisories")
