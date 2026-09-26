"""Create crypto_asset_evidence link table.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def _pk(table: str) -> tuple[str, sa.types.TypeEngine]:
    """Name and type of ``table``'s primary key *at this point in the chain*.

    ``evidence_records`` was created (0002) with ``evidence_id UUID`` and is only
    renamed to ``id`` by 0029. A foreign key must reference the column that
    exists now, with a matching type — PostgreSQL rejects both a missing column
    and a ``VARCHAR -> UUID`` reference; SQLite enforced neither, which is how
    this migration passed for a year without ever applying on Postgres.
    """
    inspector = sa.inspect(op.get_bind())
    pk_cols = inspector.get_pk_constraint(table).get("constrained_columns") or ["id"]
    name = pk_cols[0]
    col = next(c for c in inspector.get_columns(table) if c["name"] == name)
    return name, col["type"]


def upgrade() -> None:
    asset_pk, asset_type = _pk("crypto_assets")
    evidence_pk, evidence_type = _pk("evidence_records")
    op.create_table(
        "crypto_asset_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("asset_id", asset_type,
                  sa.ForeignKey(f"crypto_assets.{asset_pk}", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", evidence_type,
                  sa.ForeignKey(f"evidence_records.{evidence_pk}", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("asset_id", "evidence_id", name="uq_asset_evidence"),
    )
    op.create_index("ix_crypto_asset_evidence_asset_id", "crypto_asset_evidence", ["asset_id"])
    op.create_index("ix_crypto_asset_evidence_evidence_id", "crypto_asset_evidence", ["evidence_id"])


def downgrade() -> None:
    op.drop_index("ix_crypto_asset_evidence_evidence_id", table_name="crypto_asset_evidence")
    op.drop_index("ix_crypto_asset_evidence_asset_id", table_name="crypto_asset_evidence")
    op.drop_table("crypto_asset_evidence")
