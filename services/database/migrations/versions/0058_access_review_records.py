"""``access_reviews`` — records of completed quarterly access reviews.

Revision ID: 0058
Revises: 0057
Create Date: 2026-09-21

The CC6.3 ``access-review`` export produces a signed snapshot of the
access estate (``report_hash``). This table is the system of record for
the review itself: who attested, for which period, against which estate
hash, and with which findings.

Rows are create-only through the API (one record per period — a quarter
is reviewed, not re-issued), and findings are stored as the reviewer
recorded them. Mirrors ``db/models/access_review.py`` exactly (see
schema-parity test).
"""
import sqlalchemy as sa
from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "access_reviews",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("period", sa.String(16), nullable=False),
        sa.Column("report_hash", sa.String(64), nullable=False),
        sa.Column("estate_unchanged", sa.Boolean(), nullable=False),
        sa.Column("reviewer", sa.String(100), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_access_reviews_period", "access_reviews", ["period"], unique=True)
    op.create_index("ix_access_reviews_report_hash", "access_reviews", ["report_hash"])


def downgrade() -> None:
    op.drop_index("ix_access_reviews_report_hash", table_name="access_reviews")
    op.drop_index("ix_access_reviews_period", table_name="access_reviews")
    op.drop_table("access_reviews")
