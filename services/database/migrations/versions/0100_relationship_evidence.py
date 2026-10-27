"""Optional relationship evidence pointers; no invented legacy verification."""

from alembic import op
import sqlalchemy as sa

revision = "0100"
down_revision = "0099"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("system_dependencies", sa.Column("evidence_ref", sa.String(500), nullable=True))
    op.add_column("system_dependencies", sa.Column("confidence_meaning", sa.String(200), nullable=True))


def downgrade():
    with op.batch_alter_table("system_dependencies") as batch:
        batch.drop_column("confidence_meaning")
        batch.drop_column("evidence_ref")
