"""i18n 9 languages — en, ar, fr, de, es, ja, zh, hi, pt.

Revision ID: 0065
Revises: 0064
"""

import sqlalchemy as sa
from alembic import op

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "i18n_translations",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("lang", sa.String(10), nullable=False),
        sa.Column("key", sa.String(200), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("source", sa.String(20), nullable=False, server_default="static"),
    )
    op.create_index("ix_i18n_lang", "i18n_translations", ["lang"])
    op.create_index("ix_i18n_key", "i18n_translations", ["key"])
    op.create_index("ix_i18n_lang_key", "i18n_translations", ["lang", "key"], unique=True)

    # Seed 9 languages marker — actual translations in frontend/src/i18n/*.json
    # This table allows backend to serve translations deterministically as well


def downgrade() -> None:
    op.drop_index("ix_i18n_lang_key", table_name="i18n_translations")
    op.drop_index("ix_i18n_key", table_name="i18n_translations")
    op.drop_index("ix_i18n_lang", table_name="i18n_translations")
    op.drop_table("i18n_translations")
