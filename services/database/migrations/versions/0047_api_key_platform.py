"""P2 machine API-key platform: endpoint scopes, method allowlist, rate quota,
and lifetime usage counters.

Revision ID: 0047
Revises: 0046
Create Date: 2026-09-03

New columns are nullable / have safe defaults so existing keys keep working.
The application's schema reconciliation adds them too; this migration keeps the
alembic-head schema in exact parity with the ORM model for upgraded databases.
No AI/ML — pure access-control metadata.
"""
import sqlalchemy as sa
from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.add_column(sa.Column("scopes", sa.Text(), nullable=True))
        batch.add_column(sa.Column("allowed_methods", sa.String(length=100), nullable=True))
        batch.add_column(sa.Column("rate_per_minute", sa.Integer(), nullable=False,
                                   server_default="0"))
        batch.add_column(sa.Column("request_count", sa.Integer(), nullable=False,
                                   server_default="0"))
        batch.add_column(sa.Column("denied_count", sa.Integer(), nullable=False,
                                   server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("denied_count")
        batch.drop_column("request_count")
        batch.drop_column("rate_per_minute")
        batch.drop_column("allowed_methods")
        batch.drop_column("scopes")
