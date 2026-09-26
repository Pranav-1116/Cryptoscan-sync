""":class:`api_keys` — add per-key IP allowlist and rotation policy.

Revision ID: 0052
Revises: 0051
Create Date: 2026-09-08

Brings the alembic-head schema back into exact parity with the ``ApiKey`` ORM
model. The model declares ``allowed_ips`` and ``rotate_after_days`` (used by the
api-key repository, router, and the identity guard), but no prior migration
created them — so a PostgreSQL database upgraded via ``alembic upgrade head``
would be missing those columns and fail at runtime. This migration adds them as
nullable columns (safe default / no data rewrite) so existing keys keep working.

No AI/ML — pure access-control metadata.
"""
import sqlalchemy as sa
from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        # Comma/space-separated IPv4/IPv6 or CIDR allowlist; empty = no restriction.
        batch.add_column(sa.Column("allowed_ips", sa.Text(), nullable=True))
        # Rotation reminder (days); deterministic, not hard-enforced.
        batch.add_column(sa.Column("rotate_after_days", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("rotate_after_days")
        batch.drop_column("allowed_ips")
