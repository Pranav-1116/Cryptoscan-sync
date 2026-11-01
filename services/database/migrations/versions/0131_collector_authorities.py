"""One approved authority per collector plane.

Revision 0131. Creates ``collector_authorities``.

Guide 116 graded ten of eleven collector planes GAP: the six questions a bank
asks about a collector — who, what target, which approved revision, when, how
long, which permission — were answered by six different mechanisms in eleven
different code paths, and nothing bound the answers to the collector. A plane
inherits whatever controls it happens to import, which is why two planes were
provable and nine were not.

This table is the binding. One row per plane per estate carries the approval
(who approved it, when it expires, at which revision), the target kind the plane
accepts, and a rolling window budget with the counters the compare-and-set
protects. A plane with no row is refused rather than defaulted.

The companion code is ``api.security.collector_authority``: the plane *shape*
lives there (entry point, permission, target pattern, defaults) so it is reviewed
with the routes, while the approval lives here because it is a decision with an
owner and an expiry.

Revision ID: 0131
Revises: 0130
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0131"
down_revision = "0130"
branch_labels = None
depends_on = None

TABLE = "collector_authorities"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("plane", sa.String(40), nullable=False),
        sa.Column("entry", sa.String(200), nullable=False),
        sa.Column("permission", sa.String(80), nullable=False),
        sa.Column("target_kind", sa.String(40), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("approved_by", sa.String(120), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(120), nullable=True),
        sa.Column("window_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("max_targets", sa.Integer(), nullable=False, server_default="64"),
        sa.Column("max_requests", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("max_runtime_seconds", sa.Integer(), nullable=False, server_default="900"),
        sa.Column("requests_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("runtime_seconds_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("tenant_id", "plane", name="uq_collector_authority_plane"),
    )
    op.create_index("ix_collector_authorities_plane", TABLE, ["plane"])


def downgrade() -> None:
    op.drop_index("ix_collector_authorities_plane", table_name=TABLE)
    op.drop_table(TABLE)
