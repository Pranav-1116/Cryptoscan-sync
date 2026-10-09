"""Resource-level access grants (report 13 §2.2 — per-system permissions).

Adds ``resource_grants``: (tenant, subject, resource_type, resource_id) →
resource role (owner/operator/viewer). Restrictive-only-when-present: a
resource with no grants is unrestricted (previous behavior); once any grant
exists, subjects need a sufficient grant. Platform superadmin always passes;
auditor passes read-only checks.

Revision ID: 0076
Revises: 0075
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0076"
down_revision = "0075"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "resource_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("subject", sa.String(100), nullable=False, index=True),
        sa.Column("resource_type", sa.String(20), nullable=False, index=True),
        sa.Column("resource_id", sa.String(64), nullable=False, index=True),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("granted_by", sa.String(100), nullable=True),
        sa.Column("revoke_reason", sa.String(500), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", "subject", "resource_type", "resource_id", name="uq_resource_grant"
        ),
    )


def downgrade() -> None:
    op.drop_table("resource_grants")
