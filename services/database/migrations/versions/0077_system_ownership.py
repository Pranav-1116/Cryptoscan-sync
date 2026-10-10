"""System ownership roles (report 55 P0 — technical + security owner fields).

Adds ``technical_owner`` and ``security_owner`` to ``systems``: named
accountability for "who changes the crypto" (technical) and "who accepts the
risk" (security), distinct from the existing free-text ``owner``.
Ownership changes are audited by the API layer (``system.ownership_change``).

Revision ID: 0077
Revises: 0076
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0077"
down_revision = "0076"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("systems", sa.Column("technical_owner", sa.String(200), nullable=True))
    op.add_column("systems", sa.Column("security_owner", sa.String(200), nullable=True))


def downgrade() -> None:
    op.drop_column("systems", "security_owner")
    op.drop_column("systems", "technical_owner")
