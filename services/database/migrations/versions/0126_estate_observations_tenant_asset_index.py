"""Index ``estate_observations`` by tenant and asset.

Revision 0126. Creates ``ix_estate_observations_tenant_asset``.

A million facts in one tenant made the twin's per-asset reads linear in the size
of the estate: ``history`` took 1.53 s and ``why`` 1.42 s, both driven by a
single-column tenant index that filtered after reading every row of the tenant.
The queries already filter ``(tenant_id, asset_id)`` together — the composite
index makes that the access path.

Measured on the same 100k-asset / 1M-fact database: history 485 ms -> 1.2 ms,
why 5.9 ms -> 1.7 ms, and the index costs 0.7 s to build on 1M rows.

Revision ID: 0126
Revises: 0125
"""
from __future__ import annotations

from alembic import op

revision = "0126"
down_revision = "0125"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_estate_observations_tenant_asset", "estate_observations", ["tenant_id", "asset_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_estate_observations_tenant_asset", table_name="estate_observations")
