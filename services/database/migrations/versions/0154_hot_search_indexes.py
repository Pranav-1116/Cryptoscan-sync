"""Hot-search composite indexes: fast asset, algorithm and dependency searches.

Revision ID: 0154
Revises: 0153

The estate catalogue is CryptoScan's most-polled surface and its queries
always filter the tenant first (the RLS equality) and then a business
filter with an ORDER BY. The single-column indexes from the catalogue's
first migration cannot serve that shape: a per-tenant page sorted by
(asset_type, name) was a sort of the tenant's whole slice.

Composites added here, each one matching a real query in
``services/api/api/estate_catalog.py`` / ``estate_search.py`` (and pinned by
``scripts/tests/test_query_audit.py``'s EXPLAIN audit):

    estate_assets        (tenant_id, asset_type, name)          list_assets base
    estate_assets        (tenant_id, environment, asset_type, name)
                                             dashboard env filter (sort-free)
    estate_relationships (tenant_id, status, predicate, subject_name)
                                                              list_relationships
    estate_relationships (tenant_id, predicate, subject_name)  status=ALL path
    estate_crypto_assets (tenant_id, asset_id, usage_state, algorithm)
                                                              crypto_for(asset)

Transactional DDL with a bounded lock wait (0107's discipline): these are
live dashboard tables and an unbounded lock acquisition on them is an
outage. The downgrade drops only the composites — the single-column
indexes and all data remain.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0154"
down_revision = "0153"
branch_labels = None
depends_on = None

COMPOSITES = [
    ("ix_estate_assets_tenant_type_name", "estate_assets",
     ["tenant_id", "asset_type", "name"]),
    ("ix_estate_assets_tenant_env_type_name", "estate_assets",
     ["tenant_id", "environment", "asset_type", "name"]),
    ("ix_estate_rels_tenant_status_pred_subject", "estate_relationships",
     ["tenant_id", "status", "predicate", "subject_name"]),
    ("ix_estate_rels_tenant_pred_subject", "estate_relationships",
     ["tenant_id", "predicate", "subject_name"]),
    ("ix_estate_crypto_tenant_asset_usage", "estate_crypto_assets",
     ["tenant_id", "asset_id", "usage_state", "algorithm"]),
]


def _lock_timeout() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("SET LOCAL lock_timeout = '5s'")


def upgrade() -> None:
    _lock_timeout()
    for name, table, columns in COMPOSITES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    _lock_timeout()
    for name, table, _columns in reversed(COMPOSITES):
        op.drop_index(name, table_name=table)
