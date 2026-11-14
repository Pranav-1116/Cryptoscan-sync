"""Materialized views: fast portfolio and compliance dashboards.

Revision ID: 0155
Revises: 0154

Dashboards aggregate the same estate over and over: asset counts by
lifecycle, evidence counts by compliance status. As CryptoScan collects
evidence continuously those aggregates grow more expensive while the
answer changes at refresh-time granularity, not request-time — the exact
shape materialized views exist for.

Two views, one per dashboard surface:

    mv_portfolio_summary   per-tenant estate shape (assets by lifecycle)
    mv_compliance_summary  per-tenant evidence verdicts (PASS/WARN/FAIL/PENDING)

Each carries a UNIQUE index on ``tenant_id`` so ``REFRESH MATERIALIZED
VIEW CONCURRENTLY`` works: a refresh never blocks the dashboards reading
the previous contents (continuous operation is the point).

Honest boundary: a materialized view is a SNAPSHOT. ``db/materialized.py``
refreshes it and reports per-view timing and errors; the views themselves
never claim to be current to the row — they are current to the last
refresh, and ``as_dict``-style reporting lives in the refresher.

PostgreSQL only (0130's rule): SQLite has no materialized views and the
chain stays flat there — the dashboards' SQL is portable, the storage is
not.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0155"
down_revision = "0154"
branch_labels = None
depends_on = None

PORTFOLIO = "mv_portfolio_summary"
COMPLIANCE = "mv_compliance_summary"


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(f"""
        CREATE MATERIALIZED VIEW {PORTFOLIO} AS
        SELECT tenant_id,
               count(*) AS assets_total,
               count(*) FILTER (WHERE lifecycle_state = 'ACTIVE') AS assets_active,
               count(*) FILTER (WHERE lifecycle_state = 'STALE') AS assets_stale,
               now() AS refreshed_at
        FROM estate_assets
        GROUP BY tenant_id
    """)
    op.create_index(f"uq_{PORTFOLIO}_tenant", PORTFOLIO, ["tenant_id"], unique=True)
    op.execute(f"""
        CREATE MATERIALIZED VIEW {COMPLIANCE} AS
        SELECT tenant_id,
               count(*) AS evidence_total,
               count(*) FILTER (WHERE compliance_status = 'PASS') AS evidence_pass,
               count(*) FILTER (WHERE compliance_status = 'WARN') AS evidence_warn,
               count(*) FILTER (WHERE compliance_status = 'FAIL') AS evidence_fail,
               count(*) FILTER (WHERE compliance_status = 'PENDING') AS evidence_pending,
               now() AS refreshed_at
        FROM evidence_records
        GROUP BY tenant_id
    """)
    op.create_index(f"uq_{COMPLIANCE}_tenant", COMPLIANCE, ["tenant_id"], unique=True)


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # Views hold no rows of their own: dropping them deletes nothing.
    op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {COMPLIANCE}")
    op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {PORTFOLIO}")
