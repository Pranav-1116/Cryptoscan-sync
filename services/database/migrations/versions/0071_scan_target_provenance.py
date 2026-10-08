"""Network scan-target provenance + tenant-local snapshot versions.

Two fixes from docs/PRODUCTION-GAP-HANDOFF-2026-10-08.md:

1. ``network_scan_targets.source`` records who put a target into the due-scan
   rotation (onboarding scope / subnet-discovery / manual). Scope revocation
   keys on it, so removing authorized scope disables the targets it
   materialized — and only those.
2. Snapshot version numbers become unique **per tenant** instead of globally:
   ``cbom_versions``, ``graph_snapshots``, ``technology_bom_snapshots`` and
   ``twin_snapshots`` each drop the single-column uniqueness on ``version``
   and gain ``(tenant_id, version)``. With globally-unique versions, the
   second tenant to capture version 1 collided at the database while the ORM
   guard had already scoped every read tenant-locally.

Constraint changes run in batch mode: SQLite (the dev/test database and the
migration-chain test) cannot ALTER constraints natively.

Revision ID: 0071
Revises: 0070
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. provenance for due-scan targets
    op.add_column(
        "network_scan_targets",
        sa.Column("source", sa.String(30), nullable=False, server_default="manual"),
    )

    # 2. per-tenant snapshot versions (index/constraint names as created by
    #    0051 / 0054 / 0055 / 0070 respectively)
    with op.batch_alter_table("cbom_versions") as batch:
        batch.drop_index("ix_cv_version")
        batch.create_unique_constraint("uq_cbom_versions_tenant_version",
                                       ["tenant_id", "version"])

    with op.batch_alter_table("graph_snapshots") as batch:
        batch.drop_index("ix_graph_snapshots_version")
        batch.create_unique_constraint("uq_graph_snapshots_tenant_version",
                                       ["tenant_id", "version"])

    with op.batch_alter_table("technology_bom_snapshots") as batch:
        batch.drop_index("ix_technology_bom_snapshots_version")
        batch.create_unique_constraint("uq_technology_bom_snapshots_tenant_version",
                                       ["tenant_id", "version"])

    with op.batch_alter_table("twin_snapshots") as batch:
        batch.drop_constraint("uq_twin_snapshot_version", type_="unique")
        batch.create_unique_constraint("uq_twin_snapshots_tenant_version",
                                       ["tenant_id", "version"])


def downgrade() -> None:
    with op.batch_alter_table("twin_snapshots") as batch:
        batch.drop_constraint("uq_twin_snapshots_tenant_version", type_="unique")
        batch.create_unique_constraint("uq_twin_snapshot_version", ["version"])

    with op.batch_alter_table("technology_bom_snapshots") as batch:
        batch.drop_constraint("uq_technology_bom_snapshots_tenant_version", type_="unique")
        batch.create_index("ix_technology_bom_snapshots_version", ["version"], unique=True)

    with op.batch_alter_table("graph_snapshots") as batch:
        batch.drop_constraint("uq_graph_snapshots_tenant_version", type_="unique")
        batch.create_index("ix_graph_snapshots_version", ["version"], unique=True)

    with op.batch_alter_table("cbom_versions") as batch:
        batch.drop_constraint("uq_cbom_versions_tenant_version", type_="unique")
        batch.create_index("ix_cv_version", ["version"], unique=True)

    op.drop_column("network_scan_targets", "source")
