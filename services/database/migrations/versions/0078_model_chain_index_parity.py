"""Model/chain index parity (report 04 — the index-analysis claims, re-verified).

The models declare 24 indexes (`index=True` / `Index()`) that the migration
chain never created: every `create_all`-based deployment (tests, SQLite
installs) had them, but every alembic-migrated deployment (PostgreSQL
production) silently lacked them — including hot paths:

    vulnerabilities.scan_id            CVE lookups per scan (risk, vulns API)
    systems.business_unit|cloud_provider|coverage_status|cloud_account
                                      estate filters used by list_systems
    system_assets.asset_id             reverse joins (which systems use asset X)
    system_dependencies.child_id       reverse dependency walks
    scan_jobs.system_id                per-system job history
    graph_snapshots.version            snapshot timeline queries
    ... (full list below)

Prefix-covered ones were excluded (e.g. evidence_records.scan_id is the
leftmost prefix of ix_evidence_scan_chain; system_dependencies.parent_id is
covered by uq_system_dep) — this migration only creates what was genuinely
absent. A parity test (`test_model_migration_index_parity`) pins this so
drift cannot return.

Revision ID: 0078
Revises: 0077
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0078"
down_revision = "0077"
branch_labels = None
depends_on = None

#: (table, index name, columns) — exactly the set the parity check found.
_INDEXES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("cbom_versions", "ix_cbom_versions_version", ("version",)),
    ("cp_asset_identities", "ix_cp_asset_identities_canonical_id", ("canonical_id",)),
    ("crypto_hardware_links", "ix_crypto_hardware_links_hardware_asset_id", ("hardware_asset_id",)),
    ("exception_reviews", "ix_exception_reviews_exception_id", ("exception_id",)),
    ("graph_snapshots", "ix_graph_snapshots_version", ("version",)),
    ("migration_projects", "ix_migration_projects_system_id", ("system_id",)),
    ("ot_crypto_findings", "ix_ot_crypto_findings_device_id", ("device_id",)),
    ("policy_exceptions", "ix_policy_exceptions_asset_id", ("asset_id",)),
    ("policy_exceptions", "ix_policy_exceptions_system_id", ("system_id",)),
    ("scan_jobs", "ix_scan_jobs_system_id", ("system_id",)),
    ("system_assets", "ix_system_assets_asset_id", ("asset_id",)),
    ("system_business_process_map", "ix_system_business_process_map_process_id", ("process_id",)),
    ("system_business_process_map", "ix_system_business_process_map_system_id", ("system_id",)),
    ("system_dependencies", "ix_system_dependencies_child_id", ("child_id",)),
    ("systems", "ix_systems_business_unit", ("business_unit",)),
    ("systems", "ix_systems_cloud_account", ("cloud_account",)),
    ("systems", "ix_systems_cloud_provider", ("cloud_provider",)),
    ("systems", "ix_systems_coverage_status", ("coverage_status",)),
    ("technology_bom_export_runs", "ix_technology_bom_export_runs_content_sha256", ("content_sha256",)),
    ("technology_bom_snapshots", "ix_technology_bom_snapshots_version", ("version",)),
    ("twin_snapshots", "ix_twin_snapshots_version", ("version",)),
    ("vendor_crypto_inventory", "ix_vendor_crypto_inventory_vendor_id", ("vendor_id",)),
    ("vendor_dependencies", "ix_vendor_dependencies_child_vendor_id", ("child_vendor_id",)),
    ("vulnerabilities", "ix_vulnerabilities_scan_id", ("scan_id",)),
)


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    present = _existing_tables()
    for table, name, columns in _INDEXES:
        if table not in present:
            continue  # optional-surface table not installed in this deployment
        op.create_index(name, table, list(columns))


def downgrade() -> None:
    present = _existing_tables()
    for table, name, _columns in reversed(_INDEXES):
        if table not in present:
            continue
        op.drop_index(name, table_name=table)
