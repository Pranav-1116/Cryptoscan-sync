"""Finish tenant scoping: tenant_id on the remaining customer-owned tables.

0061 scoped the ten tables at the centre of the scan surface. This completes
the job for the other 65 tables that hold a customer's data — inventory
(systems, assets, vendors, hardware, OT devices), findings (vulnerabilities,
runtime, OT, payment policy), programme state (migration projects, tasks,
milestones), configuration a customer owns (repo configurations, network scan
targets, cloud accounts, connectors, environments, scope entries), and the
artefacts produced from them (CBOM versions, report snapshots, graph
snapshots, technology-BOM exports, gate evaluations, verification log).

After this, 87 of 102 tables are tenant-scoped. The 15 that are not are
platform infrastructure, deliberately:

  users, user_sessions, mfa_recovery_codes  identity. Authentication happens
                                            *before* any tenant is known; a
                                            user belongs to tenants through
                                            memberships, not by column.
  tenants                                   the tenant registry itself.
  audit_log                                 the security audit trail, which
                                            must record cross-tenant and
                                            platform-operator actions too.
  access_reviews                            SOC 2 CC6.3 attestations over the
                                            platform's own user estate.
  monitor_leases                            worker leader election.
  plugin_packages                           marketplace extensions installed
                                            platform-wide.
  cp_*                                      control-plane internals (several
                                            already carry their own tenant_id).

Every column is nullable and indexed: an online-safe add on PostgreSQL, no
rewrite and no backfill. NULL continues to mean "platform estate" and stays
visible to every tenant, so enabling tenancy on an existing single-tenant
install does not hide its history.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None

TENANT_SCOPED_TABLES: tuple[str, ...] = (
    "anomaly_flags", "app_settings", "automation_rules", "automation_runs",
    "business_owners", "business_processes", "cbom_versions", "certificate_usages",
    "cloud_accounts", "connectors", "credential_leases", "crypto_asset_evidence",
    "crypto_live_events", "crypto_live_states", "discovery_runs",
    "ent_compliance_controls", "ent_compliance_status", "ent_crypto_kb",
    "ent_integrations", "ent_policy_evaluations", "ent_regions", "ent_tickets",
    "environments", "exception_reviews", "gate_evaluations", "governance_approvals",
    "graph_snapshots", "hardware_agents", "hardware_assets", "hardware_events",
    "hsm_events", "key_ceremonies", "lake_export_batches", "migration_milestones",
    "migration_projects", "migration_tasks", "migration_validations", "monitor_events",
    "network_scan_targets", "organizations", "ot_crypto_findings", "ot_devices",
    "ot_maintenance_windows", "payment_keys", "payment_policy_findings",
    "payment_transaction_volume", "pentest_findings", "policy_exceptions",
    "repo_configurations", "report_schedules", "report_snapshots", "runtime_findings",
    "scope_entries", "system_agility_scores", "system_assets",
    "system_business_process_map", "system_dependencies", "system_vendors",
    "technology_bom_export_runs", "technology_bom_export_schedules",
    "technology_bom_snapshots", "vendor_crypto_inventory", "vendors",
    "verification_log", "vulnerabilities",
)


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    present = _existing_tables()
    for table in TENANT_SCOPED_TABLES:
        if table not in present or "tenant_id" in _columns(table):
            continue
        op.add_column(table, sa.Column("tenant_id", sa.String(length=36), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])


def downgrade() -> None:
    present = _existing_tables()
    for table in reversed(TENANT_SCOPED_TABLES):
        if table not in present or "tenant_id" not in _columns(table):
            continue
        try:
            op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        except Exception:  # index named differently on an older install
            pass
        op.drop_column(table, "tenant_id")
