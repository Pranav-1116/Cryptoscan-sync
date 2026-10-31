"""Make the migrated columns as strict as the models already claim.

Revision 0123. Sets NOT NULL on every column whose ORM model declares
``nullable=False`` and whose migration left the database accepting NULL.

The models are the contract the application is written against, and
``Base.metadata.create_all`` builds tables from them — which is exactly why this
diverged unnoticed: every unit and integration test creates its schema that way,
gets the strict schema, and passes. A bank runs ``alembic upgrade head``, gets the
loose one, and can store a NULL in a column every reader treats as present
(``users.username``, ``api_keys.key_hash``, ``evidence_records.finding_data``,
``scans.scan_start`` …), or leave a mandatory reference out of an audit row.
Nothing fails at write time; something fails much later, in a reader, on customer
data.

This closes the gap in one direction only. The reverse direction — a model that
allows NULL over a column the database refuses — is fixed in 0122 where the
platform estate genuinely has no tenant, and by ``TenantOwned`` where a row
cannot exist without an owner.

If an install already holds NULLs in one of these columns, this migration fails
on that column with PostgreSQL's own constraint error and changes nothing else;
backfill the column (or fix the writer that left it empty) and re-run. Refusing to
silently drop rows is deliberate: the value is the operator's data.

Revision ID: 0123
Revises: 0122
"""
from __future__ import annotations

from alembic import op

revision = "0123"
down_revision = "0122"
branch_labels = None
depends_on = None

#: (table, column) pairs, generated from the model metadata at ``head``. Table
#: order groups one table's columns together, so a failure names them together.
_STRICTEN = (
    ("algorithm_advisories", "created_at"),
    ("algorithm_advisories", "updated_at"),
    ("anomaly_flags", "created_at"),
    ("anomaly_flags", "updated_at"),
    ("api_key_quota_windows", "created_at"),
    ("api_key_quota_windows", "updated_at"),
    ("api_keys", "created_at"),
    ("api_keys", "updated_at"),
    ("app_settings", "created_at"),
    ("app_settings", "updated_at"),
    ("automation_rules", "created_at"),
    ("automation_rules", "updated_at"),
    ("automation_runs", "created_at"),
    ("automation_runs", "updated_at"),
    ("binary_scan_observations", "created_at"),
    ("binary_scan_observations", "updated_at"),
    ("binary_scan_records", "created_at"),
    ("binary_scan_records", "updated_at"),
    ("cbom_versions", "created_at"),
    ("cbom_versions", "updated_at"),
    ("compliance_evidence_packs", "created_at"),
    ("compliance_evidence_packs", "updated_at"),
    ("connectors", "created_at"),
    ("connectors", "updated_at"),
    ("cp_agents", "created_at"),
    ("cp_agents", "updated_at"),
    ("cp_asset_identities", "created_at"),
    ("cp_asset_identities", "updated_at"),
    ("cp_benchmark_cases", "created_at"),
    ("cp_benchmark_cases", "updated_at"),
    ("cp_benchmark_datasets", "created_at"),
    ("cp_benchmark_datasets", "updated_at"),
    ("cp_benchmark_runs", "created_at"),
    ("cp_benchmark_runs", "updated_at"),
    ("cp_credentials", "created_at"),
    ("cp_credentials", "updated_at"),
    ("cp_delivery_logs", "created_at"),
    ("cp_delivery_logs", "updated_at"),
    ("cp_queued_events", "created_at"),
    ("cp_queued_events", "updated_at"),
    ("cp_safe_scan_policies", "created_at"),
    ("cp_safe_scan_policies", "updated_at"),
    ("cp_scope_grants", "created_at"),
    ("cp_scope_grants", "updated_at"),
    ("cp_tenants", "created_at"),
    ("cp_tenants", "updated_at"),
    ("credential_leases", "created_at"),
    ("credential_leases", "updated_at"),
    ("crypto_live_events", "created_at"),
    ("crypto_live_events", "updated_at"),
    ("crypto_live_states", "created_at"),
    ("crypto_live_states", "updated_at"),
    ("cryptographic_facts", "created_at"),
    ("cryptographic_facts", "updated_at"),
    ("custom_roles", "created_at"),
    ("custom_roles", "updated_at"),
    ("discovery_runs", "created_at"),
    ("discovery_runs", "updated_at"),
    ("ent_compliance_controls", "created_at"),
    ("ent_compliance_controls", "updated_at"),
    ("ent_compliance_status", "created_at"),
    ("ent_compliance_status", "updated_at"),
    ("ent_crypto_kb", "created_at"),
    ("ent_crypto_kb", "updated_at"),
    ("ent_integrations", "created_at"),
    ("ent_integrations", "updated_at"),
    ("ent_policies", "created_at"),
    ("ent_policies", "updated_at"),
    ("ent_policy_evaluations", "created_at"),
    ("ent_policy_evaluations", "updated_at"),
    ("ent_regions", "created_at"),
    ("ent_regions", "updated_at"),
    ("ent_tickets", "created_at"),
    ("ent_tickets", "updated_at"),
    ("environments", "created_at"),
    ("environments", "updated_at"),
    ("estate_remediation_work", "created_at"),
    ("estate_remediation_work", "updated_at"),
    ("governance_approvals", "created_at"),
    ("governance_approvals", "updated_at"),
    ("hardware_agents", "created_at"),
    ("hardware_agents", "updated_at"),
    ("hardware_assets", "created_at"),
    ("hardware_assets", "updated_at"),
    ("hardware_events", "created_at"),
    ("hardware_events", "updated_at"),
    ("hbom_snapshots", "created_at"),
    ("hbom_snapshots", "updated_at"),
    ("hsm_events", "created_at"),
    ("hsm_events", "updated_at"),
    ("key_ceremonies", "created_at"),
    ("key_ceremonies", "updated_at"),
    ("lake_export_batches", "created_at"),
    ("lake_export_batches", "updated_at"),
    ("migration_validations", "created_at"),
    ("migration_validations", "updated_at"),
    ("monitor_leases", "created_at"),
    ("monitor_leases", "updated_at"),
    ("organizations", "created_at"),
    ("organizations", "updated_at"),
    ("ot_maintenance_windows", "created_at"),
    ("ot_maintenance_windows", "updated_at"),
    ("payment_keys", "created_at"),
    ("payment_keys", "updated_at"),
    ("payment_policy_findings", "created_at"),
    ("payment_policy_findings", "updated_at"),
    ("payment_transaction_volume", "created_at"),
    ("payment_transaction_volume", "updated_at"),
    ("plugin_packages", "created_at"),
    ("plugin_packages", "updated_at"),
    ("policy_rule_overrides", "created_at"),
    ("policy_rule_overrides", "updated_at"),
    ("relationship_collections", "created_at"),
    ("relationship_collections", "updated_at"),
    ("relationship_lifecycle_events", "created_at"),
    ("relationship_lifecycle_events", "updated_at"),
    ("relationship_sources", "created_at"),
    ("relationship_sources", "updated_at"),
    ("remediation_tasks", "created_at"),
    ("remediation_tasks", "updated_at"),
    ("remediation_verifications", "created_at"),
    ("remediation_verifications", "updated_at"),
    ("retired_assets", "created_at"),
    ("retired_assets", "updated_at"),
    ("scans", "operator"),
    ("scope_entries", "created_at"),
    ("scope_entries", "updated_at"),
    ("software_artifacts", "created_at"),
    ("software_artifacts", "updated_at"),
    ("topology_edges", "created_at"),
    ("topology_edges", "updated_at"),
    ("topology_nodes", "created_at"),
    ("topology_nodes", "updated_at"),
    ("cbom_snapshots", "created_at"),
    ("cbom_snapshots", "updated_at"),
    ("compliance_attestations", "created_at"),
    ("compliance_attestations", "updated_at"),
    ("evidence_dispositions", "created_at"),
    ("evidence_dispositions", "updated_at"),
    ("evidence_records", "algorithm"),
    ("evidence_records", "confidence"),
    ("evidence_records", "file_path"),
    ("evidence_records", "line_number"),
    ("evidence_records", "updated_at"),
    ("release_sbom_bindings", "created_at"),
    ("release_sbom_bindings", "updated_at"),
    ("software_deployments", "created_at"),
    ("software_deployments", "updated_at"),
)


def upgrade() -> None:
    for table, column in _STRICTEN:
        op.alter_column(table, column, existing_type=None, nullable=False)


def downgrade() -> None:
    for table, column in _STRICTEN:
        op.alter_column(table, column, existing_type=None, nullable=True)
