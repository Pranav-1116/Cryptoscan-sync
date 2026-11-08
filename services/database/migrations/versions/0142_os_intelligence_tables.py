"""OS & Kernel Intelligence tables
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §10).

Revision ID: 0142
Revises: 0141
Create Date: 2026-10-16

os_assets                — host OS/kernel identity, collection identity,
                           environment_development_only + qualification
                           note (§12: one host is never enterprise
                           qualification)
os_crypto_capabilities   — Kernel Crypto API registrations (§2.2):
                           algorithm vs driver distinct; unknown key
                           sizes stay NULL; runtime_usage_confirmed
                           false for Tier-1 collection
os_modules               — LKM inventory rows; a missing row is never
                           'feature unavailable' (may be built in)
os_config_flags          — recorded config states; 'not_set' is an
                           explicit state, absence is never 'disabled'
os_storage_facts         — disk-encryption METADATA only (§7): never
                           recovery keys, key files or secrets
os_trust_facts           — hardware trust metadata (TPM/RNG presence is
                           metadata, never a trust verdict)
os_findings              — normalized findings (§10): observation type,
                           evidence class, runtime_usage_confirmed,
                           limitations; severity fields COMPUTED and
                           nullable until the risk model evaluates them
os_coverage              — collection completeness (§2.1): unavailable
                           sources recorded with reasons, never zeros
"""

import sqlalchemy as sa
from alembic import op

revision = "0142"
down_revision = "0141"
branch_labels = None
depends_on = None

_COMMON = (
    sa.Column("tenant_id", sa.String(120), nullable=True),
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def _table(name, *columns):
    op.create_table(name, *columns, *_COMMON)


def upgrade() -> None:
    _table(
        "os_assets",
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("kernel_name", sa.String(40), nullable=False),
        sa.Column("kernel_release", sa.String(80), nullable=False),
        sa.Column("kernel_version", sa.String(300), nullable=True),
        sa.Column("machine", sa.String(40), nullable=True),
        sa.Column("os_pretty_name", sa.String(200), nullable=True),
        sa.Column("os_id", sa.String(80), nullable=True),
        sa.Column("os_version_id", sa.String(80), nullable=True),
        sa.Column("arch", sa.String(40), nullable=True),
        sa.Column("cmdline", sa.Text, nullable=True),
        sa.Column("tainted_flags", sa.String(24), nullable=True),
        sa.Column("tainted_meanings", sa.JSON, nullable=True),
        sa.Column("environment_development_only", sa.Boolean,
                  nullable=False),
        sa.Column("qualification_note", sa.Text, nullable=True),
        sa.Column("collector_version", sa.String(80), nullable=False),
        sa.Column("notes", sa.JSON, nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True),
                  nullable=False),
    )
    op.create_index("ix_os_assets_tenant_asset", "os_assets",
                    ["tenant_id", "asset_id"], unique=True)

    _table(
        "os_crypto_capabilities",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("algorithm", sa.String(120), nullable=False),
        sa.Column("driver", sa.String(120), nullable=True),
        sa.Column("implementation_type", sa.String(40), nullable=True),
        sa.Column("module", sa.String(80), nullable=True),
        sa.Column("priority", sa.Integer, nullable=True),
        sa.Column("blocksize", sa.Integer, nullable=True),
        sa.Column("digestsize", sa.Integer, nullable=True),
        sa.Column("min_keysize", sa.Integer, nullable=True),
        sa.Column("max_keysize", sa.Integer, nullable=True),
        sa.Column("selftest", sa.String(24), nullable=True),
        sa.Column("hardware_accelerated", sa.Boolean, nullable=True),
        sa.Column("runtime_usage_confirmed", sa.Boolean, nullable=False),
        sa.Column("parse_notes", sa.JSON, nullable=True),
    )
    op.create_index("ix_os_crypto_cap_tenant_collection",
                    "os_crypto_capabilities",
                    ["tenant_id", "collection_id"])
    op.create_index("ix_os_crypto_cap_tenant_algorithm",
                    "os_crypto_capabilities",
                    ["tenant_id", "algorithm"])

    _table(
        "os_modules",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("size", sa.Integer, nullable=True),
        sa.Column("refcount", sa.Integer, nullable=True),
        sa.Column("used_by", sa.JSON, nullable=True),
        sa.Column("state", sa.String(40), nullable=True),
    )
    op.create_index("ix_os_modules_tenant_collection", "os_modules",
                    ["tenant_id", "collection_id"])

    _table(
        "os_config_flags",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("flag", sa.String(120), nullable=False),
        sa.Column("value", sa.String(200), nullable=False),
        sa.Column("explicitly_disabled", sa.Boolean, nullable=False),
    )
    op.create_index("ix_os_config_flags_tenant_collection",
                    "os_config_flags", ["tenant_id", "collection_id"])

    _table(
        "os_storage_facts",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("device", sa.String(120), nullable=False),
        sa.Column("fstype", sa.String(60), nullable=True),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("notes", sa.JSON, nullable=True),
    )
    op.create_index("ix_os_storage_facts_tenant_collection",
                    "os_storage_facts", ["tenant_id", "collection_id"])

    _table(
        "os_trust_facts",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("subject", sa.String(80), nullable=False),
        sa.Column("state", sa.String(40), nullable=False),
        sa.Column("evidence_class", sa.String(30), nullable=False),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("notes", sa.JSON, nullable=True),
    )
    op.create_index("ix_os_trust_facts_tenant_collection", "os_trust_facts",
                    ["tenant_id", "collection_id"])

    _table(
        "os_findings",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("finding_type", sa.String(120), nullable=False),
        sa.Column("subject", sa.String(200), nullable=True),
        sa.Column("algorithm", sa.String(120), nullable=True),
        sa.Column("implementation", sa.String(120), nullable=True),
        sa.Column("evidence_source", sa.String(200), nullable=True),
        sa.Column("observation_type", sa.String(60), nullable=False),
        sa.Column("runtime_usage_confirmed", sa.Boolean, nullable=False),
        sa.Column("evidence_class", sa.String(30), nullable=False),
        sa.Column("severity_label", sa.String(24), nullable=True),
        sa.Column("severity_factors", sa.JSON, nullable=True),
        sa.Column("risk_model_version", sa.String(40), nullable=True),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column("limitations", sa.JSON, nullable=True),
    )
    op.create_index("ix_os_findings_tenant_collection", "os_findings",
                    ["tenant_id", "collection_id"])
    op.create_index("ix_os_findings_tenant_asset", "os_findings",
                    ["tenant_id", "asset_id"])

    _table(
        "os_coverage",
        sa.Column("collection_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("sources_attempted", sa.JSON, nullable=True),
        sa.Column("sources_collected", sa.JSON, nullable=True),
        sa.Column("sources_unavailable", sa.JSON, nullable=True),
        sa.Column("source_digests", sa.JSON, nullable=True),
        sa.Column("note", sa.Text, nullable=True),
    )
    op.create_index("ix_os_coverage_tenant_collection", "os_coverage",
                    ["tenant_id", "collection_id"], unique=True)
    op.create_index("ix_os_coverage_tenant_asset", "os_coverage",
                    ["tenant_id", "asset_id"])


def downgrade() -> None:
    for name in ("os_coverage", "os_findings", "os_trust_facts",
                 "os_storage_facts", "os_config_flags", "os_modules",
                 "os_crypto_capabilities", "os_assets"):
        op.drop_table(name)
