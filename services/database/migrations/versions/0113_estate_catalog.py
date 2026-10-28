"""Durable canonical estate catalogue (spec 94 §19, §22).

Revision 0113. Creates ``estate_assets``, ``estate_relationships`` and
``estate_crypto_assets``: the twin's records with a life longer than one run, so
questions like "when did we first see HSM-03", "which evidence establishes this
edge" and "what is stale rather than gone" are answerable.

Nothing is deleted automatically: an asset absent from the latest observation becomes
``STALE`` with its ``last_seen_at`` intact, because absence is not decommissioning.
"""
from alembic import op
import sqlalchemy as sa

revision = "0113"
down_revision = "0112"
branch_labels = depends_on = None


def _audit_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36)),
    ]


def _lifecycle_columns():
    return [
        sa.Column("lifecycle_state", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
    ]


def upgrade():
    op.create_table(
        "estate_assets",
        *_audit_columns(),
        sa.Column("asset_id", sa.String(120), nullable=False),
        sa.Column("asset_type", sa.String(40), nullable=False),
        sa.Column("name", sa.String(400), nullable=False),
        sa.Column("environment", sa.String(120)),
        sa.Column("owner", sa.String(200)),
        sa.Column("location", sa.String(200)),
        sa.Column("source", sa.String(200)),
        sa.Column("identity", sa.JSON()),
        sa.Column("attributes", sa.JSON()),
        sa.Column("evidence_ids", sa.JSON()),
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
        *_lifecycle_columns(),
        sa.Column("first_run_id", sa.String(64)),
        sa.Column("last_run_id", sa.String(64)),
    )
    op.create_index("ix_estate_assets_tenant_id", "estate_assets", ["tenant_id"])
    op.create_index("ix_estate_assets_asset_id", "estate_assets", ["asset_id"])
    op.create_index("ix_estate_assets_asset_type", "estate_assets", ["asset_type"])
    op.create_index("ix_estate_assets_environment", "estate_assets", ["environment"])
    op.create_index("ix_estate_assets_owner", "estate_assets", ["owner"])
    op.create_index("ix_estate_assets_lifecycle_state", "estate_assets", ["lifecycle_state"])
    op.create_index("ix_estate_assets_last_seen_at", "estate_assets", ["last_seen_at"])
    op.create_index("ix_estate_assets_tenant_asset", "estate_assets", ["tenant_id", "asset_id"], unique=True)
    op.create_index("ix_estate_assets_type_env", "estate_assets", ["asset_type", "environment"])

    op.create_table(
        "estate_relationships",
        *_audit_columns(),
        sa.Column("relationship_id", sa.String(120), nullable=False),
        sa.Column("subject_id", sa.String(120), nullable=False),
        sa.Column("subject_name", sa.String(400)),
        sa.Column("predicate", sa.String(60), nullable=False),
        sa.Column("object_id", sa.String(120), nullable=False),
        sa.Column("object_name", sa.String(400)),
        sa.Column("basis", sa.String(80)),
        sa.Column("confidence", sa.String(20)),
        sa.Column("status", sa.String(20), nullable=False, server_default="ESTABLISHED"),
        sa.Column("reason", sa.Text()),
        sa.Column("evidence_ids", sa.JSON()),
        sa.Column("attributes", sa.JSON()),
        *_lifecycle_columns(),
    )
    op.create_index("ix_estate_relationships_tenant_id", "estate_relationships", ["tenant_id"])
    op.create_index("ix_estate_relationships_relationship_id", "estate_relationships", ["relationship_id"])
    op.create_index("ix_estate_relationships_subject_id", "estate_relationships", ["subject_id"])
    op.create_index("ix_estate_relationships_object_id", "estate_relationships", ["object_id"])
    op.create_index("ix_estate_relationships_predicate", "estate_relationships", ["predicate"])
    op.create_index("ix_estate_relationships_status", "estate_relationships", ["status"])
    op.create_index("ix_estate_relationships_lifecycle_state", "estate_relationships", ["lifecycle_state"])
    op.create_index(
        "ix_estate_relationships_tenant_rel",
        "estate_relationships",
        ["tenant_id", "relationship_id"],
        unique=True,
    )

    op.create_table(
        "estate_crypto_assets",
        *_audit_columns(),
        sa.Column("artifact_id", sa.String(120), nullable=False),
        sa.Column("asset_id", sa.String(120), nullable=False),
        sa.Column("asset_name", sa.String(400)),
        sa.Column("asset_type", sa.String(40)),
        sa.Column("algorithm", sa.String(120)),
        sa.Column("protocol", sa.String(60)),
        sa.Column("curve", sa.String(80)),
        sa.Column("key_size", sa.Integer()),
        sa.Column("mode", sa.String(60)),
        sa.Column("role", sa.String(60)),
        sa.Column("layer", sa.String(40)),
        sa.Column("usage_state", sa.String(20), nullable=False),
        sa.Column("evidence_type", sa.String(40)),
        sa.Column("confidence", sa.String(20)),
        sa.Column("evidence_ids", sa.JSON()),
        sa.Column("source", sa.String(200)),
        *_lifecycle_columns(),
    )
    op.create_index("ix_estate_crypto_assets_tenant_id", "estate_crypto_assets", ["tenant_id"])
    op.create_index("ix_estate_crypto_assets_artifact_id", "estate_crypto_assets", ["artifact_id"])
    op.create_index("ix_estate_crypto_assets_asset_id", "estate_crypto_assets", ["asset_id"])
    op.create_index("ix_estate_crypto_assets_asset_type", "estate_crypto_assets", ["asset_type"])
    op.create_index("ix_estate_crypto_assets_algorithm", "estate_crypto_assets", ["algorithm"])
    op.create_index("ix_estate_crypto_assets_protocol", "estate_crypto_assets", ["protocol"])
    op.create_index("ix_estate_crypto_assets_layer", "estate_crypto_assets", ["layer"])
    op.create_index("ix_estate_crypto_assets_usage_state", "estate_crypto_assets", ["usage_state"])
    op.create_index("ix_estate_crypto_assets_lifecycle_state", "estate_crypto_assets", ["lifecycle_state"])
    op.create_index(
        "ix_estate_crypto_tenant_artifact",
        "estate_crypto_assets",
        ["tenant_id", "artifact_id"],
        unique=True,
    )


def downgrade():
    for table, indexes in (
        ("estate_crypto_assets", [
            "ix_estate_crypto_tenant_artifact", "ix_estate_crypto_assets_lifecycle_state",
            "ix_estate_crypto_assets_usage_state", "ix_estate_crypto_assets_layer",
            "ix_estate_crypto_assets_protocol", "ix_estate_crypto_assets_algorithm",
            "ix_estate_crypto_assets_asset_type", "ix_estate_crypto_assets_asset_id",
            "ix_estate_crypto_assets_artifact_id", "ix_estate_crypto_assets_tenant_id",
        ]),
        ("estate_relationships", [
            "ix_estate_relationships_tenant_rel", "ix_estate_relationships_lifecycle_state",
            "ix_estate_relationships_status", "ix_estate_relationships_predicate",
            "ix_estate_relationships_object_id", "ix_estate_relationships_subject_id",
            "ix_estate_relationships_relationship_id", "ix_estate_relationships_tenant_id",
        ]),
        ("estate_assets", [
            "ix_estate_assets_type_env", "ix_estate_assets_tenant_asset",
            "ix_estate_assets_last_seen_at", "ix_estate_assets_lifecycle_state",
            "ix_estate_assets_owner", "ix_estate_assets_environment",
            "ix_estate_assets_asset_type", "ix_estate_assets_asset_id",
            "ix_estate_assets_tenant_id",
        ]),
    ):
        for index in indexes:
            op.drop_index(index, table_name=table)
        op.drop_table(table)
