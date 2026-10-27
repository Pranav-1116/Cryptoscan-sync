"""Separate SBOM document identity, immutable release digest and deployment assertion."""
from alembic import op
import sqlalchemy as sa

revision = "0098"
down_revision = "0097"
branch_labels = None
depends_on = None


def _base(table):
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
            sa.Column("scope_key", sa.String(80), nullable=False, index=True),
            sa.Column("created_by", sa.String(100), nullable=False),
            sa.Column("evidence_ref", sa.String(500), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END",
                               name=f"ck_{table}_scope_owner")]


def upgrade():
    op.create_table("software_artifacts", *_base("software_artifacts"),
                    sa.Column("digest", sa.String(71), nullable=False, index=True),
                    sa.Column("media_type", sa.String(120), nullable=False),
                    sa.Column("identity_source", sa.String(30), nullable=False),
                    sa.Column("byte_count", sa.Integer(), nullable=True),
                    sa.UniqueConstraint("scope_key", "digest", name="uq_software_artifact_scope_digest"),
                    sa.UniqueConstraint("scope_key", "id", name="uq_software_artifact_scope_id"))
    op.create_table("release_sbom_bindings", *_base("release_sbom_bindings"),
                    sa.Column("artifact_id", sa.String(36), nullable=False, index=True),
                    sa.Column("sbom_artifact_id", sa.String(64), nullable=False, index=True),
                    sa.Column("sbom_sha256", sa.String(64), nullable=False),
                    sa.Column("components", sa.JSON(), nullable=False),
                    sa.Column("component_count", sa.Integer(), nullable=False),
                    sa.Column("unresolved_component_count", sa.Integer(), nullable=False),
                    sa.Column("assertion_source", sa.String(30), nullable=False),
                    sa.ForeignKeyConstraint(["scope_key", "artifact_id"], ["software_artifacts.scope_key", "software_artifacts.id"]),
                    sa.UniqueConstraint("scope_key", "artifact_id", "sbom_artifact_id", name="uq_release_sbom_binding"))
    op.create_table("software_deployments", *_base("software_deployments"),
                    sa.Column("artifact_id", sa.String(36), nullable=False, index=True),
                    sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id"), nullable=False, index=True),
                    sa.Column("deployment_key", sa.String(300), nullable=False),
                    sa.Column("environment", sa.String(60), nullable=False),
                    sa.Column("assertion_source", sa.String(30), nullable=False),
                    sa.ForeignKeyConstraint(["scope_key", "artifact_id"], ["software_artifacts.scope_key", "software_artifacts.id"]),
                    sa.UniqueConstraint("scope_key", "deployment_key", name="uq_software_deployment_key"))


def downgrade():
    # Explicit destructive rollback: operators must export these assertions first.
    op.drop_table("software_deployments")
    op.drop_table("release_sbom_bindings")
    op.drop_table("software_artifacts")
