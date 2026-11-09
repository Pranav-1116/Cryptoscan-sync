"""Allow immutable OS snapshots and align OS tables with BaseModel.

Revision ID: 0146
Revises: 0145

0142 made (tenant_id, asset_id) unique even though a new collection must
retain an earlier snapshot. 0144-0145 used integer IDs and omitted
updated_at for three models inheriting BaseModel's UUID ID and timestamps.
"""

import sqlalchemy as sa
from alembic import op

revision = "0146"
down_revision = "0145"
branch_labels = None
depends_on = None

_BASEMODEL_TABLES = ("os_certificates", "os_runtime_sessions", "os_runtime_events")


def _change_id(table: str, type_: sa.types.TypeEngine, using: str) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # SERIAL's sequence default must not keep generating numeric IDs after
        # switching to application-generated UUID strings.
        op.execute(sa.text(f"ALTER TABLE {table} ALTER COLUMN id DROP DEFAULT"))
        op.alter_column(table, "id", existing_type=sa.Integer() if isinstance(type_, sa.String) else sa.String(36),
                        type_=type_, existing_nullable=False,
                        postgresql_using=using)
    else:
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.alter_column("id", existing_type=sa.Integer() if isinstance(type_, sa.String) else sa.String(36),
                               type_=type_, existing_nullable=False)


def upgrade() -> None:
    op.drop_index("ix_os_assets_tenant_asset", table_name="os_assets")
    op.create_index("ix_os_assets_tenant_asset", "os_assets",
                    ["tenant_id", "asset_id"], unique=False)
    op.create_index("ix_os_assets_tenant_collection", "os_assets",
                    ["tenant_id", "collection_id"], unique=True)

    for table in _BASEMODEL_TABLES:
        _change_id(table, sa.String(36), "id::varchar(36)")
        # TenantScoped permits NULL for the pre-tenancy/platform estate.
        # Keep the existing VARCHAR(64) width to avoid truncating legacy IDs.
        op.alter_column(table, "tenant_id", existing_type=sa.String(64),
                        existing_nullable=False, nullable=True)
        op.add_column(table, sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
        op.execute(sa.text(f"UPDATE {table} SET updated_at = created_at"))
        with op.batch_alter_table(table) as batch:
            batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)


def downgrade() -> None:
    # Existing UUID rows cannot be cast to integers: PostgreSQL refuses the
    # downgrade instead of discarding OS evidence. An empty deployment
    # can return to 0145 (e.g. the migration-chain test).
    for table in reversed(_BASEMODEL_TABLES):
        op.drop_column(table, "updated_at")
        op.alter_column(table, "tenant_id", existing_type=sa.String(64),
                        existing_nullable=True, nullable=False)
        _change_id(table, sa.Integer(), "id::integer")
        if op.get_bind().dialect.name == "postgresql":
            op.execute(sa.text(
                f"ALTER TABLE {table} ALTER COLUMN id SET DEFAULT "
                f"nextval('{table}_id_seq'::regclass)"))
    op.drop_index("ix_os_assets_tenant_collection", table_name="os_assets")
    op.drop_index("ix_os_assets_tenant_asset", table_name="os_assets")
    op.create_index("ix_os_assets_tenant_asset", "os_assets",
                    ["tenant_id", "asset_id"], unique=True)
