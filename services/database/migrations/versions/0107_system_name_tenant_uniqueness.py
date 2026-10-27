"""Scope business names to an estate, retaining uniqueness in the platform estate.

Transactional PostgreSQL DDL; busy systems fail after 5s rather than waiting
indefinitely for an exclusive lock. Rollback preserves the pre-upgrade schema.
A downgrade refuses cross-estate duplicates: never delete/rename business data.
"""
from alembic import op
import sqlalchemy as sa

revision = "0107"
down_revision = "0106"
branch_labels = None
depends_on = None


def _lock_timeout():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("SET LOCAL lock_timeout = '5s'")


def upgrade():
    _lock_timeout()
    op.create_index("uq_systems_tenant_name", "systems", ["tenant_id", "name"], unique=True)
    op.create_index("uq_systems_platform_name", "systems", ["name"], unique=True,
                    postgresql_where=sa.text("tenant_id IS NULL"),
                    sqlite_where=sa.text("tenant_id IS NULL"))
    # 0012 installs a UNIQUE CONSTRAINT, whereas historical create_all
    # installs a unique ix_systems_name index. Handle both without mistaking
    # the normal nonunique lookup index for a uniqueness constraint.
    inspector = sa.inspect(op.get_bind())
    for constraint in inspector.get_unique_constraints("systems"):
        if constraint["column_names"] == ["name"]:
            with op.batch_alter_table("systems") as batch:
                batch.drop_constraint(constraint["name"], type_="unique")
    for index in sa.inspect(op.get_bind()).get_indexes("systems"):
        if index["column_names"] == ["name"] and index.get("unique") and index["name"] != "uq_systems_platform_name":
            op.drop_index(index["name"], table_name="systems")
            if index["name"] == "ix_systems_name":
                op.create_index("ix_systems_name", "systems", ["name"])


def downgrade():
    _lock_timeout()
    duplicate = op.get_bind().execute(sa.text(
        "SELECT 1 FROM systems GROUP BY name HAVING count(*) > 1 LIMIT 1"
    )).first()
    if duplicate:
        raise RuntimeError("0107 downgrade blocked: system names repeat across estates; resolve explicitly before downgrading")
    with op.batch_alter_table("systems") as batch:
        batch.create_unique_constraint("uq_systems_name", ["name"])
    op.drop_index("uq_systems_platform_name", table_name="systems")
    op.drop_index("uq_systems_tenant_name", table_name="systems")
