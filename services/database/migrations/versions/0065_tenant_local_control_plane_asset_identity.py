"""Make control-plane asset identity uniqueness tenant-local.

The original control-plane table used one global unique index on
``canonical_id``. Once asset identities became tenant-scoped, that index made
an insert in Tenant A fail when the same identifier existed in Tenant B,
turning another tenant's row into an existence oracle. The composite index
keeps identities unique inside a tenant while allowing independent tenants to
use the same external identifier.
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None

TABLE = "cp_asset_identities"
GLOBAL_INDEX = "ix_cp_asset_identities_canonical_id"
TENANT_INDEX = "ix_cp_asset_identities_tenant_canonical_id"

logger = logging.getLogger(__name__)


def _present() -> bool:
    return TABLE in set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if not _present():
        return
    inspector = sa.inspect(op.get_bind())
    indexes = {item["name"]: item for item in inspector.get_indexes(TABLE)}
    if GLOBAL_INDEX in indexes:
        op.drop_index(GLOBAL_INDEX, table_name=TABLE)
    # Older installations may have represented unique=True as a named
    # constraint rather than an index. Remove only a single-column canonical
    # uniqueness constraint, never an unrelated constraint.
    for constraint in inspector.get_unique_constraints(TABLE):
        if constraint.get("name") and constraint.get("column_names") == ["canonical_id"]:
            op.drop_constraint(constraint["name"], TABLE, type_="unique")
    if TENANT_INDEX not in indexes:
        op.create_index(
            TENANT_INDEX, TABLE, ["tenant_id", "canonical_id"], unique=True
        )


def downgrade() -> None:
    if not _present():
        return
    inspector = sa.inspect(op.get_bind())
    indexes = {item["name"]: item for item in inspector.get_indexes(TABLE)}
    if TENANT_INDEX in indexes:
        op.drop_index(TENANT_INDEX, table_name=TABLE)
    if GLOBAL_INDEX not in indexes:
        op.create_index(GLOBAL_INDEX, TABLE, ["canonical_id"], unique=True)
