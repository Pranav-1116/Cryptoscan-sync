"""Restore ``uq_fact_identity`` after 0123's batch table rebuild dropped it.

Revision 0127. Recreates the expression-based unique index on
``cryptographic_facts`` when it is missing.

0123 set NOT NULL on every column whose model declares it. SQLite has no
``ALTER COLUMN``, so alembic's batch mode recreates each table: create a new
table from the *reflected* definition, copy the rows, drop the old one, rename.
Reflection reproduces plain indexes and columns; it does not reproduce an index
whose parts are expressions. ``uq_fact_identity`` — created in 0087 as
``(algorithm, coalesce(tenant_id,''), (tenant_id IS NULL), coalesce(purpose,''),
coalesce(file_path,''), coalesce(key_size,0), (key_size IS NULL),
coalesce(mode,''))`` — is exactly that kind, and 0123 removed it.

The consequences are not cosmetic. On a migrated SQLite database two facts that
differ only in how NULL is spelled (``key_size`` NULL vs 0, absent ``purpose``
vs empty string) were accepted as separate rows, where ``create_all`` — the
schema every test builds — refuses the second. A PostgreSQL deployment keeps the
index because ``ALTER COLUMN`` runs in place there, which is why 0123 looked
harmless: the drifted deployment is the one that never runs the test suite.

``scripts/pg_qualification.py`` found it by comparing the migrated catalogue with
the model metadata; a plain-column comparison misses it, because ``algorithm``
is also covered by ``ix_facts_algorithm``.

If the database already holds duplicates this migration fails on the CREATE, and
that is deliberate: the duplicates are a projection/evidence mismatch an operator
has to reconcile, not rows to delete.

Revision ID: 0127
Revises: 0126
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0127"
down_revision = "0126"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_fact_identity"
TABLE = "cryptographic_facts"
#: must stay identical to 0087 and to ``db.models.cryptographic_fact``
_IDENTITY = (
    "algorithm",
    "coalesce(tenant_id, '')",
    "(tenant_id IS NULL)",
    "coalesce(purpose, '')",
    "coalesce(file_path, '')",
    "coalesce(key_size, 0)",
    "(key_size IS NULL)",
    "coalesce(mode, '')",
)


def _exists(connection) -> bool:
    if connection.dialect.name == "sqlite":
        return connection.execute(
            sa.text("SELECT 1 FROM sqlite_master WHERE type='index' AND name=:name"),
            {"name": INDEX_NAME},
        ).first() is not None
    return connection.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE indexname = :name"),
        {"name": INDEX_NAME},
    ).first() is not None


def upgrade() -> None:
    connection = op.get_bind()
    if _exists(connection):
        return
    if connection.dialect.name == "sqlite":
        # expression indexes cannot be created through op.create_index on SQLite
        columns = ", ".join(_IDENTITY)
        connection.execute(sa.text(
            f"CREATE UNIQUE INDEX {INDEX_NAME} ON {TABLE} ({columns})"
        ))
        return
    op.create_index(INDEX_NAME, TABLE, [sa.text(expr) for expr in _IDENTITY], unique=True)


def downgrade() -> None:
    """Nothing to undo.

    Downgrading re-runs 0123's rebuild, which drops the index again; restoring it
    on the way down would hand the next upgrade a schema this revision exists to
    correct. The index is not created by this revision on a healthy database
    either, so dropping it here could remove something 0087 owns.
    """
    return None
