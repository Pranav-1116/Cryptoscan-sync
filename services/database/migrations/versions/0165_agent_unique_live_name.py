"""One live agent per name — the uniqueness Cryptava enrolment promises.

Revision ID: 0165
Revises: 0164

Every Cryptava agent signs its observations under its enrolled name, and the
console composes the estate per contributor name. Two live agents sharing a
name would overwrite each other's slice of the estate, so the enrol endpoint
refuses a taken name (409 ``agent_name_taken``). This index makes that a
database guarantee, so two concurrent enrolments cannot both win:

    uq_cp_agents_live_name  (coalesce(tenant_id, ''), lower(name))
                            WHERE status <> 'retired'

* case-insensitive — ``SWIFTGW01`` and ``swiftgw01`` are the same host;
* ``coalesce`` — platform-scoped agents (NULL tenant) collide with each other;
  a plain unique index lets NULLs repeat;
* partial — a retired agent's name can be enrolled again (rebuilt host).

Like 0153, this refuses to run on a database that already holds two live
agents with one name: the operator retires one, the migration never deletes
or renames rows. The downgrade drops only the enforcement.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0165"
down_revision = "0164"
branch_labels = None
depends_on = None

TABLE = "cp_agents"
NAME = "uq_cp_agents_live_name"
WHERE = "status <> 'retired'"


def _lock_timeout() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("SET LOCAL lock_timeout = '5s'")


def _exists(bind) -> bool:
    # catalog query: SQLAlchemy's inspector omits expression indexes on SQLite
    if bind.dialect.name == "postgresql":
        sql = ("SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() "
               "AND tablename = :t AND indexname = :n")
    else:
        sql = "SELECT 1 FROM sqlite_master WHERE type = 'index' AND tbl_name = :t AND name = :n"
    return bind.execute(sa.text(sql), {"t": TABLE, "n": NAME}).first() is not None


def upgrade() -> None:
    bind = op.get_bind()
    if _exists(bind):  # create_all installs already carry it (the model declares it)
        return
    _lock_timeout()
    duplicate = bind.execute(sa.text(
        f"SELECT coalesce(tenant_id, '') AS tenant, lower(name) AS agent_name, count(*) AS n "
        f"FROM {TABLE} WHERE {WHERE} "
        "GROUP BY coalesce(tenant_id, ''), lower(name) HAVING count(*) > 1 LIMIT 1")).first()
    if duplicate is not None:
        raise RuntimeError(
            f"{TABLE} holds {duplicate.n} live agents named {duplicate.agent_name!r} — "
            "retire all but one (POST /api/v1/control/agents/{id}/upgrade "
            "action=retire) before enforcing unique agent names; this migration "
            "never deletes or renames agents")
    op.execute(
        f"CREATE UNIQUE INDEX {NAME} ON {TABLE} "
        f"(coalesce(tenant_id, ''), lower(name)) WHERE {WHERE}")


def downgrade() -> None:
    bind = op.get_bind()
    if not _exists(bind):
        return
    _lock_timeout()
    op.drop_index(NAME, table_name=TABLE)
