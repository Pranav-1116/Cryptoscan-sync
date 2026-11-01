"""Auth hardening columns: password history, TOTP step, session idle clock.

Revision 0128. Three columns, each closing a named gap from guide 120:

* ``users.password_history`` — a JSON list of previous password *hashes* so a
  password cannot be re-used. Hashes only: a history that stored plaintext would
  be a second credential store to protect.
* ``users.last_totp_step`` — the last accepted RFC 6238 time-step, so an observed
  code cannot be replayed inside its own window.
* ``user_sessions.last_seen_at`` — an idle clock, which is a different control
  from an absolute expiry: a token carried by a stolen laptop that is never used
  still dies at expiry, while one used continuously keeps working until the
  absolute limit.

Every column is nullable, so an existing store upgrades in place and the old
behaviour (no history, no replay check, no idle limit) is the absence of a value
rather than a migration failure.

Revision ID: 0128
Revises: 0127
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0128"
down_revision = "0127"
branch_labels = None
depends_on = None

_TABLE_COLUMNS = (
    ("users", "password_history", sa.Text()),
    ("users", "last_totp_step", sa.Integer()),
    ("user_sessions", "last_seen_at", sa.DateTime(timezone=True)),
)


def _has_column(table: str, column: str) -> bool:
    inspector = sa.inspect(op.get_bind())
    try:
        return any(col["name"] == column for col in inspector.get_columns(table))
    except sa.exc.NoSuchTableError:  # fresh database before create_all
        return False


def upgrade() -> None:
    for table, column, kind in _TABLE_COLUMNS:
        if not _has_column(table, column):
            op.add_column(table, sa.Column(column, kind, nullable=True))


def downgrade() -> None:
    for table, column, _kind in reversed(_TABLE_COLUMNS):
        if _has_column(table, column):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column)
