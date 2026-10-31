"""Admit ``HOST_SNAPSHOT_IMPORT`` in ``scans_target_type_check``.

Revision 0125. Recreates ``scans_target_type_check`` to admit the target type the
host-evidence intake path writes.

Migration 0001 created ``target_type IN ('GIT_REPOSITORY', 'LOCAL_DIRECTORY',
'ARCHIVE')`` — the three types the scanner produces when it runs over a tree. The
host-snapshot import path does not scan a tree; it admits an already-collected
snapshot and records the scan row itself with ``target_type =
"HOST_SNAPSHOT_IMPORT"`` so the evidence it appends can be traced to an import
rather than to a scan that never happened (``api/routers/host_evidence.py``).

On a migrated PostgreSQL that INSERT raised ``CheckViolation``, and the route's
``except IntegrityError`` turned it into ``409 Concurrent approval consumption;
inspect the existing receipt`` — a wrong answer with a misleading message on the
first host import a bank attempts. On SQLite and in every test it was invisible,
because ``create_all`` only creates the constraints the model declares.

The model declares both checks now (``db/models/scan.py``), so this migration and
a ``create_all`` installation agree. Revision 0124 did the same for the status
check and the ``QUEUED`` default.

Revision ID: 0125
Revises: 0124
"""
from __future__ import annotations

from alembic import op

revision = "0125"
down_revision = "0124"
branch_labels = None
depends_on = None

_ALLOWED = ("GIT_REPOSITORY", "LOCAL_DIRECTORY", "ARCHIVE", "HOST_SNAPSHOT_IMPORT")
_PREVIOUS = ("GIT_REPOSITORY", "LOCAL_DIRECTORY", "ARCHIVE")


def _check(values: tuple[str, ...]) -> str:
    return "target_type IN (" + ", ".join(f"'{value}'" for value in values) + ")"


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("scans_target_type_check", type_="check")
        batch.create_check_constraint("scans_target_type_check", _check(_ALLOWED))


def downgrade() -> None:
    # An imported host snapshot cannot survive the narrower constraint, and
    # rewriting its target type would claim the snapshot was scanned. Refuse.
    op.execute("SELECT 1 FROM scans WHERE target_type = 'HOST_SNAPSHOT_IMPORT' LIMIT 1")
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("scans_target_type_check", type_="check")
        batch.create_check_constraint("scans_target_type_check", _check(_PREVIOUS))
