"""Let the scans table hold a QUEUED scan, the status every writer creates.

Revision 0124. Recreates ``scans_status_check`` to admit ``QUEUED``.

Migration 0001 created ``status IN ('RUNNING', 'COMPLETED', 'FAILED',
'CANCELLED')``. ``Scan.status`` defaults to ``"QUEUED"``, the API's
``ScanStatus`` enum lists it, and the import path builds ``Scan(id=…,
**columns)`` without a status at all. On a migrated PostgreSQL every such row
raised ``CheckViolation`` — a 500 on the first scan a bank takes. On SQLite and
in every test it did not, because ``Base.metadata.create_all`` only creates the
constraints the model declares, and the model declared none.

The model now declares both of these constraints (``db/models/scan.py``), so a
``create_all`` installation and a migrated one agree. This migration exists for
the installations that were built by running the chain.

Revision ID: 0124
Revises: 0123
"""
from __future__ import annotations

from alembic import op

revision = "0124"
down_revision = "0123"
branch_labels = None
depends_on = None

_ALLOWED = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")
_PREVIOUS = ("RUNNING", "COMPLETED", "FAILED", "CANCELLED")


def _check(values: tuple[str, ...]) -> str:
    return "status IN (" + ", ".join(f"'{value}'" for value in values) + ")"


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("scans_status_check", type_="check")
        batch.create_check_constraint("scans_status_check", _check(_ALLOWED))


def downgrade() -> None:
    # A QUEUED row cannot survive the narrower constraint, and silently rewriting
    # a scan's status would falsify its history. Refuse instead.
    op.execute("SELECT 1 FROM scans WHERE status = 'QUEUED' LIMIT 1")
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("scans_status_check", type_="check")
        batch.create_check_constraint("scans_status_check", _check(_PREVIOUS))
