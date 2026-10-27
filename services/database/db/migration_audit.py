"""Alembic schema-migration auditing (audit 78).

Every applied schema migration is a forensic event: the database's shape
changed, and the audit trail should say who/what changed it, when, and from
which revision to which. This module gives the Alembic environment
(``migrations/env.py``) a best-effort hook that writes one hash-chained
``AuditLog`` row per applied revision after ``alembic upgrade`` runs.

Deliberate honesty:

* **Bootstrap revisions are not back-filled.** On a fresh database the
  earliest migrations run *before* the ``audit_log`` table exists; those
  revisions cannot be audited into a table that does not exist yet, and
  fabricating them later would be worse. The hook records everything from
  the first revision applied after the audit table exists.
* **Fail-soft.** The DDL has already committed when the hook runs; an audit
  write failure is logged loudly and never fails a completed migration run.
* The revision walk is pure and unit-tested: ``applied_revisions`` walks
  the script chain from the post-migration head back to the pre-migration
  version.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_ACTION = "db.schema_migration"
AUDIT_ACTOR = "migrator"


def applied_revisions(script_dir: Any, before: str | None, after: str | None) -> list[str]:
    """Revisions applied when the version moved ``before`` -> ``after``.

    Walks the script chain from ``after`` down through ``down_revision``
    links until ``before`` (or the chain base) is reached, and returns the
    revisions in application order. No change (``before == after``) is an
    empty list. A branched history (multiple heads) is not linearly
    walkable, so the walk stops at the first branch point and only the
    linear tail is reported — callers treat that as "some revisions
    applied"; the audit row still records both version strings.
    """
    if not after or after == before:
        return []
    revisions: list[str] = []
    current: str | None = after
    seen: set[str] = set()
    while current and current != before and current not in seen:
        try:
            script = script_dir.get_revision(current)
        except Exception:  # unknown revision id (stamped, pruned history)
            break
        seen.add(current)
        revisions.append(current)
        down = script.down_revision
        if down is None:
            break
        if isinstance(down, tuple):  # branch point — stop, not linear
            break
        current = down
    revisions.reverse()
    return revisions


def _audit_log_exists(connection: Any) -> bool:
    from sqlalchemy import inspect

    try:
        return inspect(connection).has_table("audit_log")
    except Exception:  # pragma: no cover - inspection failure == absent
        return False


def audit_applied_migrations(
    connection: Any,
    *,
    before: str | None,
    after: str | None,
    script_dir: Any = None,
    mode: str = "upgrade",
) -> int:
    """Write one AuditLog row per applied revision. Best-effort.

    Returns the number of audit rows written (0 when the audit table does
    not exist yet — bootstrap — or when nothing was applied).
    """
    if not after or after == before:
        return 0
    if not _audit_log_exists(connection):
        logger.warning(
            "migration_audit_skipped_no_table: revisions %s -> %s applied before "
            "audit_log existed (bootstrap); not back-filled",
            before, after,
        )
        return 0
    if script_dir is None:
        return 0

    revisions = applied_revisions(script_dir, before, after)
    rows = 0
    try:
        from sqlalchemy.orm import Session

        from db.repositories.user_repository import UserRepository

        # The connection may carry an open (read-only) transaction from the
        # version/table probes; a Session joining it would commit only a
        # savepoint and the rows would vanish with the connection. Commit
        # the probe transaction first so session.commit() is a real commit.
        if connection.in_transaction():
            connection.commit()
        session = Session(bind=connection)
        try:
            repo = UserRepository(session)
            for revision in revisions:
                try:
                    script = script_dir.get_revision(revision)
                    detail = {
                        "direction": "up",
                        "mode": mode,
                        "script": getattr(script, "path", None) and
                        str(getattr(script, "path")).rsplit("/", 1)[-1],
                        "down_revision": getattr(script, "down_revision", None),
                        "from_version": before,
                        "to_version": after,
                    }
                except Exception:
                    detail = {"direction": "up", "mode": mode,
                              "from_version": before, "to_version": after}
                repo.audit(
                    AUDIT_ACTOR, AUDIT_ACTION,
                    target_type="alembic_revision", target_id=revision,
                    detail=detail,
                )
                rows += 1
            if not revisions:
                # non-linear or stamped move — still record the version move
                repo.audit(
                    AUDIT_ACTOR, AUDIT_ACTION,
                    target_type="alembic_revision", target_id=after,
                    detail={"direction": "up", "mode": mode, "linear_walk": False,
                            "from_version": before, "to_version": after},
                )
                rows += 1
            session.commit()
        finally:
            session.close()
    except Exception:
        logger.warning(
            "migration_audit_write_failed: %s -> %s (applied DDL is committed; "
            "audit rows could not be written)", before, after, exc_info=True,
        )
        return rows
    return rows
