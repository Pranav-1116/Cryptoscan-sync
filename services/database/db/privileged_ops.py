"""Auditing for privileged database operations.

The audit chain (``db.repositories.user_repository``: hash-chained
``audit_log``, advisory-locked appends, ``verify_audit_chain``) covers
every request-path action. The privileged *database* operations —
retention sweeps deleting evidence, partition drops, maintenance scripts —
run outside a request and used to leave no trace at all. A deletion nobody
recorded is indistinguishable from a deletion nobody authorized.

``record_privileged`` is the one seam those paths use: the same chain
append semantics (via UserRepository.audit — one writer, one chain, no
forks), with the actor being the operator or scheduled job name. Every
retention deletion, every partition drop, every archive move calls it.

The database's own half is in ``deploy/ha/pg-primary/postgresql.conf``:
``log_statement = 'ddl'`` and a ``log_line_prefix`` naming the role and
application — the server logs every schema change and privileged
statement regardless of which client issued it.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def record_privileged(db: Any, *, actor: str, action: str,
                      target_type: Optional[str] = None,
                      target_id: Optional[str] = None,
                      detail: Any = None,
                      outcome: str = "SUCCESS") -> Any:
    """Append one privileged-operation entry to the audit chain.

    Returns the row. Failures to audit are RAISED by default posture: a
    privileged action whose record cannot be written does not proceed —
    the caller's operation and its record are one act, not two.
    """
    from db.repositories.user_repository import UserRepository

    repository = UserRepository(db)
    row = repository.audit(
        actor, action, target_type=target_type, target_id=target_id,
        detail=detail, outcome=outcome)
    logger.info("privileged_operation",
                extra={"action": action, "actor": actor,
                       "target_type": target_type, "target_id": target_id,
                       "outcome": outcome})
    return row
