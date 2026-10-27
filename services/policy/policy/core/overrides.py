"""Apply tenant policy-rule overrides on top of the YAML rule pack (audit 05).

One helper, used by BOTH the API's rule listing and the worker's evaluation
stage, so the rules an operator sees disabled are exactly the rules the
engine skips — divergence between the two was the risk that kept rule
management read-only.

An override can disable a rule for this tenant or change its severity. The
pack on disk is never edited; overrides are rows, so they are auditable,
tenant-scoped and revertible (DELETE restores pack behavior).
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

logger = logging.getLogger(__name__)


def apply_overrides(engine: Any, overrides: Iterable[Any]) -> dict[str, int]:
    """Mutate ``engine``'s rule set in place from override rows.

    ``overrides`` are PolicyRuleOverride-like objects (``rule_id``,
    ``enabled``, ``severity``). Unknown rule_ids are counted and ignored —
    an override that outlived a pack change must not crash evaluation.
    Returns ``{"applied": n, "unknown_rule": n}``.
    """
    applied = 0
    unknown = 0
    by_id = {rule.rule_id: rule for rule in engine.rule_set.rules}
    for row in overrides:
        rule = by_id.get(row.rule_id)
        if rule is None:
            unknown += 1
            logger.warning(
                "policy_override_unknown_rule", extra={"rule_id": row.rule_id}
            )
            continue
        rule.enabled = bool(row.enabled)
        if row.severity:
            rule.severity = row.severity
        applied += 1
    if applied:
        # the evaluator caches the enabled-rule list at construction; rebuild
        # it so the change is visible to evaluate()
        engine.evaluator.reload_rules(engine.rule_set)
    return {"applied": applied, "unknown_rule": unknown}


def load_override_rows(session: Any) -> list[Any]:
    """All policy-rule overrides visible to this session (tenant-guarded).

    Returns [] when the table does not exist yet (pre-migration installs or
    test sessions without migrations) — evaluation then runs on the pack
    alone, which is the previous behaviour, not a crash.
    """
    try:
        from db.models.policy_rule_override import PolicyRuleOverride

        return list(session.query(PolicyRuleOverride).all())
    except Exception:
        logger.debug("policy_overrides_unavailable", exc_info=True)
        return []
