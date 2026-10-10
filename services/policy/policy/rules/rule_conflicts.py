"""Cross-rule conflict detection for policy packs (audit 65 P0#1, round 27).

The rule validator checks each rule in isolation; nothing checked the
rules AGAINST EACH OTHER. When the engine loads every pack together
(``rule_definitions/**/*.yaml`` → one rule set), these cross-rule
hazards are real:

* ``DUPLICATE_ID``       — the same rule_id registered twice (the loader
  keeps both; evaluation fires both, findings double);
* ``EXACT_DUPLICATE``    — different ids, identical condition and verdict
  (maintenance hazard: one gets updated, the other rots);
* ``SHADOWED``           — rule A's coverage is a subset of rule B's,
  same verdict, and B is at least as loud: A can never alert on its own;
* ``CONTRADICTORY``      — overlapping coverage with different verdicts
  (one rule FAILs what another PASSes — the engine emits both and the
  compliance answer depends on rule order);
* ``OVERLAPPING``        — partial coverage overlap, same verdict,
  different severities (informational: an author may want to know).

Everything is deterministic set/interval logic over the four typed
condition shapes; incomparable shapes are honestly skipped rather than
guessed. The analyzer is pure — no database, no clock, no I/O — so the
API layer can feed it the effective (post-override) rule set and an
auditor can replay any verdict.
"""

from __future__ import annotations

from typing import Any, Iterable

from policy.models.policy_rule import PolicyRule

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

_ALGORITHM_IN_LIST = "ALGORITHM_IN_LIST"
_KEY_SIZE_MINIMUM = "KEY_SIZE_MINIMUM"
_MODE_WHITELIST = "ALGORITHM_MODE_WHITELIST"
_BOOLEAN_FLAG = "BOOLEAN_FLAG"


def _scope_key(rule: PolicyRule) -> tuple[frozenset[str], tuple[frozenset[str], ...]]:
    """The rule's compliance-scope restriction (see ``core.scope_resolver``).

    A rule with no ``required_scopes`` and no ``required_scope_groups``
    applies everywhere; a scoped rule only fires on findings carrying a
    matching scope tag. Cross-scope shadowing is only sound when the
    shadower fires on *every* scope the shadowed rule fires on.
    """
    params = rule.condition.parameters or {}
    required = {str(item).upper() for item in (params.get("required_scopes") or [])}
    groups: list[frozenset[str]] = []
    for group in params.get("required_scope_groups") or []:
        items = frozenset(str(item).upper() for item in group)
        if items:
            groups.append(items)
    groups.sort(key=sorted)
    return frozenset(required), tuple(groups)


def _unscoped(key: tuple[frozenset[str], tuple[frozenset[str], ...]]) -> bool:
    return not key[0] and not key[1]


def _verdict(rule: PolicyRule) -> str:
    evaluation = rule.evaluation
    return str((evaluation.result_template if evaluation else None) or "FAIL").upper()


def _rank(rule: PolicyRule) -> int:
    return SEVERITY_RANK.get(str(rule.severity or "INFO").upper(), 0)


def _algorithms(rule: PolicyRule) -> set[str] | None:
    """The algorithm set an ALGORITHM_IN_LIST rule fires on (normalized)."""
    if rule.condition.type != _ALGORITHM_IN_LIST:
        return None
    raw = rule.condition.parameters.get("algorithm_list") or []
    return {str(item).upper().replace("_", "-") for item in raw}


def _key_size_params(rule: PolicyRule) -> tuple[str, int] | None:
    if rule.condition.type != _KEY_SIZE_MINIMUM:
        return None
    algorithm = str(rule.condition.parameters.get("algorithm") or "").upper().replace("_", "-")
    try:
        minimum = int(rule.condition.parameters.get("minimum_key_size") or 0)
    except (TypeError, ValueError):
        return None
    if not algorithm:
        return None
    return algorithm, minimum


def _mode_params(rule: PolicyRule) -> tuple[str, frozenset[str]] | None:
    """(algorithm, forbidden_modes) — the modes a rule fires on.

    Only the ``forbidden_modes`` shape supports superset reasoning (the
    rule fires when the observed mode is in the set). Approved-list
    rules are not comparable beyond exact equality — honest, not lazy.
    """
    if rule.condition.type != _MODE_WHITELIST:
        return None
    algorithm = str(rule.condition.parameters.get("algorithm") or "").upper().replace("_", "-")
    if not algorithm:
        return None
    forbidden = rule.condition.parameters.get("forbidden_modes") or []
    if not forbidden:
        return None
    return algorithm, frozenset(str(m).upper() for m in forbidden)


def _flag_params(rule: PolicyRule) -> tuple[str, bool] | None:
    if rule.condition.type != _BOOLEAN_FLAG:
        return None
    field = str(rule.condition.parameters.get("field") or "")
    if not field:
        return None
    return field, bool(rule.condition.parameters.get("forbidden_value", True))


def _covers(outer: PolicyRule, inner: PolicyRule) -> bool | None:
    """Does ``outer`` fire on every finding ``inner`` fires on?

    Scope-wise this is only sound when the rules share the same scope
    restriction, or ``outer`` is unscoped (fires everywhere). Otherwise
    returns None — the caller must treat that as "unknown", never as
    True or False.
    """
    outer_scope, inner_scope = _scope_key(outer), _scope_key(inner)
    if outer_scope != inner_scope and not _unscoped(outer_scope):
        return None

    outer_algs = _algorithms(outer)
    inner_algs = _algorithms(inner)
    if outer_algs is not None and inner_algs is not None:
        return inner_algs <= outer_algs
    if outer_algs is not None:
        # list rule vs typed rule: covers it iff the typed rule's
        # algorithm is in the list (the list rule fires on ANY finding
        # of that algorithm)
        inner_ks = _key_size_params(inner)
        if inner_ks is not None:
            return inner_ks[0] in outer_algs
        inner_mode = _mode_params(inner)
        if inner_mode is not None:
            return inner_mode[0] in outer_algs
        return None
    outer_ks = _key_size_params(outer)
    inner_ks = _key_size_params(inner)
    if outer_ks is not None and inner_ks is not None:
        # a weaker minimum fires on more key sizes
        return outer_ks[0] == inner_ks[0] and outer_ks[1] <= inner_ks[1]
    outer_mode = _mode_params(outer)
    inner_mode = _mode_params(inner)
    if outer_mode is not None and inner_mode is not None:
        return outer_mode[0] == inner_mode[0] and inner_mode[1] <= outer_mode[1]
    outer_flag = _flag_params(outer)
    inner_flag = _flag_params(inner)
    if outer_flag is not None and inner_flag is not None:
        return outer_flag == inner_flag
    return None


def _condition_key(rule: PolicyRule) -> tuple:
    params = dict(rule.condition.parameters or {})
    # normalize the shapes that matter for identity
    algs = _algorithms(rule)
    if algs is not None:
        return (rule.condition.type, tuple(sorted(algs)))
    return (rule.condition.type, tuple(sorted((str(k), str(v)) for k, v in params.items())))


def detect_rule_conflicts(rules: Iterable[PolicyRule]) -> list[dict[str, Any]]:
    """Analyze a loaded rule set; returns conflict entries, worst first."""
    rules = [rule for rule in rules if getattr(rule, "enabled", True)]
    conflicts: list[dict[str, Any]] = []

    # 1. duplicate rule ids (the loader keeps both files)
    by_id: dict[str, list[PolicyRule]] = {}
    for rule in rules:
        by_id.setdefault(rule.rule_id, []).append(rule)
    for rule_id, group in sorted(by_id.items()):
        if len(group) > 1:
            conflicts.append({
                "type": "DUPLICATE_ID",
                "rules": [rule_id] * len(group),
                "detail": f"rule_id {rule_id} registered {len(group)} times; "
                          "evaluation fires every copy",
            })

    active = [rule for rule in rules if len(by_id[rule.rule_id]) == 1]

    # 2. pairwise shape-aware analysis
    for i in range(len(active)):
        for j in range(i + 1, len(active)):
            a, b = active[i], active[j]
            if a.rule_id > b.rule_id:
                a, b = b, a  # stable ordering in reports

            same_condition = _condition_key(a) == _condition_key(b)
            verdict_a, verdict_b = _verdict(a), _verdict(b)
            same_scope = _scope_key(a) == _scope_key(b)

            if same_condition:
                if not same_scope:
                    # same shape but different compliance scopes — they
                    # fire on different systems by design, not duplicates
                    continue
                if verdict_a != verdict_b:
                    conflicts.append({
                        "type": "CONTRADICTORY",
                        "rules": [a.rule_id, b.rule_id],
                        "detail": f"identical conditions but verdicts differ "
                                  f"({verdict_a} vs {verdict_b})",
                    })
                else:
                    conflicts.append({
                        "type": "EXACT_DUPLICATE",
                        "rules": [a.rule_id, b.rule_id],
                        "detail": "identical conditions and verdict under two ids",
                    })
                continue

            a_covers_b = _covers(a, b)
            b_covers_a = _covers(b, a)
            overlap = (a_covers_b is True) or (b_covers_a is True)
            # partial overlap is only decidable for algorithm-list rules,
            # and only meaningful within the same scope regime
            algs_a, algs_b = _algorithms(a), _algorithms(b)
            if algs_a is not None and algs_b is not None and not overlap and same_scope:
                overlap = bool(algs_a & algs_b)

            if not overlap:
                continue

            if verdict_a != verdict_b:
                conflicts.append({
                    "type": "CONTRADICTORY",
                    "rules": [a.rule_id, b.rule_id],
                    "detail": f"overlapping conditions with different verdicts "
                              f"({verdict_a} vs {verdict_b})",
                })
                continue

            # same verdict, overlapping coverage
            if b_covers_a is True and _rank(b) >= _rank(a) and not (a_covers_b is True):
                conflicts.append({
                    "type": "SHADOWED",
                    "rules": [a.rule_id, b.rule_id],
                    "detail": f"{a.rule_id} is shadowed by {b.rule_id}: "
                              f"{b.rule_id} fires on everything {a.rule_id} does, "
                              f"at least as loud",
                })
            elif a_covers_b is True and _rank(a) >= _rank(b) and not (b_covers_a is True):
                conflicts.append({
                    "type": "SHADOWED",
                    "rules": [b.rule_id, a.rule_id],
                    "detail": f"{b.rule_id} is shadowed by {a.rule_id}: "
                              f"{a.rule_id} fires on everything {b.rule_id} does, "
                              f"at least as loud",
                })
            elif _rank(a) != _rank(b):
                conflicts.append({
                    "type": "OVERLAPPING",
                    "rules": [a.rule_id, b.rule_id],
                    "detail": f"partially overlapping conditions with different "
                              f"severities ({a.severity} vs {b.severity})",
                })

    order = {"DUPLICATE_ID": 0, "CONTRADICTORY": 1, "EXACT_DUPLICATE": 2,
             "SHADOWED": 3, "OVERLAPPING": 4}
    conflicts.sort(key=lambda item: (order.get(item["type"], 9), tuple(item["rules"])))
    return conflicts
