"""Behavioral rule coverage (round 55, §4.3).

``rule_coverage.py`` (round 28) answers "which rules does no test file even
MENTION?" — a static lead-generation report, explicitly not proof. This
module is the behavioral successor the vision doc demands: it derives, per
ENABLED rule, a **trigger** and a **clean** evidence pair from the rule's
own condition parameters, evaluates both through the REAL policy engine,
and reports what actually happened:

* ``triggered`` — the trigger pair produced FAIL or WARN (the rule FIRED
  on evidence that violates its own declared parameters);
* ``clean_pass`` — the clean pair produced PASS (the rule does not fire
  on evidence that satisfies its parameters);
* rules whose semantics defeat derivation are reported with the reason —
  never silently dropped, never counted as covered.

The point: "covered" here means *the rule executed and decided*, not
*its ID appears in a file*. A rule that cannot be made to fire on
synthetic evidence derived from its own parameters is exactly the rule
an operator should worry about.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from policy.conditions.base_condition import algorithm_matches
from policy.core.engine import PolicyEngine
from policy.core.scope_resolver import as_scope_list

#: An algorithm that no sane pack forbids — used for clean evidence when
#: the rule does not dictate one.
_BENIGN_ALGORITHM = "ML-DSA"
_BENIGN_MODE = "GCM"


def _load_rules(rules_dir: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for yaml_file in sorted(Path(rules_dir).glob("**/*.yaml")):
        if yaml_file.name.startswith("_") or yaml_file.parent.name.startswith("_"):
            continue
        try:
            with open(yaml_file, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(data, dict) and data.get("rule_id") and data.get("enabled", True):
            data["_pack"] = yaml_file.parent.name
            rules.append(data)
    return rules


def _scope_tags(params: dict[str, Any]) -> list[str]:
    """Scope tags that satisfy any-of required_scopes + every any-of group."""
    tags: list[str] = []
    required = as_scope_list(params.get("required_scopes"))
    if required:
        tags.append(required[0])
    for group in params.get("required_scope_groups") or []:
        items = as_scope_list(group)
        if items:
            tags.append(items[0])
    return tags


def _pick_clean_algorithm(params: dict[str, Any]) -> str | None:
    """An algorithm that satisfies the rule's applicability and approval sets."""
    required = as_scope_list(params.get("require_algorithms"))
    if required:
        return required[0]
    approved = as_scope_list(params.get("approved_algorithms"))
    if approved:
        return approved[0]
    if_algorithms = as_scope_list(params.get("if_algorithms"))
    forbidden = {str(a).upper() for a in as_scope_list(params.get("forbidden_algorithms"))}
    if if_algorithms:
        for candidate in if_algorithms:
            if candidate.upper() not in forbidden:
                return candidate
        return None  # applicability set is entirely forbidden — no clean pair
    if algorithm_matches({"algorithm": _BENIGN_ALGORITHM}, list(forbidden)) is None:
        return _BENIGN_ALGORITHM
    return None


def _complex_base(params: dict[str, Any], *, for_trigger: bool) -> dict[str, Any] | None:
    """Evidence satisfying every COMPLEX gate (scopes, purpose, algorithm)."""
    evidence: dict[str, Any] = {"id": "behavioral", "evaluation_date": date.today().isoformat()}
    scopes = _scope_tags(params)
    if scopes:
        evidence["compliance_scopes"] = scopes
    if_purpose = [p.upper() for p in as_scope_list(params.get("if_purpose"))]
    forbidden_purposes = {p.upper() for p in as_scope_list(params.get("forbidden_purposes"))}
    purpose = None
    if if_purpose:
        purpose = next((p for p in if_purpose if p not in forbidden_purposes), None)
        if purpose is None:
            return None
    elif params.get("require_purpose"):
        purpose = "ENCRYPTION"
        if purpose in forbidden_purposes:
            purpose = "KEY_GENERATION"
            if purpose in forbidden_purposes:
                return None
    if purpose:
        evidence["purpose"] = purpose
    algorithm = _pick_clean_algorithm(params)
    if if_purpose or params.get("if_algorithms") or params.get("require_algorithms"):
        # applicability needs an algorithm; without a derivable one there is no pair
        if algorithm is None:
            return None
        evidence["algorithm"] = algorithm
    if params.get("require_modes"):
        evidence["mode"] = as_scope_list(params.get("require_modes"))[0]
    else:
        evidence["mode"] = _BENIGN_MODE
    min_key = params.get("min_key_size")
    evidence["key_size"] = max(int(min_key) * 2, 4096) if min_key is not None else 4096
    if not for_trigger:
        # an allow_if_true waiver must NOT be set on clean evidence
        evidence.setdefault("extra", {})
    return evidence


def _complex_trigger_candidates(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Violation evidence candidates, derived from the rule's own parameters."""
    base = _complex_base(params, for_trigger=True)
    if base is None:
        return []
    candidates: list[dict[str, Any]] = []

    def variant(**changes: Any) -> None:
        evidence = dict(base)
        evidence.update(changes)  # None values ARE the trigger (purpose/mode absent)
        candidates.append(evidence)

    forbidden = as_scope_list(params.get("forbidden_algorithms"))
    if forbidden:
        variant(algorithm=forbidden[0])
    min_key = params.get("min_key_size")
    if min_key is not None and int(min_key) > 1:
        variant(key_size=max(1, int(min_key) - 1))
    required = as_scope_list(params.get("require_algorithms"))
    if required:
        # an algorithm that is applicable yet outside the approved set
        if_algorithms = as_scope_list(params.get("if_algorithms"))
        pool = [a for a in if_algorithms if a.upper() not in {r.upper() for r in required}]
        if pool:
            variant(algorithm=pool[0])
        elif algorithm_matches({"algorithm": "MD5"}, required) is None:
            gates_need_algorithm = bool(if_algorithms)
            if not gates_need_algorithm:
                variant(algorithm="MD5")
    required_modes = as_scope_list(params.get("require_modes"))
    if required_modes:
        variant(mode="ECB" if "ECB" not in {m.upper() for m in required_modes} else "CBC")
    if params.get("mode_required"):
        variant(mode=None)
    forbidden_purposes = as_scope_list(params.get("forbidden_purposes"))
    if_purpose = [p.upper() for p in as_scope_list(params.get("if_purpose"))]
    if forbidden_purposes:
        allowed_forbidden = [p for p in forbidden_purposes if not if_purpose or p.upper() in if_purpose]
        if allowed_forbidden:
            variant(purpose=allowed_forbidden[0])
    if params.get("require_purpose") and not if_purpose:
        variant(purpose=None)
    return candidates


def _clause_params(clause: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    ctype = str(clause.get("type") or clause.get("condition_type") or "")
    return ctype, clause.get("parameters") or clause.get("params") or {}


def _derive_pair(condition_type: str, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(trigger, clean) evidence for one condition type, or None (not derivable)."""
    today = date.today()
    if condition_type == "COMPLEX":
        base = _complex_base(params, for_trigger=False)
        if base is None:
            return None
        # clean must also satisfy every nested clause
        clauses = params.get("clauses") or params.get("conditions") or params.get("all_of") or params.get("any_of")
        clean = dict(base)
        if clauses:
            operator = "ANY_OF" if params.get("any_of") else "ALL_OF"
            for clause in clauses:
                if not isinstance(clause, dict):
                    continue
                ctype, cparams = _clause_params(clause)
                sub = _derive_pair(ctype, cparams)
                if sub is None:
                    if operator == "ALL_OF":
                        return None  # an underivable ALL_OF clause blocks the clean pair
                    continue
                for key, value in sub[1].items():
                    if key in ("id",):
                        continue
                    if key in clean and clean[key] != value:
                        if operator == "ALL_OF":
                            return None  # conflicting clause requirements
                        continue
                    clean[key] = value
        triggers = _complex_trigger_candidates(params)
        if clauses:
            for clause in clauses:
                if not isinstance(clause, dict):
                    continue
                ctype, cparams = _clause_params(clause)
                sub = _derive_pair(ctype, cparams)
                if sub is not None:
                    triggers.append(sub[0])
        if not triggers:
            return None
        # try trigger candidates in order; caller evaluates and keeps the first that fires
        return {"candidates": triggers}, clean

    if condition_type == "ALGORITHM_IN_LIST":
        forbidden = as_scope_list(params.get("algorithm_list"))
        if not forbidden:
            return None
        clean_algo = _BENIGN_ALGORITHM if algorithm_matches({"algorithm": _BENIGN_ALGORITHM}, forbidden) is None else None
        if clean_algo is None:
            return None
        return ({"algorithm": forbidden[0]}, {"algorithm": clean_algo})

    if condition_type == "KEY_SIZE_MINIMUM":
        algorithm = str(params.get("algorithm") or "")
        minimum = params.get("minimum_key_size")
        if not algorithm or minimum is None:
            return None
        weak = int(minimum) - 1
        if weak < 1:
            return None
        return (
            {"algorithm": algorithm, "key_size": weak},
            {"algorithm": algorithm, "key_size": max(int(minimum) * 2, 4096)},
        )

    if condition_type == "ALGORITHM_MODE_WHITELIST":
        algorithm = str(params.get("algorithm") or "")
        bad_modes = as_scope_list(params.get("forbidden_modes"))
        if not algorithm or not bad_modes:
            return None
        good = "GCM" if "GCM" not in {m.upper() for m in bad_modes} else "CTR"
        return ({"algorithm": algorithm, "mode": bad_modes[0]}, {"algorithm": algorithm, "mode": good})

    if condition_type == "BOOLEAN_FLAG":
        field = str(params.get("field") or "")
        forbidden_value = bool(params.get("forbidden_value", True))
        if not field:
            return None
        return ({field: forbidden_value}, {field: not forbidden_value})

    if condition_type == "TIMELINE":
        retired = as_scope_list(params.get("retired_algorithms"))
        approved = as_scope_list(params.get("approved_algorithms"))
        if_purpose = [p.upper() for p in as_scope_list(params.get("if_purpose"))]
        after = str(params.get("after") or params.get("retire_after") or "")
        if not retired or not approved or not after:
            return None
        trigger = {"algorithm": retired[0], "evaluation_date": "2099-01-01"}
        clean = {"algorithm": approved[0]}
        if if_purpose:
            trigger["purpose"] = if_purpose[0]
            clean["purpose"] = if_purpose[0]  # the applicability gate applies to clean too
        scopes = _scope_tags(params)
        if scopes:
            trigger["compliance_scopes"] = scopes
            clean["compliance_scopes"] = scopes
        return trigger, clean

    if condition_type == "KEY_INVENTORY_ATTRIBUTE":
        attribute = str(params.get("attribute") or "")
        operator = str(params.get("operator") or "")
        if not attribute or not operator:
            return None

        def inv(payload: dict[str, Any]) -> dict[str, Any]:
            # the condition reads finding_data.source.type (not top-level)
            base = {"finding_data": {"source": {"type": "KEY_INVENTORY"},
                                     "inventory": dict(payload)}}
            for extra_attr in as_scope_list(params.get("require_attributes")):
                base["finding_data"]["inventory"].setdefault(extra_attr, "2030-01-01")
            return base

        days = int(params.get("days") or 30)
        value = params.get("value")
        values = as_scope_list(params.get("values"))
        if operator in {"equals", "in", "contains"}:
            needle = value if value is not None else (values[0] if values else None)
            if needle is None or str(needle) == "":
                return None
            if operator == "contains":
                clean_value = "zzz-not-matching-placeholder"  # must not CONTAIN the needle
            else:
                clean_value = f"not-{needle}"
            return (inv({attribute: str(needle)}), inv({attribute: clean_value}))
        if operator == "is_true":
            return (inv({attribute: True}), inv({attribute: False}))
        if operator == "date_before_today":
            return (inv({attribute: "2020-01-01"}), inv({attribute: "2099-01-01"}))
        if operator == "date_within_days":
            return (inv({attribute: (today + timedelta(days=1)).isoformat()}),
                    inv({attribute: (today + timedelta(days=days * 3 + 7)).isoformat()}))
        if operator == "older_than_days":
            return (inv({attribute: (today - timedelta(days=days * 2 + 1)).isoformat()}),
                    inv({attribute: today.isoformat()}))
        if operator == "missing":
            return ({}, inv({attribute: "2030-01-01"}))
        return None

    return None


def run_behavioral_coverage(rules_directory: str | Path) -> dict[str, Any]:
    """Evaluate every enabled rule against derived trigger/clean pairs.

    Returns a report: per-rule outcome plus the honest lists of rules that
    could not be derived or did not behave as their parameters declare.
    """
    rules_dir = Path(rules_directory)
    rules = _load_rules(rules_dir)
    engine = PolicyEngine(str(rules_dir))
    by_id = {r["rule_id"]: r for r in rules}

    covered: list[dict[str, Any]] = []
    not_derivable: list[dict[str, str]] = []
    misbehaved: list[dict[str, Any]] = []

    for rule in rules:
        rule_id = str(rule["rule_id"])
        condition = rule.get("condition") or {}
        ctype = str(condition.get("type") or "")
        params = condition.get("parameters") or {}
        pair = _derive_pair(ctype, params)
        if pair is None:
            not_derivable.append({"rule_id": rule_id, "reason": f"no synthetic pair derivable for condition {ctype}"})
            continue

        def _evaluate(evidence: dict[str, Any]) -> str | None:
            merged = {"id": f"{rule_id}-evidence", **evidence}
            evaluation = engine.evaluate(merged)
            for result in evaluation.rules_evaluated:
                if result.rule_id == rule_id:
                    return str(result.evaluation_result)
            return None

        trigger, clean = pair
        candidates = trigger.get("candidates") if isinstance(trigger, dict) and "candidates" in trigger else [trigger]
        trigger_result = None
        for candidate in candidates:
            outcome = _evaluate(candidate)
            if outcome in {"FAIL", "WARN"}:
                trigger_result = outcome
                break
            trigger_result = trigger_result or outcome
        clean_result = _evaluate(clean)
        entry = {"rule_id": rule_id, "pack": rule.get("_pack"),
                 "trigger_result": trigger_result, "clean_result": clean_result}
        if trigger_result in {"FAIL", "WARN"} and clean_result == "PASS":
            covered.append(entry)
        else:
            entry["reason"] = (f"trigger={trigger_result} clean={clean_result} "
                               f"(expected trigger FAIL/WARN and clean PASS)")
            misbehaved.append(entry)

    return {
        "enabled_rules": len(rules),
        "behaviorally_covered": len(covered),
        "not_derivable": not_derivable,
        "misbehaved": misbehaved,
        "covered_rule_ids": sorted(e["rule_id"] for e in covered),
        "engine_pack_hash": engine.pack_hash(),
        "by_id_present": set(by_id) == {r["rule_id"] for r in rules},
    }
