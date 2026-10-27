"""Policy-as-code engine — versioned, composable, deterministic.

Policies are structured documents layered as

    sector + region + organization + technical controls + risk rules

and evaluated against findings/attributes. Every policy has an immutable
version (hash), and evaluation is pure/deterministic — the AI never decides
policy. A policy result is PASS / FAIL / WARN / NOT_APPLICABLE with the
specific rule that fired, for auditability.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field

VERDICTS = ("PASS", "FAIL", "WARN", "NOT_APPLICABLE")

#: operator -> evaluation against (actual, expected). Pure functions.
OPERATORS = {
    "eq": lambda a, e: a == e,
    "ne": lambda a, e: a != e,
    "lt": lambda a, e: a is not None and a < e,
    "lte": lambda a, e: a is not None and a <= e,
    "gt": lambda a, e: a is not None and a > e,
    "gte": lambda a, e: a is not None and a >= e,
    "in": lambda a, e: a in e,
    "not_in": lambda a, e: a not in e,
    "contains": lambda a, e: e in (a or []),
    "not_contains": lambda a, e: e not in (a or []),
}


def policy_version(policy: dict) -> str:
    """Stable content hash for a policy document (version/audit key)."""
    canonical = json.dumps(policy.get("rules", policy), sort_keys=True,
                            separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _get(path: str, target: dict):
    cur = target
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


@dataclass
class RuleResult:
    rule_id: str
    verdict: str
    detail: str = ""


@dataclass
class PolicyResult:
    policy_id: str
    version: str
    verdict: str
    rule_results: list[RuleResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"policy_id": self.policy_id, "version": self.version,
                "verdict": self.verdict,
                "rules": [{"rule_id": r.rule_id, "verdict": r.verdict, "detail": r.detail}
                          for r in self.rule_results]}


def _merge(dst: dict, src: dict) -> dict:
    out = copy.deepcopy(dst)
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def merge_policy_layers(*layers: dict) -> dict:
    """Merge sector/region/org/control/risk layers (later layers win)."""
    merged: dict = {"rules": []}
    for layer in layers:
        if not layer:
            continue
        merged = _merge(merged, {k: v for k, v in layer.items() if k != "rules"})
        if layer.get("rules"):
            merged.setdefault("rules", [])
            merged["rules"] = merged["rules"] + list(layer["rules"])
    merged["version"] = policy_version(merged)
    return merged


def evaluate_rule(rule: dict, target: dict) -> RuleResult:
    rid = rule.get("id", "rule")
    # applicability (scope) gate
    when = rule.get("when")
    if when:
        for path, expected in when.items():
            if _get(path, target) != expected:
                return RuleResult(rid, "NOT_APPLICABLE", f"scope {path}!={expected}")
    op = rule.get("op", "eq")
    actual = _get(rule.get("path", ""), target)
    expected = rule.get("value")
    try:
        satisfied = OPERATORS.get(op, lambda a, e: False)(actual, expected)
    except TypeError:
        satisfied = False
    action = rule.get("effect", rule.get("action", "fail"))  # fail/warn
    if satisfied:
        return RuleResult(rid, "PASS", f"{rule.get('path')} {op} {expected}")
    verdict = "WARN" if action == "warn" else "FAIL"
    return RuleResult(rid, verdict, f"{rule.get('path')}={actual!r} violates {op} {expected!r}")


def evaluate_policy(policy: dict, target: dict) -> PolicyResult:
    """Evaluate a (possibly merged) policy against a finding/asset target."""
    results = [evaluate_rule(r, target) for r in policy.get("rules", [])]
    active = [r for r in results if r.verdict != "NOT_APPLICABLE"]
    if any(r.verdict == "FAIL" for r in active):
        verdict = "FAIL"
    elif any(r.verdict == "WARN" for r in active):
        verdict = "WARN"
    elif active:
        verdict = "PASS"
    else:
        verdict = "NOT_APPLICABLE"
    return PolicyResult(policy.get("id", "policy"), policy.get("version") or policy_version(policy),
                         verdict, results)
