"""Deterministic ruleset engine for marketplace ``ruleset`` plugins (no AI/ML).

A ruleset is a versioned, hash-pinned list of declarative detection rules. The
engine compiles them once and matches findings deterministically — no inference,
no model scoring. Rules are explicit and auditable.

Rule schema (YAML/JSON, all fields except id/algorithm optional)::

    id: DES-HARDCODED-001
    algorithm: DES                 # matches when finding.algorithm canonicalizes to this
    min_key_size: 128              # finding key size below this matches (weak key length)
    max_key_size: 64
    status_in: [DISALLOWED, DEPRECATED]
    is_hardcoded_key: true         # boolean finding attribute must equal
    path_glob: "**/legacy/**"      # glob over file_path (fnmatch on ** supported)
    line_min: 1000                 # line_number >= this (e.g. hand-rolled after a cutover)
    confidence_min: HIGH           # ordering LOW<MEDIUM<HIGH
    decision: FAIL                 # FAIL (must remediate) or WARN (advisory)
    message: "DES must be replaced by AES-GCM"
    remediation: "Replace Cipher.getInstance(\"DES\") with AES/GCM/NoPadding."

A finding matches a rule when ALL of the rule's set conditions hold. The engine
returns structured matches with the rule id, decision, and message so callers
can gate CI / raise tickets deterministically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CONFIRMED": 3,
                    "PROBABLE": 2, "POSSIBLE": 1, "UNKNOWN": 0}

VALID_DECISIONS = frozenset({"FAIL", "WARN", "PASS"})
_ALGO_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.-]{0,63}$")


class RulesetError(ValueError):
    """Raised when a ruleset or rule is structurally invalid."""


def _canon_algo(value: Any) -> str:
    return str(value or "").strip().upper().replace(" ", "").replace("_", "-")


def _glob_to_re(glob: str) -> re.Pattern:
    # translate fnmatch-style glob, supporting ** across path separators
    i = 0
    out = ["(?s:"]
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append(r")\Z")
    return re.compile("".join(out))


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str | None = None
    min_key_size: int | None = None
    max_key_size: int | None = None
    status_in: tuple[str, ...] = ()
    is_hardcoded_key: bool | None = None
    path_glob: str | None = None
    line_min: int | None = None
    line_max: int | None = None
    confidence_min: str | None = None
    decision: str = "FAIL"
    message: str = ""
    remediation: str = ""

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Rule":
        if not isinstance(data, dict):
            raise RulesetError("each rule must be an object")
        rid = str(data.get("id") or "").strip()
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$", rid):
            raise RulesetError(f"rule id missing or invalid: {rid!r}")
        algo = data.get("algorithm")
        if algo is not None:
            algo = _canon_algo(algo)
            if not _ALGO_RE.match(algo):
                raise RulesetError(f"rule {rid}: invalid algorithm {algo!r}")
        decision = str(data.get("decision") or "FAIL").upper()
        if decision not in VALID_DECISIONS:
            raise RulesetError(f"rule {rid}: decision must be one of {sorted(VALID_DECISIONS)}")
        status_in = tuple(str(s).upper() for s in (data.get("status_in") or ()))
        conf = data.get("confidence_min")
        if conf is not None:
            conf = str(conf).upper()
            if conf not in CONFIDENCE_ORDER:
                raise RulesetError(f"rule {rid}: unknown confidence_min {conf!r}")
        return Rule(
            id=rid,
            algorithm=algo,
            min_key_size=_as_int(data.get("min_key_size"), "min_key_size", rid),
            max_key_size=_as_int(data.get("max_key_size"), "max_key_size", rid),
            status_in=status_in,
            is_hardcoded_key=_as_bool(data.get("is_hardcoded_key"), "is_hardcoded_key", rid),
            path_glob=str(data["path_glob"]) if data.get("path_glob") else None,
            line_min=_as_int(data.get("line_min"), "line_min", rid),
            line_max=_as_int(data.get("line_max"), "line_max", rid),
            confidence_min=conf,
            decision=decision,
            message=str(data.get("message") or ""),
            remediation=str(data.get("remediation") or ""),
        )


def _as_int(value, name: str, rid: str):
    if value is None:
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise RulesetError(f"rule {rid}: {name} must be an integer") from None
    if v < 0:
        raise RulesetError(f"rule {rid}: {name} must be >= 0")
    return v


def _as_bool(value, name: str, rid: str):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise RulesetError(f"rule {rid}: {name} must be a boolean")


@dataclass
class Ruleset:
    name: str
    version: str
    rules: list[Rule] = field(default_factory=list)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Ruleset":
        if not isinstance(data, dict):
            raise RulesetError("ruleset must be an object")
        name = str(data.get("name") or "").strip()
        version = str(data.get("version") or "").strip()
        if not name:
            raise RulesetError("ruleset.name is required")
        if not re.match(r"^\d+\.\d+\.\d+$", version):
            raise RulesetError("ruleset.version must be semver X.Y.Z")
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            raise RulesetError("ruleset.rules must be a list")
        rules = [Rule.from_dict(r) for r in raw_rules]
        ids = [r.id for r in rules]
        if len(set(ids)) != len(ids):
            raise RulesetError("duplicate rule id in ruleset")
        return Ruleset(name=name, version=version, rules=rules)


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    decision: str
    message: str
    remediation: str
    algorithm: str | None


class RulesetEngine:
    def __init__(self, ruleset: Ruleset):
        self.ruleset = ruleset
        self._compiled_globs: dict[str, re.Pattern] = {}
        for rule in ruleset.rules:
            if rule.path_glob:
                self._compiled_globs[rule.id] = _glob_to_re(rule.path_glob)

    def evaluate(self, finding: dict[str, Any]) -> list[RuleMatch]:
        """Return all rules the finding matches (FAIL/WARN/PASS)."""
        algo = _canon_algo(finding.get("algorithm") or finding.get("normalized_algorithm"))
        key_size = _safe_int(finding.get("key_size"))
        status = str(finding.get("status") or "").upper()
        hardcoded = finding.get("is_hardcoded_key")
        path = str(finding.get("file_path") or finding.get("path") or "")
        line = _safe_int(finding.get("line_number"))
        confidence = str(finding.get("confidence") or "").upper()

        matches: list[RuleMatch] = []
        for rule in self.ruleset.rules:
            if rule.algorithm and rule.algorithm != algo:
                continue
            if rule.min_key_size is not None and (key_size is None or key_size < rule.min_key_size):
                continue
            if rule.max_key_size is not None and (key_size is None or key_size > rule.max_key_size):
                continue
            if rule.status_in and status not in rule.status_in:
                continue
            if rule.is_hardcoded_key is not None and bool(hardcoded) != rule.is_hardcoded_key:
                continue
            if rule.path_glob is not None:
                if not self._compiled_globs[rule.id].match(path):
                    continue
            if rule.line_min is not None and (line is None or line < rule.line_min):
                continue
            if rule.line_max is not None and (line is None or line > rule.line_max):
                continue
            if rule.confidence_min is not None:
                if CONFIDENCE_ORDER.get(confidence, -1) < CONFIDENCE_ORDER[rule.confidence_min]:
                    continue
            matches.append(RuleMatch(
                rule_id=rule.id, decision=rule.decision,
                message=rule.message, remediation=rule.remediation,
                algorithm=rule.algorithm,
            ))
        return matches

    def evaluate_many(self, findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
        """Evaluate a batch; summarize FAIL/WARN counts and per-finding results."""
        results: list[dict] = []
        fail = warn = 0
        for f in findings:
            ms = self.evaluate(f)
            decisions = {m.decision for m in ms}
            if "FAIL" in decisions:
                fail += 1
            elif "WARN" in decisions:
                warn += 1
            results.append({
                "finding": f.get("file_path") or f.get("id") or "?",
                "line": f.get("line_number"),
                "matches": [m.__dict__ for m in ms],
                "gated": "FAIL" in decisions,
            })
        return {
            "ruleset": self.ruleset.name,
            "version": self.ruleset.version,
            "rules_evaluated": len(self.ruleset.rules),
            "findings_evaluated": len(results),
            "fail_count": fail,
            "warn_count": warn,
            "gate": "FAIL" if fail else ("WARN" if warn else "PASS"),
            "results": results,
        }


def _safe_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
