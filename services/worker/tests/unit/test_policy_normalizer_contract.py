"""Cross-service contract: every algorithm a policy rule names must still match after normalisation.

The SNB-profile end-to-end run (2026-09-26) found that the normaliser writes the *display* name ``TLS 1.0`` while the
rule lists say ``TLS1.0`` — so BASELINE-005 / CBUAE-003 / PCIDSS-005 PASSed every weak-TLS endpoint. Neither
service's own suite could see it: the normaliser was right, the rule was right, only the join was wrong.

This test lives in the worker because the worker is the join: it builds the evidence payload exactly as
``stage_normalize`` + ``stage_policy`` do, for every algorithm spelled in every rule, and asserts the rule fires.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from normalization.core.engine import NormalizationEngine
from policy.conditions.condition_factory import ConditionFactory
from policy.core.engine import PolicyEngine

ROOT = Path(__file__).resolve().parents[4]
POLICY_RULES = ROOT / "services" / "policy" / "rule_definitions"
NORMALIZATION_RULES = ROOT / "services" / "normalization" / "rule_definitions"

ALGORITHM_CONDITIONS = {"ALGORITHM_IN_LIST": "algorithm_list", "KEY_SIZE_MINIMUM": "algorithm", "ALGORITHM_MODE_WHITELIST": "algorithm",
                        "COMPLEX": "forbidden_algorithms"}


def _clauses(condition: dict) -> list[dict]:
    """Flatten COMPLEX conditions to their leaf clauses."""
    ctype = str(condition.get("type") or "")
    params = condition.get("parameters") or {}
    if ctype == "COMPLEX" and (params.get("clauses") or params.get("conditions")):
        out = []
        for clause in params.get("clauses") or params.get("conditions") or []:
            out.extend(_clauses({"type": clause.get("type") or clause.get("condition_type"), "parameters": clause.get("parameters") or clause}))
        return out
    return [{"type": ctype, "parameters": params}]


def _cases() -> list[tuple[str, str, dict, str]]:
    engine = PolicyEngine(str(POLICY_RULES))
    cases = []
    for rule in engine.rule_set.rules:
        for clause in _clauses(rule.condition.model_dump()):
            key = ALGORITHM_CONDITIONS.get(clause["type"])
            if not key:
                continue
            names = clause["parameters"].get(key)
            for name in (names if isinstance(names, list) else [names]):
                if name:
                    cases.append((rule.rule_id, clause["type"], clause["parameters"], str(name)))
    return cases


CASES = _cases()


@pytest.fixture(scope="module")
def normalizer() -> NormalizationEngine:
    return NormalizationEngine(str(NORMALIZATION_RULES))


def _evidence(normalizer: NormalizationEngine, raw: str, *, key_size: int | None = None, mode: str | None = None) -> dict:
    """The payload stage_policy builds from an EvidenceRecord after stage_normalize ran."""
    normalized = normalizer.normalize(raw, {"key_size": key_size, "mode": mode})
    algorithm = normalized.algorithm if normalized.algorithm and normalized.algorithm != "UNKNOWN" else raw
    return {
        "algorithm": algorithm,
        "key_size": normalized.key_size or key_size,
        "mode": normalized.mode or mode,
        "normalized_crypto": normalized.model_dump(mode="json"),
        "finding_data": {"crypto": {"algorithm": raw}},
    }


def test_contract_has_rules_to_check():
    assert len(CASES) >= 40, CASES


@pytest.mark.parametrize("rule_id,ctype,params,name", CASES, ids=[f"{r}:{n}" for r, _, _, n in CASES])
def test_rule_algorithm_still_matches_after_normalisation(normalizer, rule_id, ctype, params, name):
    condition = ConditionFactory().create(ctype)
    if ctype in ("ALGORITHM_IN_LIST", "COMPLEX"):
        evidence = _evidence(normalizer, name)
        evidence["compliance_scopes"] = list(params.get("required_scopes") or [])
        evidence["purpose"] = (params.get("if_purpose") or [None])[0] if isinstance(params.get("if_purpose"), list) else params.get("if_purpose")
        outcome = condition.evaluate(evidence, params)
        assert outcome.result == "FAIL", (rule_id, name, outcome)
    elif ctype == "KEY_SIZE_MINIMUM":
        # a key far below any floor must be judged, not skipped as "rule applies only to X"
        outcome = condition.evaluate(_evidence(normalizer, name, key_size=8), params)
        assert outcome.result != "NOT_APPLICABLE", (rule_id, name, outcome)
    else:  # ALGORITHM_MODE_WHITELIST — a forbidden mode must be judged
        forbidden = (params.get("forbidden_modes") or ["ECB"])[0]
        outcome = condition.evaluate(_evidence(normalizer, name, mode=forbidden), params)
        assert outcome.result != "NOT_APPLICABLE", (rule_id, name, outcome)


@pytest.mark.parametrize("raw", ["TLSv1", "TLS 1.0", "TLSv1.0", "SSLv3", "TLS1.1", "RC4", "ARCFOUR", "DESede", "TripleDES", "MD5", "SHA1", "SHA-1"])
def test_common_scanner_spellings_of_forbidden_algorithms_fail_baseline(normalizer, raw):
    """Names the scanners actually emit must fail BASELINE-001/005 once normalised."""
    engine = PolicyEngine(str(POLICY_RULES))
    evaluation = engine.evaluate({"id": "x", "evidence_id": "x", **_evidence(normalizer, raw), "compliance_scopes": []})
    failed = {r.rule_id for r in evaluation.rules_evaluated if r.evaluation_result == "FAIL"}
    assert failed & {"BASELINE-001", "BASELINE-005", "FIPS140-003", "NIST131A-002"}, (raw, evaluation.overall_status, [(r.rule_id, r.evaluation_result, r.message) for r in evaluation.rules_evaluated][:6])
