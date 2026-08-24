"""Resolve whether a policy rule applies to a finding's compliance scopes."""

from __future__ import annotations

from typing import Any, Iterable


def as_scope_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, Iterable):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]


def evidence_scopes(evidence: dict[str, Any] | None) -> set[str]:
    """Collect scope tags from common finding / asset / system fields."""
    if not evidence:
        return set()
    finding = evidence.get("finding_data") if isinstance(evidence.get("finding_data"), dict) else {}
    extra = evidence.get("extra") if isinstance(evidence.get("extra"), dict) else {}
    raw = (
        evidence.get("compliance_scopes")
        or evidence.get("scopes")
        or finding.get("compliance_scopes")
        or extra.get("compliance_scopes")
        or []
    )
    return {item.upper() for item in as_scope_list(raw)}


def scopes_apply(evidence: dict[str, Any] | None, required_scopes: Any) -> bool:
    """True when the rule has no required scopes or they intersect the finding."""
    required = {item.upper() for item in as_scope_list(required_scopes)}
    if not required:
        return True
    return bool(required & evidence_scopes(evidence))


def missing_scopes_message(required_scopes: Any) -> str:
    required = sorted({item.upper() for item in as_scope_list(required_scopes)})
    return f"Finding is outside required scopes {required}"
