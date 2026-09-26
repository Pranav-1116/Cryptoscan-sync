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


def scope_groups(value: Any) -> list[set[str]]:
    """``required_scope_groups``: a list of any-of groups; every group must be satisfied (CNF)."""
    if not value:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return [{item.upper() for item in as_scope_list(value)}]
    out: list[set[str]] = []
    for group in value:
        items = {item.upper() for item in as_scope_list(group)}
        if items:
            out.append(items)
    return out


def scopes_apply(evidence: dict[str, Any] | None, required_scopes: Any, required_scope_groups: Any = None) -> bool:
    """True when the rule applies to the finding's scopes.

    ``required_scopes`` is any-of (the regulator / jurisdiction tags). ``required_scope_groups`` adds
    all-of-any-of groups for jurisdiction-neutral data classes — e.g. CBUAE-002 = ``[CBUAE]`` **and**
    one of ``[PAYMENT, CARD, SWIFT]`` — so a generic ``PAYMENT`` or ``PERSONAL_DATA`` tag never selects a
    jurisdiction on its own. A rule with neither applies everywhere.
    """
    required = {item.upper() for item in as_scope_list(required_scopes)}
    groups = scope_groups(required_scope_groups)
    if not required and not groups:
        return True
    have = evidence_scopes(evidence)
    if required and not (required & have):
        return False
    return all(group & have for group in groups)


def missing_scopes_message(required_scopes: Any, required_scope_groups: Any = None) -> str:
    required = sorted({item.upper() for item in as_scope_list(required_scopes)})
    groups = [sorted(g) for g in scope_groups(required_scope_groups)]
    if groups:
        return f"Finding is outside required scopes {required} with {groups}"
    return f"Finding is outside required scopes {required}"
