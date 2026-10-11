"""Field-level audit diffs (audit 78, P0 #1).

Every audited data mutation should record *what changed*, field by field,
not just that something happened. This module renders before/after diffs in
a single canonical shape that the audit trail can carry inside its existing
``detail`` JSON column::

    {"changes": [
        {"field": "roles", "before": ["viewer"], "after": ["auditor", "viewer"]},
        {"field": "is_active", "before": true, "after": false},
        {"field": "password", "before": "***", "after": "***"},
    ]}

Rules, deliberately boring:

* only fields whose value actually changed are listed;
* sensitive fields (passwords, secrets, tokens) are masked with ``"***"`` —
  the fact that they changed is auditable, their value never is;
* values are JSON-serialisable as-is (the repository already ``json.dumps``
  the detail with ``default=str``);
* ``unchanged=True`` fields can be omitted entirely — the diff lists changes,
  not a snapshot.
"""

from __future__ import annotations

from collections.abc import Container, Mapping
from typing import Any

MASK = "***"

#: Field names that must never carry a value into the audit log.
DEFAULT_SENSITIVE_FIELDS = frozenset({
    "password", "password_hash", "secret", "token", "api_key", "private_key",
})


def _mask(field: str, value: Any, sensitive: Container[str]) -> Any:
    if field.lower() in {s.lower() for s in sensitive}:
        return MASK if value is not None else None
    return value


def field_diff(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    sensitive: Container[str] = DEFAULT_SENSITIVE_FIELDS,
) -> list[dict[str, Any]]:
    """Render the changed fields between two snapshots as a diff list.

    A field appears when it is present in either snapshot AND the values
    differ (missing -> None). Sensitive fields are masked on both sides.
    """
    changed: list[dict[str, Any]] = []
    for field in sorted(set(before) | set(after)):
        old = before.get(field)
        new = after.get(field)
        if old != new or (field not in before) or (field not in after):
            changed.append({
                "field": field,
                "before": _mask(field, old, sensitive),
                "after": _mask(field, new, sensitive),
            })
    return changed


def audit_detail_with_changes(
    changes: list[dict[str, Any]],
    **extra: Any,
) -> dict[str, Any]:
    """Wrap a diff list into an audit ``detail`` payload.

    The ``summary`` key carries the changed-field names so audit readers can
    filter without walking the whole diff.
    """
    detail: dict[str, Any] = {
        "changes": changes,
        "summary": sorted(c["field"] for c in changes),
    }
    detail.update(extra)
    return detail
