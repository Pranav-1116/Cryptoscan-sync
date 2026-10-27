"""Runtime scope and authorization (spec 92 §3).

Runtime instrumentation is more sensitive than reading a file, so the engine is
fail-closed: with no saved scope nothing is accepted, and a batch that falls
outside the approved host/application/process set, the collection window, or the
approved method list is **rejected** — not stored and flagged later. Storing
first and worrying afterwards means unapproved data already sits in the
evidence store.

Data restrictions are enforced as field-level denials: a scope that says
``NO_PLAINTEXT`` causes any plaintext-shaped field to reject the batch.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

#: approved runtime collection methods (§3)
RUNTIME_METHODS = (
    "CRYPTO_API_TRACE",
    "FRAMEWORK_HOOK",
    "PROCESS_TELEMETRY",
    "AUDIT_TELEMETRY",
    "NETWORK_SESSION",
    "BINARY_INSTRUMENTATION",
)

#: data restrictions a bank can attach to a runtime scope
DATA_RESTRICTIONS = (
    "NO_PLAINTEXT",
    "NO_PRIVATE_KEYS",
    "NO_SECRET_KEYS",
    "NO_CUSTOMER_DATA",
    "NO_PAYLOAD",
    "NO_KEY_MATERIAL",
)

#: field-name tokens that violate each restriction
_RESTRICTION_TOKENS: dict[str, tuple[str, ...]] = {
    "NO_PLAINTEXT": ("plaintext", "cleartext", "payload", "message_body", "request_body", "response_body"),
    "NO_PAYLOAD": ("payload", "body", "packet", "pcap", "dump"),
    "NO_PRIVATE_KEYS": ("private_key", "privatekey", "priv_key", "key_pem", "pem"),
    "NO_SECRET_KEYS": ("secret_key", "key_bytes", "key_material", "raw_key", "symmetric_key"),
    "NO_KEY_MATERIAL": ("key_bytes", "key_material", "raw_key", "iv_value", "nonce_value", "salt_value"),
    "NO_CUSTOMER_DATA": ("customer", "account_number", "pan", "card_number", "cvv", "iban"),
}

DEFAULT_DATA_RESTRICTIONS = ("NO_PLAINTEXT", "NO_PRIVATE_KEYS", "NO_SECRET_KEYS", "NO_CUSTOMER_DATA")


class RuntimeScopeViolation(ValueError):
    """Raised when a runtime observation is outside the approved scope."""

    def __init__(self, code: str, reason: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.detail = detail or {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def normalize_runtime_scope(scope: dict[str, Any] | None) -> dict[str, Any]:
    """Validate and normalize an approved runtime scope.

    Unknown methods or restrictions are rejected outright: a typo must not
    silently widen or narrow what the engine may collect.
    """
    scope = dict(scope or {})
    hosts = [str(item).strip() for item in scope.get("hosts") or [] if str(item).strip()]
    applications = [str(item).strip() for item in scope.get("applications") or [] if str(item).strip()]
    processes = [str(item).strip() for item in scope.get("processes") or [] if str(item).strip()]
    methods = [str(item).strip().upper() for item in scope.get("runtime_methods") or [] if str(item).strip()]
    restrictions = [
        str(item).strip().upper() for item in scope.get("data_restrictions") or DEFAULT_DATA_RESTRICTIONS
    ]
    window = scope.get("collection_window") or {}

    unknown_methods = [method for method in methods if method not in RUNTIME_METHODS]
    if unknown_methods:
        raise RuntimeScopeViolation(
            "runtime_method_not_approved",
            f"runtime methods not in the approved list: {', '.join(unknown_methods)}",
            detail={"unknown": unknown_methods, "allowed": list(RUNTIME_METHODS)},
        )
    unknown_restrictions = [item for item in restrictions if item not in DATA_RESTRICTIONS]
    if unknown_restrictions:
        raise RuntimeScopeViolation(
            "runtime_restriction_unknown",
            f"unrecognised data restriction(s): {', '.join(unknown_restrictions)}",
            detail={"unknown": unknown_restrictions, "allowed": list(DATA_RESTRICTIONS)},
        )
    if not hosts:
        raise RuntimeScopeViolation(
            "runtime_scope_incomplete",
            "a runtime scope needs at least one approved host — blanket instrumentation is refused",
        )
    start, end = _parse(window.get("from")), _parse(window.get("to"))
    if window and (start is None or end is None):
        raise RuntimeScopeViolation(
            "runtime_window_invalid",
            "collection_window needs ISO-8601 'from' and 'to' timestamps",
        )
    if start and end and end <= start:
        raise RuntimeScopeViolation("runtime_window_invalid", "collection_window 'to' must be after 'from'")

    return {
        "name": scope.get("name") or scope.get("target") or "runtime-target",
        "hosts": hosts,
        "applications": applications,
        "processes": processes,
        "runtime_methods": methods,
        "data_restrictions": restrictions,
        "collection_window": (
            {"from": start.isoformat(), "to": end.isoformat()} if start and end else None
        ),
        "network_scope": [str(item) for item in scope.get("network_scope") or []],
        "approved_by": scope.get("approved_by"),
        "saved_at": scope.get("saved_at"),
    }


def scope_window_state(scope: dict[str, Any] | None, *, at: datetime | None = None) -> dict[str, Any]:
    """Whether the collection window is open right now."""
    if not scope:
        return {"state": "NOT_CONFIGURED", "open": False, "reason": "no approved runtime scope"}
    window = scope.get("collection_window")
    if not window:
        return {"state": "ALWAYS_OPEN", "open": True, "reason": "scope declared without a collection window"}
    clock = at or _now()
    start, end = _parse(window.get("from")), _parse(window.get("to"))
    if start and clock < start:
        return {"state": "NOT_STARTED", "open": False, "reason": f"collection window opens at {window.get('from')}"}
    if end and clock > end:
        return {"state": "EXPIRED", "open": False, "reason": f"collection window closed at {window.get('to')}"}
    return {"state": "OPEN", "open": True, "reason": "inside the approved collection window"}


def _check_restrictions(observation: dict[str, Any], restrictions: Iterable[str]) -> None:
    for restriction in restrictions:
        tokens = _RESTRICTION_TOKENS.get(restriction, ())
        if not tokens:
            continue
        stack: list[Any] = [observation]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    lowered = str(key).lower()
                    if any(token in lowered for token in tokens):
                        raise RuntimeScopeViolation(
                            "runtime_data_restriction_violated",
                            f"field '{key}' violates {restriction}: runtime events carry parameters, never content",
                            detail={"restriction": restriction, "field": key},
                        )
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)


def check_runtime_scope(
    observation: dict[str, Any],
    scope: dict[str, Any] | None,
    *,
    at: datetime | None = None,
) -> dict[str, Any]:
    """Authorize one observation against the approved runtime scope."""
    if not scope:
        raise RuntimeScopeViolation(
            "runtime_scope_missing",
            "no approved runtime scope — instrumentation is refused until scope is saved",
        )
    normalized = normalize_runtime_scope(scope)
    state = scope_window_state(normalized, at=at)
    if not state["open"]:
        raise RuntimeScopeViolation("runtime_window_closed", state["reason"], detail={"state": state["state"]})

    host = str(observation.get("host") or "").strip()
    if not host:
        raise RuntimeScopeViolation("runtime_host_unknown", "an observation must name its host")
    if host not in normalized["hosts"] and not any(
        host.startswith(candidate) for candidate in normalized["hosts"] if candidate.endswith("*")
    ):
        raise RuntimeScopeViolation(
            "runtime_host_not_approved",
            f"host '{host}' is outside the approved runtime scope",
            detail={"approved": normalized["hosts"]},
        )

    application = str(observation.get("application") or "").strip()
    approved_apps = normalized["applications"]
    if approved_apps and application not in approved_apps:
        raise RuntimeScopeViolation(
            "runtime_application_not_approved",
            f"application '{application or 'unknown'}' is outside the approved runtime scope",
            detail={"approved": approved_apps},
        )

    process = str(observation.get("process") or "").strip()
    approved_processes = normalized["processes"]
    if approved_processes and process not in approved_processes:
        raise RuntimeScopeViolation(
            "runtime_process_not_approved",
            f"process '{process or 'unknown'}' is outside the approved runtime scope",
            detail={"approved": approved_processes},
        )

    method = str(observation.get("runtime_method") or observation.get("method") or "").strip().upper()
    if normalized["runtime_methods"] and method and method not in normalized["runtime_methods"]:
        raise RuntimeScopeViolation(
            "runtime_method_not_approved",
            f"collection method '{method}' is not approved for this scope",
            detail={"approved": normalized["runtime_methods"]},
        )

    _check_restrictions(observation, normalized["data_restrictions"])
    return {
        "decision": "PERMITTED",
        "host": host,
        "application": application or None,
        "process": process or None,
        "method": method or None,
        "window": state,
        "data_restrictions": normalized["data_restrictions"],
        "scope_name": normalized["name"],
        "checked": True,
    }
