"""Duck-typing helpers so live SDKs and unit-test fakes share one scanner path."""

from __future__ import annotations

from typing import Any


def safe(call, default=None):
    try:
        return call()
    except Exception:
        return default


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def iter_records(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    if hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
        try:
            return list(value)
        except TypeError:
            return [value]
    return [value]


def attr(obj: Any, *names: str, default: Any = None) -> Any:
    if obj is None:
        return default
    for name in names:
        if isinstance(obj, dict) and name in obj and obj[name] is not None:
            return obj[name]
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def named(obj: Any, default: str = "") -> str:
    value = attr(obj, "name", "id", "Name", "Id", default=default)
    if value is None:
        return default
    if hasattr(value, "name") and not isinstance(value, str):
        return str(value.name)
    return str(value)


def resource_group(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    for idx, part in enumerate(parts):
        if part.lower() == "resourcegroups" and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""
