"""Connector registry — discover and instantiate connectors by kind/method.

Connectors register themselves via ``@register`` (or a plain class), so the
platform can list what's available and resolve the right connector for a
configured ``Connector`` row without hard-coding dispatchers in routers.
"""

from __future__ import annotations

from typing import Any

from connector_sdk.base import BaseConnector

_REGISTRY: dict[str, type[BaseConnector]] = {}


def register_connector(cls: type[BaseConnector] | None = None, *,
                       kind: str | None = None, method: str | None = None):
    """Class decorator (or direct call) to register a connector class."""
    def _wrap(clazz: type[BaseConnector]) -> type[BaseConnector]:
        k = kind or getattr(clazz, "kind", "other")
        m = method or getattr(clazz, "method", "api")
        _REGISTRY[f"{k}:{m}"] = clazz
        _REGISTRY.setdefault(k, clazz)
        return clazz

    if cls is not None:
        return _wrap(cls)
    return _wrap


def get_connector(kind: str, method: str | None = None, **options: Any) -> BaseConnector:
    if method:
        cls = _REGISTRY.get(f"{kind}:{method}")
        if cls is not None:
            return cls(**options)
    cls = _REGISTRY.get(kind)
    if cls is not None:
        return cls(**options)
    raise KeyError(f"no connector registered for kind={kind!r} method={method!r}")


def available(scope: str | None = None) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for key, cls in _REGISTRY.items():
        if scope and scope not in key:
            continue
        desc = cls().describe()
        ident = (desc["kind"], desc["method"])
        if ident in seen:
            continue
        seen.add(ident)
        out.append(desc)
    out.sort(key=lambda d: (d["kind"], d["method"]))
    return out


__all__ = ["register_connector", "get_connector", "available"]
