"""Build the CBOM generation context (system vs scan vs custom selection)."""

from __future__ import annotations

from typing import Any


def build_context(
    *,
    name: str = "cryptoscan-target",
    version: str = "unknown",
    kind: str = "scan",
    identifier: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "name": name,
        "version": version,
        "kind": kind,
        "identifier": identifier,
    }
    if extra:
        payload.update(extra)
    return payload
