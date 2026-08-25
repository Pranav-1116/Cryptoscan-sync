"""Azure Container Registry push-event adapter."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.acr_handler import parse_acr_event


def handle_acr_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    return parse_acr_event(payload)
