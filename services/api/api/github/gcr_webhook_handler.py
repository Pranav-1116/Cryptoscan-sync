"""GCR / Artifact Registry push-event adapter."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.gcr_handler import parse_gcr_event


def handle_gcr_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    return parse_gcr_event(payload)
