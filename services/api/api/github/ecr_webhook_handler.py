"""AWS ECR push-event adapter for the API webhook layer."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.ecr_handler import parse_ecr_event


def handle_ecr_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    return parse_ecr_event(payload)
