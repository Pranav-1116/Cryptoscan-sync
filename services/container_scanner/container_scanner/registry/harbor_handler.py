"""Harbor project webhook payloads."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.registry_webhook_handler import parse_registry_event


def parse_harbor_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    event_data = body.get("event_data") if isinstance(body.get("event_data"), dict) else {}
    resources = event_data.get("resources") if isinstance(event_data.get("resources"), list) else []
    repo = event_data.get("repository") if isinstance(event_data.get("repository"), dict) else {}
    first = resources[0] if resources and isinstance(resources[0], dict) else {}
    if first.get("resource_url"):
        body["image"] = first.get("resource_url")
    elif repo.get("repo_full_name") or repo.get("name"):
        body["image"] = repo.get("repo_full_name") or repo.get("name")
    body["tag"] = first.get("tag") or body.get("tag")
    body["digest"] = first.get("digest") or body.get("digest")
    event = parse_registry_event(body, source="harbor")
    event["registry"] = "harbor"
    event["event_type"] = body.get("type")
    return event
