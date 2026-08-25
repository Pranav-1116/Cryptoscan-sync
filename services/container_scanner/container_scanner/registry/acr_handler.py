"""Azure Container Registry webhook payloads."""

from __future__ import annotations

from typing import Any

from container_scanner.registry.registry_webhook_handler import parse_registry_event


def parse_acr_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    target = body.get("target") if isinstance(body.get("target"), dict) else {}
    request = body.get("request") if isinstance(body.get("request"), dict) else {}
    if target.get("repository") and not body.get("image"):
        host = request.get("host") or body.get("host")
        repo = target.get("repository")
        body["image"] = f"{host}/{repo}" if host else repo
        body["tag"] = target.get("tag") or body.get("tag")
        body["digest"] = target.get("digest")
    event = parse_registry_event(body, source="acr")
    event["registry"] = "acr"
    return event
