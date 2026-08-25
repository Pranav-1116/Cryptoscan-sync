"""Google Artifact Registry / GCR Pub/Sub payloads."""

from __future__ import annotations

import json
from typing import Any

from container_scanner.registry.registry_webhook_handler import parse_registry_event


def parse_gcr_event(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    message = body.get("message") if isinstance(body.get("message"), dict) else {}
    data = message.get("data")
    if isinstance(data, str):
        try:
            import base64

            decoded = base64.b64decode(data + "===").decode("utf-8")
            inner = json.loads(decoded)
            if isinstance(inner, dict):
                body.update(inner)
        except Exception:
            pass
    tag = body.get("tag") or body.get("digest")
    if body.get("action") in {None, "INSERT"} and body.get("tag"):
        body["image"] = body.get("tag")
        if ":" in str(tag):
            body["image"], _, body["tag"] = str(tag).rpartition(":")
    event = parse_registry_event(body, source="gcr")
    event["registry"] = "gcr"
    return event
