"""Normalize container-registry webhook payloads into a scan request."""

from __future__ import annotations

from typing import Any


def _first(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, dict):
            continue
        text = str(value or "").strip()
        if text:
            return text
    return None


def parse_registry_event(payload: dict[str, Any] | None, *, source: str = "generic") -> dict[str, Any]:
    body = payload or {}
    detail = body.get("detail") if isinstance(body.get("detail"), dict) else {}
    repository = body.get("repository") if isinstance(body.get("repository"), dict) else {}
    target = body.get("target") if isinstance(body.get("target"), dict) else {}
    event_data = body.get("event_data") if isinstance(body.get("event_data"), dict) else {}
    resources = body.get("resources") if isinstance(body.get("resources"), list) else []
    first_resource = resources[0] if resources and isinstance(resources[0], dict) else {}

    image = _first(
        body.get("image"),
        body.get("repository"),
        repository.get("repo_name"),
        repository.get("repoName"),
        repository.get("name"),
        detail.get("repository-name"),
        detail.get("repositoryName"),
        event_data.get("repository"),
        first_resource.get("resource_url"),
    )
    tag = _first(
        body.get("tag"),
        body.get("digest"),
        target.get("tag"),
        target.get("digest"),
        detail.get("image-tag"),
        detail.get("imageTag"),
        event_data.get("tag"),
        first_resource.get("tag"),
    )
    digest = _first(
        body.get("digest"),
        target.get("digest"),
        detail.get("image-digest"),
        first_resource.get("digest"),
    )
    path = _first(body.get("path"), body.get("image_root"), body.get("root"))
    archive = _first(body.get("archive"), body.get("tar"), body.get("tarball"))
    reference = image
    if image and tag and ":" not in str(image) and "@" not in str(image):
        reference = f"{image}:{tag}"
    return {
        "source": source,
        "accepted": True,
        "image": image,
        "tag": tag,
        "digest": digest,
        "reference": reference,
        "path": path,
        "archive": archive,
        "action": _first(body.get("action"), body.get("eventName"), "push"),
        "scan_requested": bool(path or archive or reference),
    }
