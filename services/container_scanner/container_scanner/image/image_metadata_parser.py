"""Parse docker-save `manifest.json` and OCI `index.json` metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_image_metadata(root: str | Path) -> dict[str, Any]:
    unpacked = Path(root)
    manifest_path = unpacked / "manifest.json"
    index_path = unpacked / "index.json"
    if manifest_path.is_file():
        return parse_docker_manifest(manifest_path)
    if index_path.is_file():
        return parse_oci_index(index_path)
    raise FileNotFoundError(f"no manifest.json or index.json under {unpacked}")


def parse_docker_manifest(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    entry = payload[0] if isinstance(payload, list) and payload else (payload if isinstance(payload, dict) else {})
    layers = [str(item) for item in (entry.get("Layers") or [])]
    tags = [str(tag) for tag in (entry.get("RepoTags") or []) if tag]
    return {
        "format": "docker-archive",
        "config": entry.get("Config"),
        "layers": layers,
        "tags": tags,
        "reference": tags[0] if tags else None,
        "raw": entry,
    }


def parse_oci_index(path: str | Path) -> dict[str, Any]:
    index = json.loads(Path(path).read_text(encoding="utf-8"))
    manifests = index.get("manifests") or []
    first = manifests[0] if manifests else {}
    annotations = first.get("annotations") or {}
    digest = str((first.get("digest") or "").split(":", 1)[-1])
    tag = annotations.get("org.opencontainers.image.ref.name")
    return {
        "format": "oci-archive",
        "digest": digest or None,
        "media_type": first.get("mediaType"),
        "tags": [str(tag)] if tag else [],
        "reference": tag,
        "raw": index,
    }


def parse_manifest_json(path: str | Path) -> dict[str, Any]:
    return parse_docker_manifest(path)
