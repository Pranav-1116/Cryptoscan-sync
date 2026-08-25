"""Attach system mappings from cloud resource tags / names."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SYSTEM_TAG_KEYS = (
    "cryptoscan:system",
    "cryptoscan_system",
    "system",
    "System",
    "Name",
    "name",
)


def _as_tags(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(val) for key, val in value.items() if val is not None}
    if isinstance(value, list):
        tags: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict):
                key = item.get("Key") or item.get("key") or item.get("TagKey")
                val = item.get("Value") or item.get("value") or item.get("TagValue")
                if key is not None and val is not None:
                    tags[str(key)] = str(val)
        return tags
    return {}


def extract_tags(finding: Mapping[str, Any]) -> dict[str, str]:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    merged: dict[str, str] = {}
    for candidate in (finding.get("tags"), extra.get("tags"), metadata.get("tags")):
        merged.update(_as_tags(candidate))
    return merged


class ResourceTagger:
    def __init__(self, systems: Iterable[Mapping[str, Any]] | None = None) -> None:
        rows = list(systems or [])
        self.systems_by_id = {str(item.get("id")): item for item in rows if item.get("id")}
        self.systems_by_name = {str(item.get("name") or "").lower(): item for item in rows if item.get("name")}

    def apply(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(finding)
        extra = dict(payload.get("extra") or {})
        metadata = dict(payload.get("metadata") or {})
        tags = extract_tags(payload)
        match = None
        for key in SYSTEM_TAG_KEYS:
            raw = tags.get(key)
            if not raw:
                continue
            match = self.systems_by_id.get(raw) or self.systems_by_name.get(raw.lower())
            if match:
                break
        if match is None:
            resource = str(metadata.get("resource") or payload.get("resource") or payload.get("file_path") or "")
            for name, system in self.systems_by_name.items():
                if name and name in resource.lower():
                    match = system
                    break
        if match is not None:
            payload["system_id"] = match.get("id")
            extra["system_id"] = match.get("id")
            extra["system_name"] = match.get("name")
            metadata["system_id"] = match.get("id")
        extra["tags"] = tags
        payload["extra"] = extra
        if payload.get("metadata") is not None or metadata:
            payload["metadata"] = metadata
        return payload

    def apply_all(self, findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [self.apply(item) for item in findings]


def tag_resources(
    findings: Iterable[Mapping[str, Any]],
    systems: Iterable[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    return ResourceTagger(systems).apply_all(findings)
