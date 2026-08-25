"""Build CycloneDX `evidence.identity` from an evidence / asset record."""

from __future__ import annotations

from typing import Any

from cbom.generator import CbomGenerator
from cbom.mappers.confidence_float_mapper import confidence_to_float


def build_evidence(record: Any) -> dict[str, Any]:
    component = CbomGenerator()._component(record)
    return component.get("evidence") or {}


def build_detection_methods(asset: dict[str, Any]) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    for source in asset.get("detection_sources") or asset.get("scanner_ids") or []:
        if isinstance(source, dict):
            scanner = str(source.get("scanner_id") or "unknown")
            conf = source.get("confidence")
        else:
            scanner = str(source)
            conf = asset.get("confidence")
        technique = "source-code-analysis"
        lower = scanner.lower()
        if "container" in lower or "binary" in lower or "jar" in lower:
            technique = "binary-analysis"
        methods.append(
            {
                "technique": technique,
                "confidence": confidence_to_float(conf),
                "value": scanner,
            }
        )
    return methods


def build_occurrences(asset: dict[str, Any]) -> list[dict[str, Any]]:
    occurrences: list[dict[str, Any]] = []
    for location in asset.get("locations") or []:
        if isinstance(location, dict):
            occurrences.append(
                {
                    "location": location.get("file_path")
                    or location.get("location")
                    or location.get("container_image")
                    or location.get("path")
                }
            )
        elif location:
            occurrences.append({"location": str(location)})
    if not occurrences and (asset.get("file_path") or asset.get("location")):
        occurrences.append({"location": asset.get("file_path") or asset.get("location")})
    return occurrences
