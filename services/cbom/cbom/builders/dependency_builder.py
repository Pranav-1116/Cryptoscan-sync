"""Build CycloneDX `dependencies[]` from CBOM components."""

from __future__ import annotations

from typing import Any


def build_dependencies(
    components: list[dict[str, Any]] | None,
    *,
    name: str = "cryptoscan-target",
    extra: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if extra:
        return list(extra)
    refs = [str(item.get("bom-ref")) for item in (components or []) if item.get("bom-ref")]
    if not refs:
        return []
    return [{"ref": name, "dependsOn": refs}]


def infer_library_edges(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for asset in assets:
        library = asset.get("library") or asset.get("vendor")
        ref = asset.get("id") or asset.get("bom-ref") or asset.get("asset_id")
        if library and ref:
            edges.append({"ref": f"crypto-asset-{ref}", "dependsOn": [f"crypto-lib-{library}"]})
    return edges
