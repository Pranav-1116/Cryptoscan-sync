"""Build CycloneDX ``dependencies[]`` from CBOM components and estate links.

Two sources of truth, two builders:

* :func:`build_dependencies` — the generic fallback: a root that depends on
  every component. Used when no estate linkage exists for the BOM's scope.
* :func:`build_estate_dependencies` — real edges for a system's CBOM: the
  system depends on the crypto assets registered to it (``SystemAsset``),
  plus its registered inter-system edges (``SystemDependency``), in both
  directions, so a system BOM answers "what breaks if this system changes"
  with the graph, not a fan-out guess.

Refs prefixed ``system:`` point at systems outside this BOM's component set
on purpose — CycloneDX ``dependsOn`` may reference external components, and
naming the caller is the point of a dependency edge.
"""

from __future__ import annotations

from typing import Any, Mapping


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


def build_estate_dependencies(
    system_id: str,
    asset_ids: list[str] | None,
    system_edges: list[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Real dependency edges for one system's CBOM.

    ``system_edges`` are ``{"parent": ..., "child": ..., "relation": ...}``
    rows (``SystemDependency``), already filtered to edges touching this
    system — the caller owns the query, this function owns the shape.
    """
    depends: dict[str, set[str]] = {}
    system_ref = f"system:{system_id}"
    depends[system_ref] = {str(a) for a in (asset_ids or []) if a}
    for edge in system_edges or []:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        if not parent or not child:
            continue
        # this system depends on that one (registered, not inferred)
        if parent == str(system_id):
            depends.setdefault(system_ref, set()).add(f"system:{child}")
        # that one depends on this system — keep the direction true
        elif child == str(system_id):
            depends.setdefault(f"system:{parent}", set()).add(system_ref)
    if not depends.get(system_ref):
        depends.pop(system_ref, None)
    return [{"ref": ref, "dependsOn": sorted(targets)}
            for ref, targets in sorted(depends.items())]


def infer_library_edges(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Naming-convention asset→library edges (best effort, no registry).

    Only a fallback for estates without ``CryptoLibraryFingerprint`` data:
    refs are the components' own bom-refs, and the library side is prefixed
    ``library:`` because library components are not part of the asset BOM.
    """
    edges: list[dict[str, Any]] = []
    for asset in assets:
        library = asset.get("library") or asset.get("vendor")
        ref = asset.get("id") or asset.get("bom-ref") or asset.get("asset_id")
        if library and ref:
            edges.append({"ref": str(ref), "dependsOn": [f"library:{library}"]})
    return edges
