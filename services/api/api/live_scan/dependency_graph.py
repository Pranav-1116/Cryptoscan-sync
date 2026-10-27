"""Evidence-backed dependency and cascade projection for live CBOM data."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


_CHANGEABLE_TYPES = {"algorithm", "library", "package", "key", "certificate", "provider", "parameter", "protocol"}


def _text(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return str(value).strip()


def _node_id(component: dict[str, Any], index: int) -> str:
    """Return a stable identity, preferring the scanner's own identifiers.

    Cascade consumers need the same identity that an explicit dependency uses.
    Falling back to ``type:name:version:index`` made a service named
    ``payments`` appear as ``service:payments::2``; an explicit
    ``depends_on: payments`` then could not resolve it. A display name is a
    valid fallback when no machine reference was supplied, while the builder
    below disambiguates duplicate names deterministically.
    """
    ref = _text(component.get("ref") or component.get("bom-ref") or component.get("id"))
    if ref:
        return ref
    name = _text(component.get("name") or component.get("algorithm") or component.get("protocol"))
    if name:
        return name
    asset = _text(component.get("asset_id") or component.get("asset") or component.get("resource_id"))
    if asset:
        return asset
    kind = _text(component.get("type")) or "component"
    version = _text(component.get("version"))
    return f"{kind}:{version or 'unknown'}:{index}"


def _evidence(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_type": _text(component.get("evidence_type") or component.get("source") or "live_scanner"),
        "evidence_reference": component.get("evidence_reference"),
        "observed_at": component.get("observed_at"),
        "confidence": _text(component.get("confidence")) or None,
    }


def _edge(source: str, target: str, relation: str, component: dict[str, Any]) -> dict[str, Any]:
    return {"from": source, "to": target, "relation": relation, **_evidence(component)}


def build_live_dependency_graph(components: list[dict[str, Any]] | None, *, max_nodes: int = 5000,
                                max_edges: int = 15000) -> dict[str, Any]:
    """Create a bounded live graph and reverse impact reports.

    Relationships are emitted only from explicit scanner metadata or shared
    identifiers already present in a scanner component. No dependency is
    guessed from a display label. Unresolved explicit references remain in the
    report for operator review.
    """
    raw = [item for item in (components or []) if isinstance(item, dict)]
    nodes: list[dict[str, Any]] = []
    node_ids: list[str] = []
    used_node_ids: set[str] = set()
    for index, component in enumerate(raw[:max_nodes]):
        base_id = _node_id(component, index)
        node_id = base_id
        if node_id in used_node_ids:
            version = _text(component.get("version"))
            suffix = version or str(index)
            node_id = f"{base_id}:{suffix}"
            while node_id in used_node_ids:
                node_id = f"{node_id}:{index}"
        used_node_ids.add(node_id)
        node_ids.append(node_id)

    by_ref: dict[str, str] = {}
    by_name: dict[tuple[str, str], str] = {}
    by_any_name: dict[str, str] = {}
    by_asset: defaultdict[str, list[str]] = defaultdict(list)
    for index, component in enumerate(raw[:max_nodes]):
        node_id = node_ids[index]
        kind = _text(component.get("type")) or "component"
        name = _text(component.get("name") or component.get("algorithm") or component.get("protocol")) or "unknown"
        node = {
            "id": node_id,
            "type": kind,
            "name": name,
            "version": component.get("version"),
            "source": component.get("source"),
            "asset_id": component.get("asset_id") or component.get("asset") or component.get("resource_id"),
            "file_path": component.get("file_path"),
            "provider": component.get("provider"),
            "key_id": component.get("key_id") or component.get("key_label"),
            "certificate_id": component.get("certificate_id") or component.get("certificate"),
            **_evidence(component),
        }
        nodes.append(node)
        by_ref[node_id] = node_id
        ref = _text(component.get("ref") or component.get("bom-ref"))
        if ref:
            by_ref[ref] = node_id
        by_name[(kind.lower(), name.lower())] = node_id
        by_any_name[name.lower()] = node_id
        asset = _text(node.get("asset_id"))
        if asset:
            by_asset[asset].append(node_id)

    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add(source: str, target: str, relation: str, component: dict[str, Any]) -> None:
        if not source or not target or source == target or len(edges) >= max_edges:
            return
        key = (source, target, relation)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append(_edge(source, target, relation, component))

    for index, component in enumerate(raw[:max_nodes]):
        source = node_ids[index]
        # Explicit dependency references are authoritative. Resolve by ref,
        # type/name, or an exact component name; otherwise retain an unresolved
        # relationship rather than inventing a node.
        explicit = component.get("depends_on") or component.get("dependsOn") or component.get("dependencies") or []
        if isinstance(explicit, (str, dict)):
            explicit = [explicit]
        for dependency in explicit if isinstance(explicit, list) else []:
            if isinstance(dependency, dict):
                target_ref = _text(dependency.get("ref") or dependency.get("id") or dependency.get("name"))
            else:
                target_ref = _text(dependency)
            target = by_ref.get(target_ref)
            if target is None:
                target = by_name.get(("component", target_ref.lower())) or by_any_name.get(target_ref.lower())
            if target is None:
                unresolved.append({"from": source, "reference": target_ref, **_evidence(component), "reason": "explicit dependency not observed"})
            else:
                add(source, target, "DEPENDS_ON", component)

        # A package/library/algorithm association is only emitted when the
        # scanner supplied the field on the component.
        for field_name, relation, target_kind in (
            ("library", "USES_LIBRARY", "library"),
            ("package", "PROVIDED_BY_PACKAGE", "package"),
            ("algorithm", "USES_ALGORITHM", "algorithm"),
            ("protocol", "USES_PROTOCOL", "protocol"),
            ("key_id", "USES_KEY", "key"),
            ("key_label", "USES_KEY", "key"),
            ("certificate_id", "USES_CERTIFICATE", "certificate"),
        ):
            value = _text(component.get(field_name))
            if not value:
                continue
            target = by_name.get((target_kind, value.lower()))
            if target is not None:
                add(source, target, relation, component)

        asset = _text(component.get("asset_id") or component.get("asset") or component.get("resource_id"))
        if asset and len(by_asset[asset]) > 1:
            # Shared-asset relationships are evidence of co-location, not an
            # assumed call graph. The relation is intentionally explicit.
            for target in by_asset[asset]:
                if target != source:
                    add(source, target, "SHARED_ASSET", component)

    forward: defaultdict[str, list[str]] = defaultdict(list)
    reverse: defaultdict[str, list[str]] = defaultdict(list)
    for edge in edges:
        forward[edge["from"]].append(edge["to"])
        reverse[edge["to"]].append(edge["from"])

    def impact(target: str) -> dict[str, Any]:
        direct = sorted(set(reverse.get(target, [])))
        seen: set[str] = set(direct)
        queue = deque(direct)
        while queue:
            current = queue.popleft()
            for dependent in reverse.get(current, []):
                if dependent not in seen:
                    seen.add(dependent)
                    queue.append(dependent)
        return {
            "changed_node": target,
            "direct_dependents": direct,
            "transitive_dependents": sorted(seen),
            "affected_count": len(seen),
            "migration_rationale": "migrate dependents after compatibility or dual-stack validation; approval and rollback are required",
            "destructive_execution": False,
        }

    change_reports = [impact(node["id"]) for node in nodes if node["type"].lower() in _CHANGEABLE_TYPES]
    truncated = {
        "nodes": max(0, len(raw) - max_nodes),
        "edges": max(0, len(edges) - max_edges),
        "unresolved_relationships": 0,
    }
    return {
        "nodes": nodes,
        "edges": edges,
        "cascade_reports": change_reports,
        "unresolved_relationships": unresolved,
        "truncated": truncated,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "changeable_nodes": len(change_reports),
            "unresolved_relationships": len(unresolved),
        },
        "safety": {
            "automatic_rotation": False,
            "automatic_revocation": False,
            "automatic_certificate_replacement": False,
            "production_change_execution": False,
        },
    }
