"""Normalize SQL / API rows into MERGE batches."""

from __future__ import annotations

from typing import Any, Iterable


def _sid(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("system_id") or item.get("name") or "")


def _aid(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("asset_id") or "")


def _tenant(item: dict[str, Any]) -> dict[str, Any]:
    """Round 35: the tenant stamp must survive normalization.

    store.sync stamps every input row before the builders run; builders
    build fresh dicts, so they re-attach the stamp explicitly. A missing
    stamp would drop a node out of its tenant partition (and, on a
    platform sync, into the legacy-cleanup prune set).
    """
    tenant = item.get("tenant_id")
    return {"tenant_id": tenant} if tenant else {}


def systems_rows(systems: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for system in systems:
        sid = _sid(system)
        if not sid:
            continue
        extra = system.get("extra") or {}
        rows.append(
            {
                "system_id": sid,
                "name": system.get("name"),
                "environment": system.get("environment"),
                "criticality": system.get("criticality") or extra.get("criticality"),
                "owner": system.get("owner"),
                "compliance_scopes": list(system.get("compliance_scopes") or []),
                **_tenant(system),
            }
        )
    return rows


def asset_rows(assets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for asset in assets:
        aid = _aid(asset)
        if not aid:
            continue
        rows.append(
            {
                "asset_id": aid,
                "algorithm": asset.get("algorithm"),
                "key_size": asset.get("key_size"),
                "purpose": asset.get("purpose"),
                "confidence": asset.get("confidence"),
                "file_path": asset.get("file_path"),
                "system_id": asset.get("system_id"),
                **_tenant(asset),
            }
        )
    return rows


def uses_rows(assets: Iterable[dict[str, Any]], systems: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    by_asset: dict[str, str] = {}
    for system in systems:
        sid = _sid(system)
        for asset_id in system.get("asset_ids") or []:
            by_asset[str(asset_id)] = sid
    for asset in asset_rows(assets):
        system_id = asset.get("system_id") or by_asset.get(asset["asset_id"])
        if system_id:
            rows.append({"system_id": str(system_id), "asset_id": asset["asset_id"], "usage_type": "DISCOVERED", **_tenant(asset)})
    return rows


def call_rows(edges: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for edge in edges:
        parent = edge.get("parent_id") or edge.get("from") or edge.get("source")
        child = edge.get("child_id") or edge.get("to") or edge.get("destination")
        if parent and child:
            rows.append(
                {
                    "parent_id": str(parent),
                    "child_id": str(child),
                    "protocol": edge.get("protocol") or edge.get("relation") or "CALLS",
                    "frequency": edge.get("frequency"),
                    **_tenant(edge),
                }
            )
    return rows


def process_rows(processes: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes, edges = [], []
    for process in processes:
        pid = str(process.get("id") or process.get("process_id") or process.get("name") or "")
        if not pid:
            continue
        nodes.append(
            {
                "process_id": pid,
                "name": process.get("name") or process.get("process_name"),
                "revenue_daily": float(process.get("revenue_daily") or 0),
                "customer_count": int(process.get("customer_count") or 0),
                **_tenant(process),
            }
        )
        for system_id in process.get("system_ids") or []:
            edges.append({"system_id": str(system_id), "process_id": pid, **_tenant(process)})
    return nodes, edges


def owner_rows(owners: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes, edges = [], []
    for owner in owners:
        oid = str(owner.get("id") or owner.get("email") or owner.get("name") or "")
        if not oid:
            continue
        nodes.append(
            {
                "owner_id": oid,
                "name": owner.get("name"),
                "email": owner.get("email"),
                "role": owner.get("role"),
                **_tenant(owner),
            }
        )
        for system_id in owner.get("system_ids") or []:
            edges.append({"system_id": str(system_id), "owner_id": oid, **_tenant(owner)})
    return nodes, edges


def scope_rows(systems: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges = []
    for system in systems:
        sid = _sid(system)
        for scope in system.get("compliance_scopes") or []:
            name = str(scope)
            nodes[name] = {"standard_name": name, "version": None, **_tenant(system)}
            if sid:
                edges.append({"system_id": sid, "standard_name": name, **_tenant(system)})
    return list(nodes.values()), edges


def vendor_rows(vendors: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes, edges = [], []
    for vendor in vendors:
        vid = str(vendor.get("id") or vendor.get("vendor_id") or vendor.get("name") or "")
        if not vid:
            continue
        nodes.append({"vendor_id": vid, "name": vendor.get("name"), "criticality": vendor.get("criticality"), **_tenant(vendor)})
        for system_id in vendor.get("system_ids") or []:
            edges.append(
                {
                    "system_id": str(system_id),
                    "vendor_id": vid,
                    "dependency_type": vendor.get("dependency_type"),
                    **_tenant(vendor),
                }
            )
    return nodes, edges


def cert_rows(certificates: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes, edges = [], []
    for cert in certificates:
        cid = str(cert.get("id") or cert.get("fingerprint_sha256") or cert.get("cert_id") or cert.get("subject") or "")
        if not cid:
            continue
        nodes.append(
            {
                "cert_id": cid,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_after": cert.get("not_after"),
                "expiry_status": cert.get("expiry_status"),
                **_tenant(cert),
            }
        )
        for system_id in cert.get("system_ids") or []:
            edges.append({"system_id": str(system_id), "cert_id": cid, "endpoint": cert.get("endpoint"), **_tenant(cert)})
    return nodes, edges


def cloud_rows(resources: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes, edges = [], []
    for resource in resources:
        rid = str(resource.get("id") or resource.get("resource_id") or resource.get("account_identifier") or "")
        if not rid:
            continue
        nodes.append(
            {
                "resource_id": rid,
                "cloud_provider": resource.get("cloud_provider") or resource.get("provider"),
                "resource_type": resource.get("resource_type") or "ACCOUNT",
                "name": resource.get("name") or resource.get("account_identifier"),
                **_tenant(resource),
            }
        )
        for system_id in resource.get("system_ids") or []:
            edges.append({"system_id": str(system_id), "resource_id": rid, **_tenant(resource)})
    return nodes, edges


def network_rows(resources: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """NetworkResource nodes (mirrors the memory engine's network: plane)."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for resource in resources or []:
        rid = str(resource.get("id") or resource.get("endpoint") or resource.get("resource_id") or "")
        if not rid:
            continue
        nodes.append(
            {
                "network_id": rid,
                "name": resource.get("name") or resource.get("endpoint"),
                "endpoint": resource.get("endpoint"),
                "resource_type": resource.get("resource_type") or "TLS_ENDPOINT",
                **_tenant(resource),
            }
        )
        for system_id in resource.get("system_ids") or []:
            edges.append({"system_id": str(system_id), "network_id": rid, **_tenant(resource)})
    return nodes, edges


def container_rows(images: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """ContainerImage nodes (report 03's container->graph gap, round 21)."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for image in images or []:
        cid = str(image.get("id") or image.get("target") or "")
        if not cid:
            continue
        nodes.append(
            {
                "container_id": cid,
                "name": image.get("name") or image.get("target"),
                "image": image.get("image") or image.get("target"),
                "package_count": image.get("package_count"),
                "library_count": image.get("library_count"),
                "vuln_count": image.get("vuln_count"),
                **_tenant(image),
            }
        )
        for system_id in image.get("system_ids") or []:
            edges.append({"system_id": str(system_id), "container_id": cid, **_tenant(image)})
    return nodes, edges
