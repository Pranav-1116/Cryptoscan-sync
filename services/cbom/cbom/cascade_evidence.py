"""Witnesses for existing cascade membership; never widen modeled exposure."""

from shared_models.traversal_evidence import (
    SCHEMA,
    MAX_WITNESSES,
    canonical_dependencies,
    envelope,
    path_evidence,
    walk_paths,
    provenance,
    timestamp,
)
from shared_models.relationship_lifecycle import current, possible


def _seed(snapshot, sid, kind, matched, layers, *, now, potential=False):
    software = layers.get("software") or {}
    if kind in {"package", "artifact"}:
        artifacts = {a["id"]: a for a in software.get("artifacts") or []}
        valid = possible if potential else current
        for deployment in sorted(software.get("deployments") or [], key=lambda d: d["id"]):
            if deployment.get("system_id") != sid or not valid(deployment, now=now):
                continue
            aid = deployment["artifact_id"]
            binding = next(
                (
                    b
                    for b in sorted(software.get("sbom_bindings") or [], key=lambda b: b["id"])
                    if b.get("artifact_id") == aid and valid(b, now=now)
                ),
                None,
            )
            if kind == "package" and binding is None:
                continue
            artifact = artifacts.get(aid) or {}
            identity = {
                "digest": artifact.get("digest"),
                "identity_source": artifact.get("identity_source"),
                "artifact_evidence_ref": artifact.get("evidence_ref"),
                "byte_count": artifact.get("byte_count"),
            }
            nodes = ["artifact:" + aid, sid]
            edges = [
                {
                    **deployment,
                    **identity,
                    "from": nodes[0],
                    "to": sid,
                    "label": "DEPLOYMENT_ASSERTION",
                    "provenance": "DECLARED",
                    "source": deployment.get("assertion_source"),
                }
            ]
            if binding:
                binding = {**binding, **identity}
            if kind == "package":
                node = "package:" + str(matched.get("purl"))
                edges.insert(
                    0,
                    {
                        **binding,
                        "from": node,
                        "to": nodes[0],
                        "label": "SBOM_RELEASE_ASSERTION",
                        "provenance": "DECLARED",
                        "source": binding.get("assertion_source"),
                    },
                )
                nodes.insert(0, node)
            return {
                "system_id": sid,
                "kind": kind,
                "basis": "explicit software assertions",
                "path": path_evidence(nodes, edges, now=now, scope="potential" if potential else "current"),
                "record_listing_truncated": False,
            }
    if kind == "system":
        return {
            "system_id": sid,
            "kind": kind,
            "basis": "explicit target selection, not a runtime observation",
            "path": path_evidence([sid], [], now=now),
            "record_listing_truncated": False,
        }
    records = []
    evidence_ids = set((layers.get("code") or {}).get("evidence_ids") or [])
    for row in snapshot.get("evidence") or []:
        if row.get("system_id") == sid and str(row.get("id")) in evidence_ids:
            records.append(
                {
                    "record_type": "evidence_record",
                    **row,
                    "provenance": "SCANNER_DERIVED",
                    "source": "evidence_records",
                    "evidence_ref": "evidence_record:" + str(row["id"]),
                    "note": "Scanner finding, not a measured dependency call.",
                }
            )
    assets = set((layers.get("code") or {}).get("assets") or [])
    if kind in {"algorithm", "library"}:
        assets.update((layers.get("code") or {}).get("matched_asset_ids") or [])
    for row in snapshot.get("system_asset_links") or []:
        if row.get("system_id") == sid and row.get("asset_id") in assets:
            records.append(
                {"record_type": "system_asset_link", **row, "provenance": "UNATTRIBUTED", "source": "system_assets"}
            )
    if kind == "vendor":
        records.extend(
            {"record_type": "system_vendor", **r}
            for r in snapshot.get("system_vendors") or []
            if r.get("system_id") == sid and r.get("vendor_id") == matched.get("id")
        )
    if kind == "device":
        records.extend(
            {"record_type": "crypto_hardware_link", **r}
            for r in snapshot.get("crypto_hardware_links") or []
            if r.get("hardware_asset_id") == matched.get("asset_id") and r.get("asset_id") in assets
        )
    if kind == "certificate":
        records.extend(
            {"record_type": "certificate_usage", **r}
            for r in snapshot.get("certificate_usage_records") or []
            if r.get("fingerprint_sha256") == matched.get("fingerprint_sha256") and r.get("location") == "system:" + sid
        )
    if kind in {"endpoint", "certificate"}:
        endpoints = set((layers.get("network") or {}).get("endpoints") or [])
        records.extend(
            {
                "record_type": "endpoint_context",
                **r,
                "note": "An observed endpoint is not proof its declared system ownership was measured.",
            }
            for r in snapshot.get("network_endpoints") or []
            if r.get("system_id") == sid and f"{r.get('host')}:{r.get('port')}" in endpoints
        )
    if kind == "process":
        records.extend(
            {"record_type": "process_system_link", **r}
            for r in (snapshot.get("business_processes") or {}).get(sid) or []
            if r.get("id") == matched.get("id")
        )
    records = [
        {
            **r,
            "provenance": provenance(r.get("provenance")),
            "record_pointer": {"type": r["record_type"], "id": r.get("relationship_record_id") or r.get("id")},
            "evidence_missing": not bool(r.get("evidence_ref")),
            "references_verified_by_traversal": False,
            "freshness": {
                "observation": timestamp(r.get("observed_at"), now),
                "recorded_at": timestamp(r.get("created_at") or r.get("recorded_at"), now),
                "note": "Record creation is not a runtime observation or confirmation of a dependency.",
            },
        }
        for r in records
    ]
    return {
        "system_id": sid,
        "kind": kind,
        "basis": "existing target adapter's recorded linkage",
        "records": records[:20],
        "record_count": len(records),
        "record_listing_truncated": len(records) > 20,
        "complete_chain_verified": False,
        "note": "Context records are not proof of runtime reachability. Missing/compact legacy linkage is not fabricated into a sourced edge.",
    }


def cascade_evidence(
    snapshot, classification, layers, matched, kind, *, now, depth, uncertain_systems, possible_direct
):
    seeds = set(classification["direct_exposure"]["systems"])
    known = {s["id"] for s in snapshot.get("systems") or []}
    edges = canonical_dependencies(snapshot.get("dependencies") or [])
    consumers = classification["dependent_consumers"]["systems"]
    context = classification["supporting_context"]["systems"]
    upstream = walk_paths(edges, seeds, known=known, now=now, hops=depth, reverse=True, targets=consumers)
    downstream = walk_paths(edges, seeds, known=known, now=now, hops=depth, targets=context)
    potential_up = walk_paths(
        edges,
        seeds | set(possible_direct),
        known=known,
        now=now,
        hops=depth,
        reverse=True,
        potential=True,
        targets=uncertain_systems,
    )
    potential_down = walk_paths(
        edges, seeds | set(possible_direct), known=known, now=now, hops=depth, potential=True, targets=uncertain_systems
    )
    potential = {sid: potential_up.get(sid) or potential_down[sid] for sid in set(potential_up) | set(potential_down)}
    result = {
        "schema": SCHEMA,
        "direct": [_seed(snapshot, s, kind, matched, layers, now=now) for s in sorted(seeds)[:MAX_WITNESSES]],
        "direct_count": len(seeds),
        "direct_truncated": len(seeds) > MAX_WITNESSES,
        "potential_direct": [
            _seed(snapshot, s, kind, matched, layers, now=now, potential=True)
            for s in sorted(possible_direct)[:MAX_WITNESSES]
        ],
        "potential_direct_count": len(possible_direct),
        "potential_direct_truncated": len(possible_direct) > MAX_WITNESSES,
        "dependent_consumers": envelope(upstream, consumers, now=now),
        "supporting_context": envelope(downstream, context, now=now),
        "potential": envelope(potential, uncertain_systems, now=now),
        "note": "Seed context and one witness per reported system; no aggregate confidence or all-paths claim. Process closure is unchanged.",
    }
    if kind == "vendor":
        rows = snapshot.get("vendor_dependencies") or []
        vendor_edges = [
            {
                **r,
                "from": str(r.get("parent")),
                "to": str(r.get("child")),
                "label": r.get("relation") or "SUPPLIER_ASSERTION",
            }
            for r in rows
        ]
        targets = {
            sid for values in (layers["vendor"].get("sub_tier_vendors_by_depth") or {}).values() for sid in values
        }
        # Legacy traversal may name an external vendor absent from the registry;
        # retain the count, but do not invent a witness through an unknown node.
        vendor_known = {str(v["id"]) for v in snapshot.get("vendors") or []}
        paths = walk_paths(
            vendor_edges,
            {str(matched["id"])},
            known=vendor_known,
            now=now,
            hops=3,
            targets=targets,
            system_policy=False,
        )
        result["vendor_subtiers"] = envelope(paths, targets, now=now)
    return result
