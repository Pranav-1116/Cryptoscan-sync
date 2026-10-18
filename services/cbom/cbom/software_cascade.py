"""Pure explicit release/deployment joins; never infer a system from co-presence."""
from __future__ import annotations

from shared_models.software_identity import SCHEMA, artifact_digest, package_identity


def _same_scope(left, right):
    return (left.get("tenant_id") == right.get("tenant_id")
            and left.get("scope_key") == right.get("scope_key"))


def identify_software(snapshot, target, kind):
    if kind == "package":
        if package_identity(target) is None:
            return None
        if any(c.get("package_identity") == target
               for b in snapshot.get("software_sbom_bindings") or [] for c in b.get("components") or []):
            return {"kind": "package", "matched": {"purl": target}}
    elif kind == "artifact":
        try:
            digest = artifact_digest(target)
        except ValueError:
            digest = None
        for row in snapshot.get("software_artifacts") or []:
            if row.get("id") == target or (digest and row.get("digest") == digest):
                return {"kind": "artifact", "matched": {"id": row.get("id"), "digest": row.get("digest")}}
    return None


def software_context(snapshot, *, purl=None, artifact_id=None, system_id=None):
    artifacts = {a["id"]: a for a in snapshot.get("software_artifacts") or []}
    bindings = [b for b in snapshot.get("software_sbom_bindings") or []
                if b.get("artifact_id") in artifacts and _same_scope(b, artifacts[b["artifact_id"]])]
    deployments = [d for d in snapshot.get("software_deployments") or []
                   if d.get("artifact_id") in artifacts and _same_scope(d, artifacts[d["artifact_id"]])]
    if purl is not None:
        bindings = [b for b in bindings if any(c.get("package_identity") == purl for c in b.get("components") or [])]
        selected_ids = {b["artifact_id"] for b in bindings}
    elif artifact_id is not None:
        selected_ids = {artifact_id} & artifacts.keys()
    else:
        selected_ids = {d["artifact_id"] for d in deployments if d.get("system_id") == system_id}
    bindings = [b for b in bindings if b["artifact_id"] in selected_ids]
    deployments = [d for d in deployments if d["artifact_id"] in selected_ids
                   and (system_id is None or d.get("system_id") == system_id)]
    known = {s["id"]: s for s in snapshot.get("systems") or []}
    linked = [d for d in deployments if d.get("system_id") in known and
              (not known[d["system_id"]].get("environment") or
               known[d["system_id"]]["environment"] == d.get("environment"))]
    linked_ids = {d["id"] for d in linked}
    selected = [artifacts[identifier] for identifier in sorted(selected_ids)]
    return {
        "schema": SCHEMA,
        "artifacts": selected,
        "sbom_bindings": [{k: v for k, v in b.items() if k != "components"} for b in bindings],
        "packages": [{**c, "sbom_binding_id": b["id"], "artifact_id": b["artifact_id"]}
                     for b in bindings for c in b.get("components") or []
                     if purl is None or c.get("package_identity") == purl],
        "deployments": deployments,
        "systems": sorted({d["system_id"] for d in linked}),
        "unlinked_deployment_ids": sorted(d["id"] for d in deployments if d["id"] not in linked_ids),
        "unbound_artifact_ids": sorted(selected_ids - {d["artifact_id"] for d in linked}),
        "coverage": snapshot.get("software_supply_chain_coverage"),
        "deployment_evidence": "explicit declarations; not independently observed running deployments",
    }
