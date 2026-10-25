"""Verified layer/package-record projection over stored originals only."""

import json
import uuid
from shared_models.host_collection import digest


def props(value):
    return [
        {
            "name": "cryptoscan:" + k,
            "value": v if isinstance(v, str) else json.dumps(v, sort_keys=True, separators=(",", ":")),
        }
        for k, v in sorted(value.items())
    ]


def container_sbom(snapshot, records, approval_id):
    grouped, failures, runtime = {}, [], []
    inputs = {i.input_id: i.kind for i in snapshot.manifest.inputs}
    for receipt in snapshot.receipts:
        kind = inputs[receipt.input_id]
        if kind not in {"OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"}:
            continue
        if receipt.status != "PARSED":
            failures.append({"input_id": receipt.input_id, "status": receipt.status, "reason": receipt.reason})
            continue
        proofs = sorted(
            r.id for r in records if r.finding_data.get("host_evidence", {}).get("input_id") == receipt.input_id
        )
        if not proofs:
            raise ValueError("Retained receipt evidence required")
        fact = receipt.facts[0]
        source = {"input_id": receipt.input_id, "evidence_ids": proofs, "selected_sha256": receipt.content_sha256}
        if kind == "OCI_RUNTIME_PROCESS":
            runtime.append(
                {
                    **source,
                    "container_id": fact.container_id,
                    "runtime": fact.runtime,
                    "process_identity": fact.process.identity_key,
                    "cgroup_sha256": fact.cgroup_sha256,
                    "declared_image_manifest_sha256": fact.image_manifest_sha256,
                    "image_binding_basis": fact.image_binding_basis,
                    "runtime_image_verified": False,
                }
            )
            continue
        semantic = fact.model_dump(mode="json")
        semantic.pop("interface_sha256")
        for field in ["layout_sha256", "index_sha256", "interface_sha256"]:
            semantic["image"].pop(field)
        prior = grouped.get(fact.identity_key)
        if prior and prior["semantic"] != semantic:
            raise ValueError("Conflicting same-image content evidence")
        entry = grouped.setdefault(fact.identity_key, {"fact": fact, "semantic": semantic, "sources": []})
        entry["sources"].append(source)
    if not grouped:
        raise ValueError("No parsed verified content; gaps are not empty image inventory")
    components = []
    for identity, entry in sorted(grouped.items()):
        f = entry["fact"]
        image = f.image
        components.append(
            {
                "type": "container",
                "bom-ref": identity,
                "name": "OCI verified image manifest sha256:" + image.manifest_sha256,
                "properties": props(
                    {
                        "manifest_sha256": image.manifest_sha256,
                        "config_sha256": image.config_sha256,
                        "declared_platform": "linux/"
                        + image.image_architecture
                        + ("/" + image.image_variant if image.image_variant else ""),
                        "verified_layers": [l.model_dump(mode="json") for l in image.layers],
                        "rootfs_virtual_view_sha256": f.rootfs_view_sha256,
                        "databases": [d.model_dump(mode="json") for d in f.databases],
                        "layer_contents_verified": True,
                        "filesystem_materialized": False,
                        "package_inventory_verified": False,
                        "deployment_verified": False,
                        "vendor_identity_verified": False,
                        "runtime_use": "UNKNOWN",
                        "unsupported_package_surfaces": f.unsupported_package_surfaces,
                        "source_basis": "IMPORTED",
                        "sources": sorted(entry["sources"], key=lambda s: s["input_id"]),
                    }
                ),
            }
        )
        for package in f.packages:
            component = {
                "type": "library",
                "bom-ref": identity + ":package:" + digest(package),
                "name": package.name,
                "properties": props(
                    {
                        "image_artifact_ref": identity,
                        **package.model_dump(mode="json"),
                        "component_type_basis": "PACKAGED_SOFTWARE_RECORD_NOT_LOADED_LIBRARY",
                        "source_basis": "IMPORTED",
                        "runtime_use": "UNKNOWN",
                        "sources": sorted(entry["sources"], key=lambda s: s["input_id"]),
                    }
                ),
            }
            if package.version is not None:
                component["version"] = package.version
            components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, "cryptoscan:container-content:" + approval_id + ":" + digest(snapshot))),
        "metadata": {
            "properties": props(
                {
                    "profile": "VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES",
                    "snapshot_sha256": digest(snapshot),
                    "approval_id": approval_id,
                    "source_basis": "IMPORTED",
                    "complete_inventory_verified": False,
                    "production_execution_qualified": False,
                    "failed_inputs": failures,
                    "runtime_process_evidence": sorted(runtime, key=lambda r: r["input_id"]),
                }
            )
        },
        "components": components,
        "compositions": [{"aggregate": "incomplete"}],
    }
