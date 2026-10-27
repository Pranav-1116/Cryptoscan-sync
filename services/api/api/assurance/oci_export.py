"""Artifact-only OCI SBOM from verified stored originals; no filesystem/network IO."""

import json
import uuid
from shared_models.host_collection import digest


def image_sbom(snapshot, records, approval_id):
    grouped = {}
    requested = {i.input_id for i in snapshot.manifest.inputs if i.kind == "OCI_IMAGE_METADATA"}
    failures = []
    for receipt in snapshot.receipts:
        if receipt.input_id not in requested:
            continue
        if receipt.status != "PARSED":
            failures.append({"input_id": receipt.input_id, "status": receipt.status, "reason": receipt.reason})
            continue
        fact = receipt.facts[0]
        proofs = [r.id for r in records if r.finding_data.get("host_evidence", {}).get("input_id") == receipt.input_id]
        if not proofs:
            raise ValueError("Retained evidence reference required")
        semantic = {
            k: v
            for k, v in fact.model_dump(mode="json").items()
            if k not in {"layout_sha256", "index_sha256", "interface_sha256"}
        }
        prior = grouped.get(fact.identity_key)
        if prior and prior["semantic"] != semantic:
            raise ValueError("Conflicting same-manifest metadata")
        entry = grouped.setdefault(fact.identity_key, {"fact": fact, "semantic": semantic, "sources": []})
        entry["sources"].append(
            {
                "input_id": receipt.input_id,
                "evidence_ids": sorted(proofs),
                "selected_metadata_sha256": receipt.content_sha256,
                "index_sha256": fact.index_sha256,
                "layout_sha256": fact.layout_sha256,
            }
        )
    if not grouped:
        raise ValueError("No parsed approved OCI metadata; failure is not image absence")

    def props(value):
        return [
            {
                "name": "cryptoscan:" + k,
                "value": v if isinstance(v, str) else json.dumps(v, sort_keys=True, separators=(",", ":")),
            }
            for k, v in sorted(value.items())
        ]

    components = []
    for identity, entry in sorted(grouped.items()):
        f = entry["fact"]
        components.append(
            {
                "type": "container",
                "bom-ref": identity,
                "name": "OCI image manifest sha256:" + f.manifest_sha256,
                "properties": props(
                    {
                        "identity_basis": "MANIFEST_CONTENT_ADDRESS_AND_DECLARED_PLATFORM_NOT_DEPLOYMENT",
                        "manifest_sha256": f.manifest_sha256,
                        "config_sha256": f.config_sha256,
                        "declared_platform": "linux/"
                        + f.image_architecture
                        + ("/" + f.image_variant if f.image_variant else ""),
                        "declared_layers": [l.model_dump(mode="json") for l in f.layers],
                        "declared_ports": f.declared_ports,
                        "declared_base_digest": f.declared_base_digest,
                        "configuration_basis": "DECLARED",
                        "source_basis": "IMPORTED",
                        "local_basis": "OBSERVED",
                        "layer_contents_verified": False,
                        "package_inventory_verified": False,
                        "deployment_verified": False,
                        "runtime_use": "UNKNOWN",
                        "sources": sorted(entry["sources"], key=lambda x: x["input_id"]),
                    }
                ),
            }
        )
    commitment = digest(snapshot)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, "cryptoscan:oci-metadata:" + approval_id + ":" + commitment)),
        "version": 1,
        "metadata": {
            "properties": props(
                {
                    "profile": "OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM",
                    "approval_id": approval_id,
                    "snapshot_sha256": commitment,
                    "source_basis": "IMPORTED",
                    "approved_image_inputs": len(requested),
                    "failed_image_inputs": failures,
                    "production_execution_qualified": False,
                    "complete_inventory_verified": False,
                }
            )
        },
        "components": components,
        "compositions": [{"aggregate": "incomplete"}],
    }
