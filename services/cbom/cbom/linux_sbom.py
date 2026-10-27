"""Evidence-linked, explicitly incomplete CycloneDX 1.6 Linux software export.

Uses existing pinned offline official schemas. Never guesses dependency edges,
package artifact hashes, purl, licenses or runtime use. Package type uses the
specification's application fallback, explicitly NOT an observed classification.
"""

from uuid import uuid5, NAMESPACE_URL
from shared_models.linux_software import LinuxSoftwareInventory
from cbom.cyclonedx16 import validate_cyclonedx16


class LinuxSBOMValidationError(ValueError):
    """No standard document may be returned when official validation fails."""


def _properties(values):
    return [{"name": "cryptoscan:" + key, "value": str(value)} for key, value in sorted(values.items())]


def _evidence(row):
    return {
        "observation_id": row.observation_id,
        "evidence_id": row.evidence_id,
        "fact_sha256": row.fact_sha256,
        "source_content_sha256": row.source.input_content_sha256,
        "source_path": row.source.path,
        "source_kind": row.source.kind,
        "local_basis": row.fact.local_basis,
        "transport_basis": row.provenance,
        "runtime_use": "UNKNOWN",
        "licenses": "UNKNOWN",
        "dependencies": "UNKNOWN",
        "artifact_integrity": "NOT_ASSERTED",
        "host_identity_attested": "false",
    }


def build_linux_sbom(inventory: LinuxSoftwareInventory) -> dict:
    # Revalidate typed copies too, so model_copy/update cannot bypass guards.
    inventory = LinuxSoftwareInventory.model_validate(inventory.model_dump(mode="json"))
    coverage = inventory.coverage
    components, omitted = [], []
    for package in inventory.packages:
        if package.identity_status != "SINGLE_RECORD":
            omitted.append(package.identity_slot)
            continue
        row = package.records[0]
        component = {
            "type": "application",
            "bom-ref": "urn:cryptoscan:metadata-slot:" + package.identity_slot,
            "name": package.name,
            "properties": _properties(
                {
                    **_evidence(row),
                    "package_manager": package.package_manager,
                    "architecture": "UNKNOWN",
                    "component_type_basis": "CYCLONEDX_SPEC_DEFAULT_NOT_OBSERVED_CLASSIFICATION",
                    "identity_basis": package.identity_basis,
                }
            ),
        }
        if package.version is not None:
            component["version"] = package.version
        components.append(component)
    for row in inventory.binary_presence:
        components.append(
            {
                "type": "file",
                "bom-ref": "urn:cryptoscan:observation:" + row.observation_id,
                "name": row.source.path,
                "properties": _properties(
                    {
                        **_evidence(row),
                        "component_type_basis": "APPROVED_FILE_PRESENCE_ONLY",
                        "package_ownership": "UNKNOWN",
                    }
                ),
            }
        )
    metadata = {
        "profile": "LINUX_SOFTWARE_METADATA_INCOMPLETE_V1",
        "job_id": coverage.job_id,
        "target_id": coverage.target_id,
        "target_revision": coverage.target_revision,
        "target_sha256": coverage.target_sha256,
        "envelope_sha256": coverage.envelope_sha256,
        "system_id": coverage.system_id,
        "transport_basis": "IMPORTED",
        "inventory_completeness": "NOT_PROVEN",
        "dependency_completeness": "UNKNOWN",
        "production_execution_qualified": "false",
        "host_identity_attested": "false",
        "materialized_without_collection": "true",
        "timestamp_basis": "OPERATOR_SUPPLIED_NOT_ATTESTED",
        "package_inputs_approved": len(inventory.package_inputs),
        "package_inputs_failed": sum(i.status != "PARSED" for i in inventory.package_inputs),
        "mapped_path_records_not_components": len(inventory.mapped_library_paths),
        "ambiguous_package_groups_omitted": len(omitted),
        "artifact_hashes_and_purl": "NOT_ASSERTED",
    }
    metadata.update({"omitted_metadata_slot:" + str(i): slot for i, slot in enumerate(sorted(omitted))})
    for item in inventory.package_inputs:
        metadata["package_input:" + item.input_id] = item.status + ":" + item.reason
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:"
        + str(uuid5(NAMESPACE_URL, "cryptoscan:linux-sbom:" + coverage.job_id + ":" + coverage.envelope_sha256)),
        "metadata": {"timestamp": coverage.finished_at, "properties": _properties(metadata)},
        "components": sorted(components, key=lambda c: c["bom-ref"]),
        "compositions": [{"aggregate": "incomplete"}],
    }
    # No dependsOn: [] leaves, invented root fanout, or metadata-join dependencies.
    validation = validate_cyclonedx16(document)
    if not validation["ok"]:
        raise LinuxSBOMValidationError("Pinned official CycloneDX validation failed; no export produced")
    return document
