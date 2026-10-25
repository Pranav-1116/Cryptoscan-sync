"""Linux software metadata over one verified envelope, not a standard SBOM.

Package records, binary presence and mapped paths are different evidence classes.
No purl/architecture/license/dependency/artifact digest or crypto use is guessed.
"""

from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Token
from shared_models.collection import CollectionResult, TargetSpec, Observation
from shared_models.collection_coverage import project_coverage, CoverageReport, InputCoverage

MANAGERS = {"DPKG_STATUS": "dpkg", "APK_INSTALLED": "apk", "RPM_SQLITE": "rpm"}


class PackageGroup(Strict):
    identity_slot: str = Field(min_length=1, max_length=36)
    identity_basis: Literal["SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"] = "SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET"
    package_manager: Literal["dpkg", "apk", "rpm"]
    name: Token
    version: Token | None
    identity_status: Literal["SINGLE_RECORD", "MULTIPLE_RECORDS_UNRESOLVED"]
    records: list[Observation] = Field(min_length=1, max_length=1000)
    architecture: Literal["UNKNOWN"] = "UNKNOWN"
    purl: None = None
    licenses: Literal["UNKNOWN"] = "UNKNOWN"
    package_artifact_sha256: None = None
    dependencies: Literal["UNKNOWN"] = "UNKNOWN"
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    cryptographic_use: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def bindings(self):
        for row in self.records:
            if (
                row.identity_slot != self.identity_slot
                or row.fact.kind != "SOFTWARE"
                or row.fact.software_name != self.name
                or MANAGERS.get(row.source.kind) != self.package_manager
            ):
                raise ValueError("Package group must retain exact metadata-slot/source/name binding")
        status = "SINGLE_RECORD" if len(self.records) == 1 else "MULTIPLE_RECORDS_UNRESOLVED"
        version = self.records[0].fact.software_version if len(self.records) == 1 else None
        if (
            self.identity_status != status
            or self.version != version
            or len({r.observation_id for r in self.records}) != len(self.records)
        ):
            raise ValueError("Package records cannot be silently merged or have a winning version selected")
        return self


class LinuxSoftwareInventory(Strict):
    schema_version: Literal["cryptoscan.linux-software-inventory/v1"] = "cryptoscan.linux-software-inventory/v1"
    coverage: CoverageReport
    package_inputs: list[InputCoverage] = Field(max_length=100)
    packages: list[PackageGroup] = Field(max_length=1000)
    binary_presence: list[Observation] = Field(max_length=1000)
    mapped_library_paths: list[Observation] = Field(max_length=1000)
    provenance: Literal["IMPORTED"] = "IMPORTED"
    standard_document: Literal[False] = False
    dependencies_complete: Literal[False] = False
    installed_package_inventory_complete: Literal[False] = False
    host_identity_attested: Literal[False] = False
    production_execution_qualified: Literal[False] = False
    materialized_without_collection: Literal[True] = True

    @model_validator(mode="after")
    def reconcile(self):
        if self.package_inputs != [i for i in self.coverage.surfaces["software"].inputs if i.kind in MANAGERS]:
            raise ValueError("Package input outcomes must retain the approved scope and original errors")
        rows = [r for group in self.packages for r in group.records] + self.binary_presence + self.mapped_library_paths
        if (
            len(rows) > 1000
            or len({r.observation_id for r in rows}) != len(rows)
            or len({p.identity_slot for p in self.packages}) != len(self.packages)
        ):
            raise ValueError("Duplicate/oversized software evidence")
        if any(r.fact.kind != "BINARY" or r.source.kind != "BINARY_METADATA" for r in self.binary_presence):
            raise ValueError("Binary presence is not a package record")
        if any(
            r.fact.kind != "LOADED_LIBRARY" or r.source.kind != "LINUX_PROCESS_MAPS" for r in self.mapped_library_paths
        ):
            raise ValueError("Mapped path evidence required; it is not crypto invocation")
        if len(rows) != self.coverage.bom_observation_counts["SBOM"]:
            raise ValueError("Software evidence must reconcile to the same SBOM projection references")
        return self


def project_linux_software(
    result: CollectionResult, target: TargetSpec, envelope_sha256: str
) -> LinuxSoftwareInventory:
    if target.collection_method != "offline_host" or not target.manifest or target.manifest.platform != "linux":
        raise ValueError("This profile is only the approved offline Linux adapter")
    coverage = project_coverage(result, target, envelope_sha256)
    groups, binaries, mapped = {}, [], []
    for row in result.observations:
        if row.fact.kind == "SOFTWARE":
            if row.source.kind not in MANAGERS or not row.fact.software_name:
                raise ValueError("Unqualified Linux package source/identity")
            groups.setdefault(row.identity_slot, []).append(row)
        elif row.fact.kind == "BINARY":
            binaries.append(row)
        elif row.fact.kind == "LOADED_LIBRARY":
            mapped.append(row)
    packages = [
        PackageGroup(
            identity_slot=key,
            package_manager=MANAGERS[rows[0].source.kind],
            name=rows[0].fact.software_name,
            version=rows[0].fact.software_version if len(rows) == 1 else None,
            identity_status="SINGLE_RECORD" if len(rows) == 1 else "MULTIPLE_RECORDS_UNRESOLVED",
            records=rows,
        )
        for key, rows in sorted(groups.items())
    ]
    return LinuxSoftwareInventory(
        coverage=coverage,
        package_inputs=[i for i in coverage.surfaces["software"].inputs if i.kind in MANAGERS],
        packages=packages,
        binary_presence=binaries,
        mapped_library_paths=mapped,
    )
