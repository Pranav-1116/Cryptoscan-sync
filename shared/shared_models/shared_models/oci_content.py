"""Verified OCI content and scoped process evidence, not publisher/use attestation."""

import hashlib
import json
import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict
from shared_models.oci_image import OciImageFact, image_resource
from shared_models.host_runtime import RuntimeFact

KINDS = {"OCI_IMAGE_METADATA", "OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"}
DIGEST = r"^[0-9a-f]{64}$"
DB_PATHS = {"dpkg": "var/lib/dpkg/status", "apk": "lib/apk/db/installed"}


def content_resource(path):
    if not path.startswith("oci-content://"):
        raise ValueError("Explicit OCI content scope required")
    return image_resource("oci-layout://" + path.removeprefix("oci-content://"))


def runtime_resource(path):
    match = re.fullmatch(
        r"container-proc://linux/(docker|containerd)/([0-9a-f]{64})/pid/([1-9][0-9]{0,8})"
        r"/start/([1-9][0-9]{0,19})/boot/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"/manifest/sha256/([0-9a-f]{64})",
        path,
    )
    if not match:
        raise ValueError("Exact container/PID incarnation and declared image required")
    runtime, container, pid, start, boot, image = match.groups()
    return runtime, container, int(pid), int(start), boot, image


def selected_bytes(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(
        {k: v for k, v in value.items() if k != "interface_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def seal(model, **value):
    # Defaults also participate in the selected evidence commitment.
    fact = model.model_construct(**value, interface_sha256="0" * 64)
    return model.model_validate(
        {**fact.model_dump(mode="json"), "interface_sha256": hashlib.sha256(selected_bytes(fact)).hexdigest()}
    )


class PackageRecord(Strict):
    manager: Literal["dpkg", "apk"]
    name: str = Field(min_length=1, max_length=120, pattern=r"^[^\x00-\x1f\x7f]+$")
    version: str | None = Field(default=None, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")
    source_path: str
    source_sha256: str = Field(pattern=DIGEST)
    layer_index: int = Field(ge=0, le=127, strict=True)
    basis: Literal["VERIFIED_IMAGE_PACKAGE_DATABASE_RECORD_NOT_EXECUTABLE_OR_USE"] = (
        "VERIFIED_IMAGE_PACKAGE_DATABASE_RECORD_NOT_EXECUTABLE_OR_USE"
    )


class PackageDatabase(Strict):
    manager: Literal["dpkg", "apk"]
    path: str
    status: Literal["PARSED", "NOT_PRESENT_IN_VERIFIED_VIEW"]
    sha256: str | None = Field(default=None, pattern=DIGEST)
    layer_index: int | None = Field(default=None, ge=0, le=127, strict=True)

    @model_validator(mode="after")
    def scope(self):
        if self.path != DB_PATHS[self.manager] or (
            (self.sha256 is not None and self.layer_index is not None) != (self.status == "PARSED")
        ):
            raise ValueError("Package database scope/provenance mismatch")
        if self.status != "PARSED" and (self.sha256 is not None or self.layer_index is not None):
            raise ValueError("Missing database cannot claim provenance")
        return self


class ContainerFact(Strict):
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    deployment_verified: Literal[False] = False
    vendor_identity_verified: Literal[False] = False
    interface_sha256: str = Field(pattern=DIGEST)
    identity_key: str = Field(max_length=300)

    @model_validator(mode="after")
    def commitment(self):
        if self.interface_sha256 != hashlib.sha256(selected_bytes(self)).hexdigest():
            raise ValueError("Selected container evidence commitment mismatch")
        return self


class OciContentFact(ContainerFact):
    kind: Literal["OCI_IMAGE_CONTENT"] = "OCI_IMAGE_CONTENT"
    purpose: Literal["VERIFIED_OCI_LAYERS_AND_PACKAGE_DATABASES"] = "VERIFIED_OCI_LAYERS_AND_PACKAGE_DATABASES"
    interface: Literal["OFFLINE_OCI_VERIFIED_CONTENT"] = "OFFLINE_OCI_VERIFIED_CONTENT"
    image: OciImageFact
    layer_contents_verified: Literal[True] = True
    final_filesystem_view_verified: Literal[True] = True
    filesystem_materialized: Literal[False] = False
    rootfs_view_sha256: str = Field(pattern=DIGEST)
    packages: list[PackageRecord] = Field(max_length=500)
    databases: list[PackageDatabase] = Field(min_length=2, max_length=2)
    package_inventory_verified: Literal[False] = False
    complete_inventory_verified: Literal[False] = False
    unsupported_package_surfaces: Literal["RPM_LANGUAGE_BINARY_AND_EXECUTABLE_CONTENT"] = (
        "RPM_LANGUAGE_BINARY_AND_EXECUTABLE_CONTENT"
    )

    @model_validator(mode="after")
    def consistent(self):
        if self.identity_key != self.image.identity_key + ":content":
            raise ValueError("Content identity mismatch")
        if [d.manager for d in self.databases] != ["dpkg", "apk"]:
            raise ValueError("Exact database denominator required")
        dbs = {d.manager: d for d in self.databases}
        keys = [(p.manager, p.name) for p in self.packages]
        if keys != sorted(set(keys)):
            raise ValueError("Canonical unique package records required")
        for d in self.databases:
            if d.status == "PARSED" and not any(p.manager == d.manager for p in self.packages):
                raise ValueError("Parsed database must retain package records")
            if d.layer_index is not None and d.layer_index >= len(self.image.layers):
                raise ValueError("Database layer outside verified image")
        for p in self.packages:
            d = dbs[p.manager]
            if d.status != "PARSED" or (p.source_path, p.source_sha256, p.layer_index) != (
                d.path,
                d.sha256,
                d.layer_index,
            ):
                raise ValueError("Package record lacks verified database provenance")
        return self


class OciRuntimeFact(ContainerFact):
    kind: Literal["OCI_RUNTIME_PROCESS"] = "OCI_RUNTIME_PROCESS"
    purpose: Literal["EXACT_PROCESS_CONTAINER_CGROUP_MEMBERSHIP"] = "EXACT_PROCESS_CONTAINER_CGROUP_MEMBERSHIP"
    interface: Literal["LINUX_PROCFS_CONTAINER_MEMBERSHIP"] = "LINUX_PROCFS_CONTAINER_MEMBERSHIP"
    runtime: Literal["docker", "containerd"]
    container_id: str = Field(pattern=DIGEST)
    image_manifest_sha256: str = Field(pattern=DIGEST)
    image_binding_basis: Literal["OPERATOR_DECLARED_NOT_RUNTIME_VERIFIED"] = "OPERATOR_DECLARED_NOT_RUNTIME_VERIFIED"
    runtime_image_verified: Literal[False] = False
    process_observed: Literal[True] = True
    process: RuntimeFact
    source_sha256: str = Field(pattern=DIGEST)
    cgroup_sha256: str = Field(pattern=DIGEST)

    @model_validator(mode="after")
    def consistent(self):
        p = self.process
        if p.kind != "PROCESS" or p.interface != "LINUX_PROCFS" or p.interface_sha256 is not None:
            raise ValueError("Exact unpromoted kernel process metadata required")
        if self.identity_key != f"container:{self.runtime}:{self.container_id}:{p.identity_key}":
            raise ValueError("Container process identity mismatch")
        return self


def validate_container(item, facts):
    if not facts:
        return
    if len(facts) != 1:
        raise ValueError("One bounded container observation per input")
    fact = facts[0]
    if item.kind == "OCI_IMAGE_CONTENT":
        _, arch, variant, digest = content_resource(item.path)
        if (fact.image.image_architecture, fact.image.image_variant, fact.image.manifest_sha256) != (
            arch,
            variant,
            digest,
        ):
            raise ValueError("Content outside approved image")
    else:
        runtime, container, pid, start, boot, image = runtime_resource(item.path)
        p = fact.process
        if (fact.runtime, fact.container_id, p.pid, p.process_start_ticks, p.boot_id, fact.image_manifest_sha256) != (
            runtime,
            container,
            pid,
            start,
            boot,
            image,
        ):
            raise ValueError("Runtime evidence outside approved incarnation/image declaration")
