"""Pinned OCI manifest/config metadata; layer contents and runtime remain unknown."""

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict

HEX = r"[0-9a-f]{64}"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
}


def image_resource(path):
    match = re.fullmatch(
        r"oci-layout://local/linux/(amd64|arm64)(/v8)?/manifest/sha256/(" + HEX + r")/root/([^%?#\x00-\x1f\x7f]+)", path
    )
    if not match:
        raise ValueError("Exact pinned local OCI layout/manifest/platform required")
    arch, variant, manifest, root = match.groups()
    if variant and arch != "arm64" or any(part in {"", ".", ".."} for part in root.split("/")) or "\\" in root:
        raise ValueError("Noncanonical OCI root/platform")
    root = "/" + root
    if PurePosixPath(root).as_posix() != root:
        raise ValueError("Noncanonical OCI root")
    return root, arch, "v8" if variant else None, manifest


def select_oci_manifest(index, digest):
    """Exact selector shared with the existing image metadata parser; never first-match."""
    if not isinstance(index, dict) or type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2:
        raise ValueError("Unsupported OCI index")
    if index.get(
        "mediaType", "application/vnd.oci.image.index.v1+json"
    ) != "application/vnd.oci.image.index.v1+json" or any(k in index for k in ("subject", "artifactType")):
        raise ValueError("Direct OCI image index required")
    entries = index.get("manifests")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
        raise ValueError("Bounded OCI index required")
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("digest") == digest]
    if len(matches) != 1:
        raise ValueError("Unique approved OCI manifest descriptor required")
    return matches[0]


class OciLayer(Strict):
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    size: int = Field(ge=0, le=9007199254740991, strict=True)
    media_type: Literal[
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
    ]
    diff_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


SELECTED = (
    "layout_sha256",
    "index_sha256",
    "manifest_sha256",
    "manifest_size",
    "config_sha256",
    "config_size",
    "image_os",
    "image_architecture",
    "image_variant",
    "layers",
    "declared_ports",
    "declared_base_digest",
)


def metadata_bytes(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(
        {k: value[k] for k in SELECTED}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


class OciImageFact(Strict):
    kind: Literal["OCI_IMAGE_METADATA"]
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["PINNED_OCI_MANIFEST_CONFIG_METADATA"] = "PINNED_OCI_MANIFEST_CONFIG_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    interface: Literal["OFFLINE_OCI_LAYOUT_METADATA"] = "OFFLINE_OCI_LAYOUT_METADATA"
    configuration_basis: Literal["DECLARED"] = "DECLARED"
    capture_basis: Literal["MANIFEST_CONFIG_BYTES_NOT_LAYERS_OR_RUNTIME"] = (
        "MANIFEST_CONFIG_BYTES_NOT_LAYERS_OR_RUNTIME"
    )
    layout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_size: int = Field(ge=1, le=1048576, strict=True)
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    config_size: int = Field(ge=1, le=1048576, strict=True)
    image_os: Literal["linux"] = "linux"
    image_architecture: Literal["amd64", "arm64"]
    image_variant: Literal["v8"] | None = None
    layers: list[OciLayer] = Field(max_length=128)
    declared_ports: list[str] = Field(max_length=64)
    declared_base_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    identity_key: str = Field(max_length=150)
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    layer_contents_verified: Literal[False] = False
    filesystem_materialized: Literal[False] = False
    package_inventory_verified: Literal[False] = False
    deployment_verified: Literal[False] = False
    vendor_identity_verified: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self):
        if self.image_variant and self.image_architecture != "arm64":
            raise ValueError("Variant outside supported platform")
        if self.declared_ports != sorted(set(self.declared_ports)) or any(
            not re.fullmatch(r"[1-9][0-9]{0,4}/(?:tcp|udp)", p) or int(p.split("/")[0]) > 65535
            for p in self.declared_ports
        ):
            raise ValueError("Canonical bounded declared ports required")
        expected = f"oci-manifest:sha256:{self.manifest_sha256}:linux:{self.image_architecture}:{self.image_variant or 'unspecified'}"
        if self.identity_key != expected or self.interface_sha256 != hashlib.sha256(metadata_bytes(self)).hexdigest():
            raise ValueError("OCI metadata identity/selected commitment mismatch")
        return self


def validate_image(item, facts):
    _, arch, variant, manifest = image_resource(item.path)
    if facts and (
        len(facts) != 1
        or (facts[0].manifest_sha256, facts[0].image_architecture, facts[0].image_variant) != (manifest, arch, variant)
    ):
        raise ValueError("OCI fact outside pinned manifest/platform")
