"""Offline OCI evidence contract. Image metadata is not runtime or host evidence."""

from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, HostFact, HostManifest, Token, digest

MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA = "application/vnd.oci.image.layer.v1.tar"
MAX_BLOB = 16 * 1024 * 1024
MAX_RAW_LAYER = 32 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_ENTRIES = 10000


def relative_path(value: str) -> str:
    p = PurePosixPath(value)
    if (
        not value
        or value == "."
        or len(value) > 512
        or value.startswith("/")
        or str(p) != value
        or ".." in p.parts
        or len(p.parts) > 64
        or "\\" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Canonical relative image path required")
    return value


class ImageInput(Strict):
    input_id: Token
    kind: Literal[
        "DPKG_STATUS",
        "APK_INSTALLED",
        "RPM_SQLITE",
        "LINUX_OS_RELEASE",
        "PUBLIC_CERTIFICATE",
        "BINARY_METADATA",
        "NGINX_TLS_CONFIG",
    ]
    path: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def scoped(self):
        relative_path(self.path)
        fixed = {
            "DPKG_STATUS": {"var/lib/dpkg/status"},
            "APK_INSTALLED": {"lib/apk/db/installed"},
            "RPM_SQLITE": {"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"},
            "LINUX_OS_RELEASE": {"etc/os-release", "usr/lib/os-release"},
        }
        if self.kind in fixed and self.path not in fixed[self.kind]:
            raise ValueError("Noncanonical package/OS metadata path")
        return self


class OciTarget(Strict):
    schema_version: Literal["cryptoscan.oci-target/v1"] = "cryptoscan.oci-target/v1"
    target_id: Token
    system_id: Token
    environment: Token
    authorization_reference: Token
    layout_path: str = Field(min_length=1, max_length=1024)
    manifest_sha256: Digest
    architecture: Literal["amd64", "arm64"]
    not_before: datetime
    expires_at: datetime
    inputs: list[ImageInput] = Field(min_length=1, max_length=16)

    @field_validator("not_before", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def scope(self):
        p = PurePosixPath(self.layout_path)
        if (
            not p.is_absolute()
            or str(p) != self.layout_path
            or self.layout_path == "/"
            or ".." in p.parts
            or self.layout_path.startswith("//")
        ):
            raise ValueError("Canonical absolute OCI directory required")
        duration = (self.expires_at - self.not_before).total_seconds()
        if not 0 < duration <= 86400:
            raise ValueError("Explicit positive collection window, at most one day, required")
        if len({x.input_id for x in self.inputs}) != len(self.inputs) or len({x.path for x in self.inputs}) != len(
            self.inputs
        ):
            raise ValueError("Duplicate image input")
        return self


class BlobRef(Strict):
    sha256: Digest
    byte_count: int = Field(ge=0, le=MAX_BLOB)
    role: Literal["MANIFEST", "CONFIG", "LAYER"]


class ImageReceipt(Strict):
    input_id: Token
    path: str
    status: Literal["PARSED", "UNAVAILABLE", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED"]
    reason: Literal["METADATA_ONLY", "NOT_FOUND", "LINK_OR_SPECIAL", "INVALID_FORMAT", "LIMIT"]
    content_sha256: Digest | None = None
    layer_sha256: Digest | None = None
    byte_count: int = Field(default=0, ge=0, le=1048576)
    facts: list[HostFact] = Field(default_factory=list, max_length=1000)
    asset_absence_proven: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self):
        pairs = {
            "PARSED": "METADATA_ONLY",
            "UNAVAILABLE": "NOT_FOUND",
            "UNSUPPORTED": "LINK_OR_SPECIAL",
            "INVALID": "INVALID_FORMAT",
            "BUDGET_EXCEEDED": "LIMIT",
        }
        if pairs[self.status] != self.reason:
            raise ValueError("Receipt status/reason mismatch")
        if self.status == "PARSED" and (not self.facts or self.content_sha256 is None or self.layer_sha256 is None):
            raise ValueError("Successful receipt needs source commitments and nonempty typed facts")
        if self.status != "PARSED" and self.facts:
            raise ValueError("Failed input cannot assert facts")
        return self


class ImageDeclarations(Strict):
    provenance: Literal["DECLARED"] = "DECLARED"
    exposed_ports: list[str] = Field(default_factory=list, max_length=64)
    vendor: Token | None = None
    base_image_name: Token | None = None
    base_image_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    base_image_verified: Literal[False] = False
    live_listeners_observed: Literal[False] = False

    @field_validator("exposed_ports")
    @classmethod
    def ports(cls, values):
        import re

        if values != sorted(set(values)) or any(
            not re.fullmatch(r"(?:[1-9][0-9]{0,4})/(?:tcp|udp|sctp)", x) or int(x.split("/")[0]) > 65535 for x in values
        ):
            raise ValueError("Canonical exposed port declarations required")
        return values


class ImageCoverage(Strict):
    parsed_inputs: int = Field(ge=0, le=16)
    approved_inputs: int = Field(ge=1, le=16)
    basis: Literal["APPROVED_METADATA_INPUTS_ONLY"] = "APPROVED_METADATA_INPUTS_ONLY"
    whole_image_percent: None = None
    whole_image_coverage_verified: Literal[False] = False


class OciEvidence(Strict):
    schema_version: Literal["cryptoscan.oci-evidence/v1"] = "cryptoscan.oci-evidence/v1"
    collector: Literal["offline-oci/candidate-v1"] = "offline-oci/candidate-v1"
    target: OciTarget
    target_sha256: Digest
    started_at: datetime
    finished_at: datetime
    status: Literal["COMPLETED", "PARTIAL", "FAILED"]
    provenance: Literal["IMPORTED"] = "IMPORTED"
    blobs: list[BlobRef] = Field(min_length=3, max_length=18)
    config_sha256: Digest
    diff_ids: list[Digest] = Field(min_length=1, max_length=16)
    declarations: ImageDeclarations
    coverage: ImageCoverage
    receipts: list[ImageReceipt] = Field(min_length=1, max_length=16)
    authenticity_verified: Literal[False] = False
    full_image_software_complete: Literal[False] = False
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    hardware_origin: Literal["UNKNOWN"] = "UNKNOWN"
    production_execution_qualified: Literal[False] = False
    image_executed: Literal[False] = False

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def consistent(self):
        if self.target_sha256 != digest(self.target):
            raise ValueError("Target commitment mismatch")
        if not self.target.not_before <= self.started_at <= self.finished_at < self.target.expires_at:
            raise ValueError("Collection outside approved window")
        if [(r.input_id, r.path) for r in self.receipts] != [(i.input_id, i.path) for i in self.target.inputs]:
            raise ValueError("Exactly one ordered receipt per approved input required")
        if [b.role for b in self.blobs] != ["MANIFEST", "CONFIG"] + ["LAYER"] * len(self.diff_ids):
            raise ValueError("Exact ordered manifest/config/layer commitments required")
        if self.blobs[0].sha256 != self.target.manifest_sha256 or self.blobs[1].sha256 != self.config_sha256:
            raise ValueError("Blob identity mismatch")
        if sum(b.byte_count for b in self.blobs) > MAX_TOTAL:
            raise ValueError("Total blob budget exceeded")
        success = sum(r.status == "PARSED" for r in self.receipts)
        if self.coverage.parsed_inputs != success or self.coverage.approved_inputs != len(self.receipts):
            raise ValueError("Receipt coverage mismatch")
        expected = "COMPLETED" if success == len(self.receipts) else "PARTIAL" if success else "FAILED"
        if self.status != expected or sum(len(r.facts) for r in self.receipts) > 1000:
            raise ValueError("Outcome/fact budget mismatch")
        kinds = {
            "DPKG_STATUS": "SOFTWARE",
            "APK_INSTALLED": "SOFTWARE",
            "RPM_SQLITE": "SOFTWARE",
            "LINUX_OS_RELEASE": "OS_RELEASE",
            "PUBLIC_CERTIFICATE": "CERTIFICATE",
            "BINARY_METADATA": "BINARY",
            "NGINX_TLS_CONFIG": "TLS_CONFIGURATION",
        }
        layers = {b.sha256 for b in self.blobs if b.role == "LAYER"}
        for item, r in zip(self.target.inputs, self.receipts):
            if any(f.kind != kinds[item.kind] for f in r.facts) or (
                r.layer_sha256 is not None and r.layer_sha256 not in layers
            ):
                raise ValueError("Fact kind or source layer mismatch")
        return self
