"""Versioned offline host contract. Collection claims are NOT host attestation.

Only explicit metadata fields cross the wire; unknown keys/raw bytes are refused.
A parsed input is not complete host coverage or proof of effective runtime use.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

SCHEMA = "cryptoscan.host-snapshot/v1"
MAX_FILE_BYTES = 1048576
MAX_TOTAL_BYTES = 16 * MAX_FILE_BYTES
MAX_FACTS = 1000
Token = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/@+ ~()\[\]-]{0,119}$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SignatureOid = Annotated[str, StringConstraints(max_length=100, pattern=r"^(UNKNOWN|[0-9]+(?:\.[0-9]+)+)$")]
Kind = Literal["PUBLIC_CERTIFICATE", "NGINX_TLS_CONFIG", "BINARY_METADATA", "DPKG_STATUS", "WINDOWS_UNINSTALL"]
Basis = Literal["OBSERVED", "DECLARED", "IMPORTED", "INFERRED", "UNKNOWN"]
Protocol = Literal["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
Cipher = Literal[
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def digest(value) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    ).hexdigest()


class HostInput(Strict):
    input_id: Token
    kind: Kind
    path: str = Field(min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f]+$")


class HostManifest(Strict):
    schema_version: Literal["cryptoscan.host-manifest/v1"] = "cryptoscan.host-manifest/v1"
    approval_reference: Token
    host_id: Token
    environment: Token
    platform: Literal["linux", "windows"]
    expires_at: datetime
    inputs: list[HostInput] = Field(min_length=1, max_length=100)
    max_file_bytes: int = Field(default=MAX_FILE_BYTES, ge=1, le=MAX_FILE_BYTES)
    max_total_bytes: int = Field(default=MAX_TOTAL_BYTES, ge=1, le=MAX_TOTAL_BYTES)

    @field_validator("expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("UTC-offset-aware expiry required")
        return value

    @model_validator(mode="after")
    def unique(self):
        if len({i.input_id for i in self.inputs}) != len(self.inputs) or len({i.path for i in self.inputs}) != len(
            self.inputs
        ):
            raise ValueError("duplicate input identity/path")
        return self


class HostFact(Strict):
    kind: Literal["CERTIFICATE", "TLS_CONFIGURATION", "BINARY", "SOFTWARE"]
    local_basis: Literal["OBSERVED", "DECLARED"]
    algorithm: Literal["RSA", "EC", "DSA", "ED25519", "ED448", "UNKNOWN"] = "UNKNOWN"
    key_size: int | None = Field(default=None, ge=1, le=16384)
    mode: Literal["UNKNOWN"] = "UNKNOWN"
    purpose: Literal["PUBLIC_KEY_METADATA", "TLS_CONFIGURATION", "FILE_PRESENCE", "PACKAGE_DATABASE_RECORD"]
    fingerprint_sha256: Digest | None = None
    signature_hash: Literal["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "UNKNOWN"] = "UNKNOWN"
    curve: Literal["secp256r1", "secp384r1", "secp521r1", "UNKNOWN"] = "UNKNOWN"
    certificate_signature_oid: SignatureOid = "UNKNOWN"
    protocols: list[Protocol] = Field(default_factory=list, max_length=4)
    cipher_suites: list[Cipher] = Field(default_factory=list, max_length=6)
    unparsed_directives: bool = False
    binary_format: Literal["ELF", "PE", "UNKNOWN"] = "UNKNOWN"
    software_name: Token | None = None
    software_version: Token | None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def no_promotion(self):
        if self.kind == "CERTIFICATE" and self.fingerprint_sha256 is None:
            raise ValueError("certificate identity fingerprint required")
        if self.curve != "UNKNOWN" and self.algorithm != "EC":
            raise ValueError("curve metadata requires EC public-key family")
        if self.kind != "CERTIFICATE" and (
            self.algorithm != "UNKNOWN"
            or self.key_size is not None
            or self.fingerprint_sha256 is not None
            or self.signature_hash != "UNKNOWN"
            or self.curve != "UNKNOWN"
            or self.certificate_signature_oid != "UNKNOWN"
        ):
            raise ValueError("non-certificate metadata cannot assert a public-key algorithm")
        if (self.kind == "TLS_CONFIGURATION") != (self.local_basis == "DECLARED"):
            raise ValueError("configuration contents are declarations, never effective TLS observations")
        purposes = {
            "CERTIFICATE": "PUBLIC_KEY_METADATA",
            "TLS_CONFIGURATION": "TLS_CONFIGURATION",
            "BINARY": "FILE_PRESENCE",
            "SOFTWARE": "PACKAGE_DATABASE_RECORD",
        }
        if self.purpose != purposes[self.kind]:
            raise ValueError("fact purpose mismatch")
        if self.kind != "TLS_CONFIGURATION" and (self.protocols or self.cipher_suites or self.unparsed_directives):
            raise ValueError("configuration fields require a configuration fact")
        if self.kind != "BINARY" and self.binary_format != "UNKNOWN":
            raise ValueError("binary format requires a binary fact")
        if self.kind != "SOFTWARE" and (self.software_name is not None or self.software_version is not None):
            raise ValueError("software fields require a software fact")
        if self.algorithm == "UNKNOWN" and self.key_size is not None:
            raise ValueError("unknown algorithm cannot carry an interpreted key size")
        return self


ReceiptStatus = Literal["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"]
ReceiptReason = Literal[
    "METADATA_ONLY",
    "ACCESS_DENIED",
    "UNSUPPORTED_PLATFORM",
    "SYMLINK_OR_SPECIAL",
    "INVALID_FORMAT",
    "PRIVATE_MATERIAL_REFUSED",
    "INPUT_CHANGED",
    "LIMIT",
    "NOT_FOUND",
    "EXPIRED",
    "LEAST_PRIVILEGE_UNPROVEN",
]
SignatureHash = Literal["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "UNKNOWN"]
Curve = Literal["secp256r1", "secp384r1", "secp521r1", "UNKNOWN"]


class HostReceipt(Strict):
    input_id: Token
    status: Literal["PARSED", "DENIED", "UNSUPPORTED", "INVALID", "BUDGET_EXCEEDED", "UNAVAILABLE"]
    reason: Literal[
        "METADATA_ONLY",
        "ACCESS_DENIED",
        "UNSUPPORTED_PLATFORM",
        "SYMLINK_OR_SPECIAL",
        "INVALID_FORMAT",
        "PRIVATE_MATERIAL_REFUSED",
        "INPUT_CHANGED",
        "LIMIT",
        "NOT_FOUND",
        "EXPIRED",
        "LEAST_PRIVILEGE_UNPROVEN",
    ]
    byte_count: int = Field(default=0, ge=0, le=MAX_FILE_BYTES)
    content_sha256: Digest | None = None
    facts: list[HostFact] = Field(default_factory=list, max_length=MAX_FACTS)

    @model_validator(mode="after")
    def disposition(self):
        if self.status == "PARSED":
            if self.reason != "METADATA_ONLY" or not self.facts or not self.content_sha256:
                raise ValueError("parsed receipt requires bounded metadata and digest")
        elif self.facts or self.content_sha256:
            raise ValueError("failed receipt cannot contain positive facts or content digest")
        permitted = {
            "METADATA_ONLY": {"PARSED"},
            "ACCESS_DENIED": {"DENIED"},
            "UNSUPPORTED_PLATFORM": {"UNSUPPORTED"},
            "SYMLINK_OR_SPECIAL": {"UNSUPPORTED"},
            "INVALID_FORMAT": {"INVALID", "UNSUPPORTED"},
            "PRIVATE_MATERIAL_REFUSED": {"INVALID"},
            "INPUT_CHANGED": {"INVALID"},
            "LIMIT": {"BUDGET_EXCEEDED"},
            "NOT_FOUND": {"UNAVAILABLE"},
            "EXPIRED": {"DENIED"},
            "LEAST_PRIVILEGE_UNPROVEN": {"DENIED"},
        }
        if self.status not in permitted[self.reason]:
            raise ValueError("receipt status/reason mismatch")
        return self


class HostSnapshot(Strict):
    schema_version: Literal["cryptoscan.host-snapshot/v1"] = SCHEMA
    collector_version: Literal["1.0"] = "1.0"
    manifest: HostManifest
    manifest_sha256: Digest
    started_at: datetime
    finished_at: datetime
    execution_platform: Literal["linux", "windows", "unsupported"]
    receipts: list[HostReceipt] = Field(min_length=1, max_length=100)
    source_revision: None = None  # A host snapshot is not a Git revision.
    whole_host_coverage_verified: Literal[False] = False
    host_identity_attested: Literal[False] = False
    windows_execution_qualified: Literal[False] = False
    production_execution_qualified: Literal[False] = False

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def consistent(self):
        if self.manifest_sha256 != digest(self.manifest):
            raise ValueError("manifest commitment mismatch")
        if self.finished_at < self.started_at:
            raise ValueError("collection clock ordering invalid")
        if [r.input_id for r in self.receipts] != [i.input_id for i in self.manifest.inputs]:
            raise ValueError("exactly one ordered receipt per approved input required")
        if sum(len(r.facts) for r in self.receipts) > MAX_FACTS:
            raise ValueError("snapshot fact limit")
        if sum(r.byte_count for r in self.receipts) > self.manifest.max_total_bytes:
            raise ValueError("total input byte limit")
        kinds = {
            "PUBLIC_CERTIFICATE": "CERTIFICATE",
            "NGINX_TLS_CONFIG": "TLS_CONFIGURATION",
            "BINARY_METADATA": "BINARY",
            "DPKG_STATUS": "SOFTWARE",
            "WINDOWS_UNINSTALL": "SOFTWARE",
        }
        for item, receipt in zip(self.manifest.inputs, self.receipts):
            if receipt.byte_count > self.manifest.max_file_bytes or any(
                f.kind != kinds[item.kind] for f in receipt.facts
            ):
                raise ValueError("input budget/fact kind mismatch")
            if receipt.status == "PARSED" and (
                (item.kind == "DPKG_STATUS" and self.execution_platform != "linux")
                or (item.kind == "WINDOWS_UNINSTALL" and self.execution_platform != "windows")
            ):
                raise ValueError("OS-specific inventory on the wrong platform")
            if self.execution_platform != self.manifest.platform and receipt.status == "PARSED":
                raise ValueError("wrong-platform snapshot cannot assert collection success")
        return self


class HostEvidenceRef(Strict):
    """Flat, hash-covered reference, never a raw snapshot in a finding."""

    source_basis: Literal["IMPORTED"] = "IMPORTED"
    local_basis: Basis
    snapshot_sha256: Digest
    approval_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    system_id: Token
    host_id: Token
    environment: Token
    input_id: Token
    fact_ordinal: int = Field(ge=-1, le=MAX_FACTS)
    fact_kind: Literal["RECEIPT", "CERTIFICATE", "TLS_CONFIGURATION"]
    receipt_status: ReceiptStatus
    receipt_reason: ReceiptReason
    observed_at: str = Field(min_length=1, max_length=40)
    source_revision: Literal["UNKNOWN"] = "UNKNOWN"
    fingerprint_sha256: Digest | Literal["UNKNOWN"] = "UNKNOWN"
    library: Literal["UNKNOWN"] = "UNKNOWN"
    library_version: Literal["UNKNOWN"] = "UNKNOWN"
    configured_protocols: str = Field(
        default="", max_length=40, pattern=r"^(TLSv1(?:\.[123])?(?:,TLSv1(?:\.[123])?)*)?$"
    )
    configured_cipher_suites: str = Field(default="", max_length=256, pattern=r"^[A-Z0-9,_-]*$")
    signature_hash: SignatureHash = "UNKNOWN"
    curve: Curve = "UNKNOWN"
    certificate_signature_oid: SignatureOid = "UNKNOWN"
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"


def snapshot_findings(snapshot: HostSnapshot, approval_id: str, system_id: str):
    """Receipts enter the chain; only cert/config facts enter the crypto CBOM."""
    sha = digest(snapshot)
    result = []
    for item, receipt in zip(snapshot.manifest.inputs, snapshot.receipts):
        common = dict(
            snapshot_sha256=sha,
            approval_id=approval_id,
            system_id=system_id,
            host_id=snapshot.manifest.host_id,
            environment=snapshot.manifest.environment,
            input_id=item.input_id,
            receipt_status=receipt.status,
            receipt_reason=receipt.reason,
            observed_at=snapshot.finished_at.isoformat(),
        )
        for ordinal, fact in [(-1, None), *enumerate(receipt.facts)]:
            if fact and fact.kind not in {"CERTIFICATE", "TLS_CONFIGURATION"}:
                continue
            reference = HostEvidenceRef(
                **common,
                local_basis=fact.local_basis if fact else "UNKNOWN",
                fact_ordinal=ordinal,
                fact_kind=fact.kind if fact else "RECEIPT",
                configured_protocols=",".join(fact.protocols) if fact else "",
                configured_cipher_suites=",".join(fact.cipher_suites) if fact else "",
                signature_hash=fact.signature_hash if fact else "UNKNOWN",
                certificate_signature_oid=fact.certificate_signature_oid if fact else "UNKNOWN",
                curve=fact.curve if fact else "UNKNOWN",
                fingerprint_sha256=fact.fingerprint_sha256 if fact and fact.fingerprint_sha256 else "UNKNOWN",
            )
            finding = {
                "scanner_id": "host-snapshot-import-v1",
                "scanner_version": "1.0",
                "finding_type": "HOST_CRYPTO_METADATA" if fact else "HOST_COLLECTION_RECEIPT",
                "source": {"type": "HOST_SNAPSHOT_IMPORT", "file_path": item.path, "line_number": 0},
                "crypto": {
                    "algorithm": fact.algorithm if fact else "UNKNOWN",
                    "key_size": fact.key_size if fact else None,
                    "mode": "UNKNOWN",
                    "purpose": fact.purpose if fact else "COLLECTION_RECEIPT",
                },
                "metadata": {"confidence": "LOW"},
                "host_evidence": reference.model_dump(mode="json"),
            }
            if fact and fact.fingerprint_sha256:
                finding["inventory"] = {"fingerprint_sha256": fact.fingerprint_sha256}
            result.append(finding)
    return result
