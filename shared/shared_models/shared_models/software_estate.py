"""Closed multi-asset denominator and signed source reconciliation, not omniscient discovery."""

from datetime import datetime
from typing import Literal
import hashlib
from pydantic import Field, model_validator, field_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Token, Digest
from shared_models.collection import offset_time
from shared_models.collector_identity import decode
from shared_models.tpm_quote_verification import canonical, sha

Surface = Literal[
    "os_packages", "language_dependencies", "unpackaged_binaries", "loaded_code", "container_images", "firmware"
]
SURFACES = {
    "os_packages",
    "language_dependencies",
    "unpackaged_binaries",
    "loaded_code",
    "container_images",
    "firmware",
}


class EstateAsset(Strict):
    asset_id: Token
    platform: Literal["linux", "windows", "container", "application", "appliance"]
    producer_public_key: str = Field(min_length=44, max_length=44)

    @field_validator("producer_public_key")
    @classmethod
    def key(cls, value):
        decode(value, 32)
        return value


class EstateAssetRegister(Strict):
    estate_id: Token
    register_reference: Token
    assets: list[EstateAsset] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def unique(self):
        if len({a.asset_id for a in self.assets}) != len(self.assets):
            raise ValueError("Duplicate asset")
        return self


class SoftwareRecord(Strict):
    identity: Token
    version: Token | None
    content_sha256: Digest | None


class EstateSurfaceScope(Strict):
    asset_id: Token
    surface: Surface
    expected_records: list[SoftwareRecord] = Field(max_length=1000)
    expected_source_sha256: Digest
    applicability: Literal["REQUIRED", "NOT_APPLICABLE"] = "REQUIRED"
    scope_reason: Token

    @model_validator(mode="after")
    def scope(self):
        if (self.applicability == "REQUIRED") != bool(self.expected_records):
            raise ValueError("Required scope needs expected records; N/A must not hide records")
        return self


class SoftwareEstatePlan(Strict):
    schema_version: Literal["cryptoscan.software-estate-plan/v1"] = "cryptoscan.software-estate-plan/v1"
    asset_register: EstateAssetRegister
    asset_register_sha256: Digest
    release_sha256: Digest
    reviewer_reference: Token
    not_before: datetime
    expires_at: datetime
    scopes: list[EstateSurfaceScope] = Field(min_length=6, max_length=120)

    @field_validator("not_before", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return offset_time(value)

    @model_validator(mode="after")
    def denominator(self):
        expected = {(a.asset_id, s) for a in self.asset_register.assets for s in SURFACES}
        actual = [(s.asset_id, s.surface) for s in self.scopes]
        if (
            sha(self.asset_register) != self.asset_register_sha256
            or len(set(actual)) != len(actual)
            or set(actual) != expected
            or not self.not_before < self.expires_at
            or sum(len(s.expected_records) for s in self.scopes) > 20000
        ):
            raise ValueError("Exact registered assets x six surfaces, release and ordered window required")
        for a in self.asset_register.assets:
            if not any(s.asset_id == a.asset_id and s.applicability == "REQUIRED" for s in self.scopes):
                raise ValueError("All-N/A assets cannot qualify")
        return self


class EstateSurfaceStatement(Strict):
    plan_sha256: Digest
    release_sha256: Digest
    asset_id: Token
    surface: Surface
    source_sha256: Digest
    captured_at: datetime
    status: Literal["MEASURED", "DECLARED_ONLY", "UNAVAILABLE", "FAILED"]
    records: list[SoftwareRecord] = Field(max_length=1000)

    @field_validator("captured_at", mode="before")
    @classmethod
    def aware(cls, value):
        return offset_time(value)

    @model_validator(mode="after")
    def nonempty_measured(self):
        if (self.status == "MEASURED") != bool(self.records):
            raise ValueError("Nonempty measured records required; failure is not absence")
        return self


class SignedEstateSurface(Strict):
    statement: EstateSurfaceStatement
    signature: str = Field(min_length=88, max_length=88)


class SoftwareEstatePacket(Strict):
    schema_version: Literal["cryptoscan.software-estate-packet/v1"] = "cryptoscan.software-estate-packet/v1"
    returns: list[SignedEstateSurface] = Field(max_length=120)


def reconcile_estate(plan, packet, artifacts, now):
    """Original artifact bytes plus approved producer signatures; never infer hidden scope."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    from collections import Counter

    now = offset_time(now)
    if not plan.not_before <= now < plan.expires_at:
        raise ValueError("Estate plan not current")
    if len(artifacts) > 120 or sum(len(v) for v in artifacts.values()) > 16 * 1024 * 1024:
        raise ValueError("Artifact budget")
    for digest, data in artifacts.items():
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 2 * 1024 * 1024
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise ValueError("Original software source missing, changed or oversized")
    returned = {}
    assets = {a.asset_id: a for a in plan.asset_register.assets}
    scopes = {(s.asset_id, s.surface): s for s in plan.scopes}
    for proof in packet.returns:
        s = proof.statement
        k = (s.asset_id, s.surface)
        if (
            k in returned
            or k not in scopes
            or s.plan_sha256 != sha(plan)
            or s.release_sha256 != plan.release_sha256
            or not plan.not_before <= s.captured_at <= now
            or s.source_sha256 not in artifacts
        ):
            raise ValueError("Return outside exact asset/surface/plan/release/source/window")
        try:
            Ed25519PublicKey.from_public_bytes(decode(assets[s.asset_id].producer_public_key, 32)).verify(
                decode(proof.signature, 64), canonical(s)
            )
        except InvalidSignature:
            raise ValueError("Unapproved software producer signature") from None
        returned[k] = s
    if set(artifacts) != {s.source_sha256 for s in returned.values()}:
        raise ValueError("Unreferenced source artifacts refused")
    rows = []
    counter = lambda records: Counter((r.identity, r.version, r.content_sha256) for r in records)
    for key, scope in sorted(scopes.items()):
        actual = returned.get(key)
        if scope.applicability == "NOT_APPLICABLE":
            if actual is not None:
                raise ValueError("Unexpected return for pre-reviewed N/A scope")
            status = "PRE_REVIEWED_NOT_APPLICABLE"
            matched = False
        else:
            comparable = (
                actual is not None
                and actual.status == "MEASURED"
                and actual.source_sha256 == scope.expected_source_sha256
            )
            matched = comparable and counter(actual.records) == counter(scope.expected_records)
            status = "MATCHED_SIGNED_RECORD_SET" if matched else "UNMEASURED_OR_MISMATCHED"
        rows.append(
            {
                "asset_id": key[0],
                "surface": key[1],
                "applicability": scope.applicability,
                "status": status,
                "expected_records": len(scope.expected_records),
                "observed_records": len(actual.records) if actual and actual.status == "MEASURED" else None,
                "record_set_matched": bool(matched),
            }
        )
    required = [r for r in rows if r["applicability"] == "REQUIRED"]
    complete = all(r["record_set_matched"] for r in required)
    return {
        "schema_version": "cryptoscan.software-estate-reconciliation/v1",
        "plan_sha256": sha(plan),
        "packet_sha256": sha(packet),
        "asset_register_sha256": plan.asset_register_sha256,
        "registered_assets": len(assets),
        "total_surface_units": len(rows),
        "required_units": len(required),
        "matched_units": sum(r["record_set_matched"] for r in required),
        "pre_reviewed_not_applicable_units": len(rows) - len(required),
        "agreed_register_record_sets_matched": complete,
        "verdict": "MATCHED_AGREED_SIGNED_REGISTER" if complete else "BLOCKED_ESTATE_COVERAGE_GAPS",
        "units": rows,
        "source_basis": "IMPORTED_SIGNED_CLAIMS",
        "original_source_hashes_verified": True,
        "producer_measurement_truth_independently_verified": False,
        "asset_register_authoritativeness_verified": False,
        "whole_estate_software_complete": False,
        "production_execution_qualified": False,
        "materialized_without_collection": True,
    }
