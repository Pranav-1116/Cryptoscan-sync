"""
NormalizedCrypto output model — the canonical representation
of a cryptographic finding after normalization.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class NormalizedCrypto(BaseModel):
    """
    Canonical normalized representation of a cryptographic asset.
    Produced by the normalization engine from raw scanner output.
    Conforms to CycloneDX CBOM 1.5 structure.
    """

    # ── Core Identification ──────────────────────────────────────────
    algorithm: str = Field(
        ...,
        description="Canonical algorithm name (e.g., AES, RSA, SHA2)",
        examples=["AES", "RSA", "SHA2", "DES", "ECDSA"],
    )
    algorithm_family: str = Field(
        ...,
        description="Algorithm family classification",
        examples=["symmetric", "asymmetric", "hash", "kdf", "mac", "signature"],
    )
    standard_name: str = Field(
        ...,
        description="Full standard designation",
        examples=["AES-256-GCM", "RSA-2048", "SHA-256"],
    )

    # ── Parameters ───────────────────────────────────────────────────
    mode: Optional[str] = Field(
        None,
        description="Mode of operation (e.g., GCM, CBC, ECB). Null if N/A.",
        examples=["GCM", "CBC", "ECB", "CTR", "CCM"],
    )
    padding: Optional[str] = Field(
        None,
        description="Padding scheme. Null if N/A.",
        examples=["PKCS5Padding", "PKCS1Padding", "NoPadding", "OAEPWithSHA-256"],
    )
    key_size: Optional[int] = Field(
        None,
        ge=1,
        description="Key size in bits. Null if not applicable or not determinable.",
        examples=[128, 192, 256, 1024, 2048, 4096],
    )
    iv_size: Optional[int] = Field(
        None,
        ge=1,
        description="IV/nonce size in bits. Null if N/A.",
        examples=[96, 128],
    )
    tag_size: Optional[int] = Field(
        None,
        ge=1,
        description="Authentication tag size in bits (AEAD modes). Null if N/A.",
        examples=[128, 96, 64],
    )
    output_bits: Optional[int] = Field(
        None,
        ge=1,
        description="Output size in bits (hash functions). Null if N/A.",
        examples=[256, 384, 512, 160],
    )

    # ── Purpose ──────────────────────────────────────────────────────
    purpose: Optional[str] = Field(
        None,
        description="Cryptographic purpose inferred from API context.",
        examples=["encryption", "decryption", "hashing", "signing", "key-exchange", "key-generation"],
    )

    # ── Standards Mapping ────────────────────────────────────────────
    iana_id: Optional[str] = Field(
        None,
        description="IANA algorithm registry identifier.",
        examples=["aes256-gcm", "rsa-oaep", "sha-256"],
    )
    nist_designation: Optional[str] = Field(
        None,
        description="NIST approval status per SP 800-131A Rev 2.",
        examples=["APPROVED", "ACCEPTABLE", "DEPRECATED", "DISALLOWED"],
    )
    nist_reference: Optional[str] = Field(
        None,
        description="NIST standard reference.",
        examples=["FIPS 197", "FIPS 186-4", "FIPS 180-4", "SP 800-56A"],
    )
    fips_status: Optional[str] = Field(
        None,
        description="FIPS compliance status.",
        examples=["FIPS-197", "FIPS-186-4", "NON-FIPS"],
    )
    quantum_vulnerable: bool = Field(
        False,
        description="True if algorithm is vulnerable to Grover/Shor quantum attacks.",
    )
    pqc_replacement: Optional[str] = Field(
        None,
        description="Recommended post-quantum replacement algorithm.",
        examples=["ML-KEM-768", "ML-DSA-65", "SLH-DSA"],
    )

    # ── CBOM Integration ─────────────────────────────────────────────
    cbom_component_type: str = Field(
        default="cryptographic-asset",
        description="CycloneDX CBOM component type.",
    )
    cbom_algorithm_ref: Optional[str] = Field(
        None,
        description="CycloneDX CBOM URN reference.",
        examples=["urn:ietf:crypto:aes:gcm:256", "urn:ietf:crypto:rsa:2048"],
    )

    # ── Normalization Metadata ────────────────────────────────────────
    normalization_confidence: str = Field(
        ...,
        description="Confidence level of normalization result.",
        examples=["HIGH", "MEDIUM", "LOW"],
    )
    normalization_version: str = Field(
        default="1.0",
        description="Version of normalization rules applied.",
    )
    normalization_timestamp: Optional[str] = Field(
        None,
        description="ISO-8601 timestamp when normalization was performed.",
    )
    raw_input: str = Field(
        ...,
        description="Original raw algorithm string from scanner output.",
        examples=["AES/GCM/NoPadding", "SHA256withRSA", "DES"],
    )
    needs_human_review: bool = Field(
        default=False,
        description="True if algorithm could not be confidently normalized.",
    )
    review_reason: Optional[str] = Field(
        None,
        description="Reason why human review is required.",
    )

    @field_validator("algorithm_family")
    @classmethod
    def validate_algorithm_family(cls, v: str) -> str:
        allowed = {
            "symmetric", "asymmetric", "hash", "kdf",
            "mac", "signature", "key-agreement", "unknown",
        }
        if v not in allowed:
            raise ValueError(f"algorithm_family must be one of {allowed}, got '{v}'")
        return v

    @field_validator("normalization_confidence")
    @classmethod
    def validate_confidence(cls, v: str) -> str:
        allowed = {"HIGH", "MEDIUM", "LOW"}
        if v not in allowed:
            raise ValueError(f"normalization_confidence must be one of {allowed}")
        return v

    @field_validator("nist_designation")
    @classmethod
    def validate_nist_designation(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"APPROVED", "ACCEPTABLE", "DEPRECATED", "DISALLOWED", "UNKNOWN"}
        if v not in allowed:
            raise ValueError(f"nist_designation must be one of {allowed}")
        return v

    def is_approved(self) -> bool:
        """Return True if NIST designation is APPROVED."""
        return self.nist_designation == "APPROVED"

    def is_deprecated_or_disallowed(self) -> bool:
        """Return True if algorithm is deprecated or disallowed."""
        return self.nist_designation in {"DEPRECATED", "DISALLOWED"}

    def compliance_summary(self) -> dict:
        """Return a compact compliance summary for API responses."""
        return {
            "algorithm": self.algorithm,
            "standard_name": self.standard_name,
            "nist_designation": self.nist_designation,
            "quantum_vulnerable": self.quantum_vulnerable,
            "needs_human_review": self.needs_human_review,
            "normalization_confidence": self.normalization_confidence,
        }

    model_config = {
        "json_schema_extra": {
            "example": {
                "algorithm": "AES",
                "algorithm_family": "symmetric",
                "standard_name": "AES-256-GCM",
                "mode": "GCM",
                "padding": "NoPadding",
                "key_size": 256,
                "iv_size": 96,
                "tag_size": 128,
                "output_bits": None,
                "purpose": "encryption",
                "iana_id": "aes256-gcm",
                "nist_designation": "APPROVED",
                "nist_reference": "FIPS 197",
                "fips_status": "FIPS-197",
                "quantum_vulnerable": False,
                "pqc_replacement": None,
                "cbom_component_type": "cryptographic-asset",
                "cbom_algorithm_ref": "urn:ietf:crypto:aes:gcm:256",
                "normalization_confidence": "HIGH",
                "normalization_version": "1.0",
                "normalization_timestamp": "2024-01-15T10:00:00Z",
                "raw_input": "AES/GCM/NoPadding",
                "needs_human_review": False,
                "review_reason": None,
            }
        }
    }