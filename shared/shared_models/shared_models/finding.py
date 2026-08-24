"""RawFinding model - output of the static scanner."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, Field, field_validator

from shared_models.enums import ApiType, Confidence, Purpose


class GitContext(BaseModel):
    """Git repository context for a finding."""
    commit_hash: Optional[str] = Field(None, description="Full commit SHA")
    commit_author: Optional[str] = Field(None, description="Author username")
    commit_timestamp: Optional[datetime] = Field(None, description="Commit time")
    branch: Optional[str] = Field(None, description="Branch name")
    repository_url: Optional[str] = Field(None, description="Repository clone URL")
    commit_message: Optional[str] = Field(None, description="Commit message")

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


class SourceLocation(BaseModel):
    """Location of a finding within source code."""
    type: str = Field("SOURCE_CODE", description="Location type")
    language: str = Field("JAVA", description="Programming language")
    file_path: str = Field(..., description="File path relative to repo root")
    line_number: int = Field(..., ge=1, description="1-indexed line number")
    column_number: Optional[int] = Field(None, ge=0, description="0-indexed column")
    method_name: Optional[str] = Field(None, description="Containing method name")
    class_name: Optional[str] = Field(None, description="Fully qualified class name")
    code_snippet: Optional[str] = Field(None, description="±5 lines around finding")
    variable_name: Optional[str] = Field(None, description="Variable storing the result")
    is_in_try_catch: bool = Field(False, description="Whether wrapped in try/catch")


class CryptoInfo(BaseModel):
    """Cryptographic details extracted from the finding."""
    api_type: ApiType = Field(..., description="Type of crypto API called")
    algorithm: Optional[str] = Field(None, description="Algorithm name (e.g., AES, RSA)")
    mode: Optional[str] = Field(None, description="Mode of operation (e.g., GCM, CBC)")
    padding: Optional[str] = Field(None, description="Padding scheme")
    key_size: Optional[int] = Field(None, description="Key size in bits")
    purpose: Optional[Purpose] = Field(None, description="Inferred crypto purpose")
    raw_transformation: Optional[str] = Field(
        None, description="Raw transformation string (e.g., AES/GCM/NoPadding)"
    )


class FindingMetadata(BaseModel):
    """Metadata about the detection quality."""
    confidence: Confidence = Field(..., description="Detection confidence level")
    confidence_reason: str = Field(..., description="Explanation of confidence level")
    library: Optional[str] = Field(None, description="Java crypto library used")
    is_hardcoded_key: bool = Field(False, description="Whether a hardcoded key was detected")
    hardcoded_key_length: Optional[int] = Field(
        None, description="Length of hardcoded key bytes (NOT the key value)"
    )


class RawFinding(BaseModel):
    """
    A single cryptographic finding from the static scanner.
    
    This is the canonical output format of the scanner engine.
    All fields must be present for HIGH confidence findings.
    """
    # Identity
    finding_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique finding identifier (UUID v4)"
    )
    scan_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this finding was created (ISO-8601)"
    )
    scanner_id: str = Field(
        "static-java-scanner-v0.1",
        description="Identifier of the scanner that produced this finding"
    )
    scanner_version: str = Field(
        "0.1.0",
        description="Version of the scanner"
    )

    # Location
    source: SourceLocation = Field(..., description="Where the crypto call was found")

    # Crypto details
    crypto: CryptoInfo = Field(..., description="What crypto was found")

    # Quality metadata
    metadata: FindingMetadata = Field(..., description="Detection quality information")

    # Git context (populated when scanning a Git repository)
    git_context: Optional[GitContext] = Field(None, description="Git context if available")

    model_config = {
        "json_encoders": {datetime: lambda v: v.isoformat()},
        "use_enum_values": True,
    }

    @field_validator("finding_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        """Ensure finding_id is a valid UUID."""
        try:
            uuid.UUID(v, version=4)
        except ValueError:
            raise ValueError(f"finding_id must be a valid UUID v4, got: {v}")
        return v

    def to_canonical_dict(self) -> dict[str, Any]:
        """
        Produce a canonical dictionary for hashing.
        
        Excludes: finding_id, scan_timestamp (runtime metadata)
        Sorts: all keys alphabetically at every nesting level
        """
        raw = self.model_dump(
            exclude={"finding_id", "scan_timestamp"},
            mode="json",
        )
        return self._sort_dict_recursively(raw)

    def _sort_dict_recursively(self, obj: Any) -> Any:
        """Recursively sort dictionary keys."""
        if isinstance(obj, dict):
            return {k: self._sort_dict_recursively(v) for k in sorted(obj.keys())}
        if isinstance(obj, list):
            return [self._sort_dict_recursively(item) for item in obj]
        return obj