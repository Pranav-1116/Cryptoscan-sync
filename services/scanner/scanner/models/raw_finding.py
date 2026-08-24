"""RawFinding model for scanner output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Any

from pydantic import BaseModel, Field


class GitContext(BaseModel):
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_timestamp: Optional[str] = None  # ISO-8601 string
    branch: Optional[str] = None
    repository_url: Optional[str] = None
    commit_message: Optional[str] = None


class SourceLocation(BaseModel):
    type: str = "SOURCE_CODE"
    language: str = "JAVA"
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    code_snippet: Optional[str] = None
    variable_name: Optional[str] = None
    is_in_try_catch: bool = False


class CryptoInfo(BaseModel):
    api_type: str
    algorithm: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    key_size: Optional[int] = None
    purpose: Optional[str] = None
    raw_transformation: Optional[str] = None


class FindingMetadata(BaseModel):
    confidence: str
    confidence_reason: str
    library: Optional[str] = None
    is_hardcoded_key: bool = False
    hardcoded_key_length: Optional[int] = None


class RawFinding(BaseModel):
    """Scanner output model - one per cryptographic API call detected."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scanner_id: str = "static-java-scanner-v0.1"
    scanner_version: str = "0.1.0"

    source: SourceLocation
    crypto: CryptoInfo
    metadata: FindingMetadata
    git_context: Optional[GitContext] = None

    def to_canonical_dict(self) -> dict[str, Any]:
        """
        Produce canonical dict for hashing (sorted keys, no runtime metadata).
        """
        raw = self.model_dump(
            exclude={"finding_id", "scan_timestamp"},
            mode="json",
        )
        return _sort_dict_recursively(raw)

    def to_canonical_json(self) -> str:
        """Produce canonical JSON string (UTF-8, no whitespace, sorted keys)."""
        return json.dumps(
            self.to_canonical_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )


def _sort_dict_recursively(obj: Any) -> Any:
    """Recursively sort all dictionary keys alphabetically."""
    if isinstance(obj, dict):
        return {k: _sort_dict_recursively(v) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_sort_dict_recursively(item) for item in obj]
    return obj