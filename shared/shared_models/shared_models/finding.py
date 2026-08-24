"""Canonical RawFinding model — scanner output and evidence input."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from shared_models.enums import ApiType, Confidence, Purpose


class GitContext(BaseModel):
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_timestamp: Optional[str] = None
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
    api_type: str = ApiType.UNKNOWN.value
    algorithm: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    key_size: Optional[int] = None
    purpose: Optional[str] = Purpose.UNKNOWN.value
    raw_transformation: Optional[str] = None


class FindingMetadata(BaseModel):
    confidence: str = Confidence.LOW.value
    confidence_reason: str = ""
    library: Optional[str] = None
    is_hardcoded_key: bool = False
    hardcoded_key_length: Optional[int] = None


class RawFinding(BaseModel):
    model_config = {"extra": "allow"}

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

    @model_validator(mode="before")
    @classmethod
    def _accept_flat_constructor(cls, data):
        if not isinstance(data, dict):
            return data
        if "source" in data or "crypto" in data:
            return data
        if "file_path" not in data and "algorithm" not in data:
            return data
        return {
            "source": {
                "file_path": data.get("file_path") or "unknown",
                "line_number": int(data.get("line_number") or 0),
                "class_name": data.get("class_name"),
                "method_name": data.get("method_name"),
                "code_snippet": data.get("code_snippet"),
            },
            "crypto": {
                "api_type": data.get("api_type") or "UNKNOWN",
                "algorithm": data.get("algorithm"),
                "mode": data.get("mode"),
                "padding": data.get("padding"),
                "key_size": data.get("key_size"),
                "purpose": data.get("purpose"),
                "raw_transformation": data.get("raw_transformation"),
            },
            "metadata": {
                "confidence": data.get("confidence") or "LOW",
                "confidence_reason": data.get("confidence_reason") or "flat-constructor",
                "is_hardcoded_key": bool(data.get("is_hardcoded_key")),
                "library": data.get("library"),
            },
            **{k: v for k, v in data.items() if k in {"finding_id", "scan_timestamp", "scanner_id", "scanner_version", "git_context"}},
        }

    def to_canonical_dict(self) -> dict[str, Any]:
        raw = self.model_dump(exclude={"finding_id", "scan_timestamp"}, mode="json")
        return _sort_dict_recursively(raw)

    def to_canonical_json(self) -> str:
        return json.dumps(
            self.to_canonical_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )


def _sort_dict_recursively(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_dict_recursively(v) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_sort_dict_recursively(item) for item in obj]
    return obj
