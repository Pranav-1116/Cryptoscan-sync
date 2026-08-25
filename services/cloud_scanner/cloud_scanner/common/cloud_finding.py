"""Dataclass wrapper around the shared cloud_finding() helper."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.common.finding import cloud_finding


@dataclass
class CloudFinding:
    source_type: str
    resource: str
    purpose: str
    file_path: str
    algorithm: str | None = None
    line_number: int = 1
    provider: str = "AWS"
    issue: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    key_size: int | None = None
    mode: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return cloud_finding(
            source_type=self.source_type,
            resource=self.resource,
            algorithm=self.algorithm,
            purpose=self.purpose,
            file_path=self.file_path,
            line_number=self.line_number,
            provider=self.provider,
            issue=self.issue,
            extra=self.extra or None,
            key_size=self.key_size,
            mode=self.mode,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CloudFinding":
        metadata = data.get("metadata") or {}
        crypto = data.get("crypto") or {}
        source = data.get("source") or {}
        extra = {key: value for key, value in metadata.items() if key not in {"confidence", "library", "cloud_provider", "resource", "scan_method"}}
        return cls(
            source_type=str(source.get("type") or data.get("source_type") or "CLOUD"),
            resource=str(metadata.get("resource") or crypto.get("raw_transformation") or data.get("resource") or ""),
            purpose=str(data.get("purpose") or crypto.get("purpose") or "UNKNOWN"),
            file_path=str(data.get("file_path") or source.get("file_path") or ""),
            algorithm=data.get("algorithm") or crypto.get("algorithm"),
            line_number=int(data.get("line_number") or source.get("line_number") or 1),
            provider=str(metadata.get("cloud_provider") or data.get("provider") or "AWS"),
            issue=data.get("compliance_issue") or data.get("issue"),
            extra=extra,
            key_size=data.get("key_size") if data.get("key_size") is not None else crypto.get("key_size"),
            mode=data.get("mode") or crypto.get("mode"),
        )
