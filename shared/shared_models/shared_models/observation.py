"""Canonical CryptoObservation — every scanner normalizes to this shape."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class CryptoObservation(BaseModel):
    """Sector-neutral observation. Policy and CBOM consume this, not regex groups."""

    observation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: Optional[str] = None
    scan_id: Optional[str] = None
    source_type: str = "SOURCE_CODE"
    source_id: Optional[str] = None
    asset_hint: Optional[str] = None
    location: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    collector: str = "static-java-scanner"
    collector_version: str = "1.0.0"
    raw_evidence_reference: Optional[str] = None
    crypto_algorithm: Optional[str] = None
    algorithm_family: Optional[str] = None
    key_size: Optional[int] = None
    curve: Optional[str] = None
    hash_function: Optional[str] = None
    protocol: Optional[str] = None
    certificate_metadata: Optional[dict[str, Any]] = None
    library_metadata: Optional[dict[str, Any]] = None
    provider: Optional[str] = None
    usage: Optional[str] = None
    operation: Optional[str] = None
    environment: Optional[str] = None
    cloud_provider: Optional[str] = None
    region: Optional[str] = None
    account_or_subscription: Optional[str] = None
    confidence: str = "LOW"
    evidence_quality: str = "STATIC"
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def observation_from_raw_finding(finding: Any, *, scan_id: str | None = None) -> CryptoObservation:
    """Map a scanner RawFinding (object or dict) onto the canonical contract."""
    if hasattr(finding, "model_dump"):
        data = finding.model_dump()
    elif isinstance(finding, dict):
        data = finding
    else:
        data = {}
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    crypto = data.get("crypto") if isinstance(data.get("crypto"), dict) else {}
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    file_path = source.get("file_path") or data.get("file_path") or ""
    line = source.get("line_number") or data.get("line_number") or 0
    algorithm = crypto.get("algorithm") or data.get("algorithm")
    return CryptoObservation(
        observation_id=str(data.get("finding_id") or uuid.uuid4()),
        scan_id=scan_id,
        source_type=source.get("type") or "SOURCE_CODE",
        source_id=file_path,
        asset_hint=algorithm,
        location=f"{file_path}:{line}",
        timestamp=str(data.get("scan_timestamp") or datetime.now(timezone.utc).isoformat()),
        collector=str(data.get("scanner_id") or "static-java-scanner"),
        collector_version=str(data.get("scanner_version") or "1.0.0"),
        raw_evidence_reference=str(data.get("finding_id") or "") or None,
        crypto_algorithm=algorithm,
        algorithm_family=algorithm,
        key_size=crypto.get("key_size") if crypto.get("key_size") is not None else data.get("key_size"),
        hash_function=crypto.get("mode") if (crypto.get("purpose") or "") == "HASHING" else None,
        protocol=crypto.get("algorithm") if "TLS" in str(crypto.get("algorithm") or "") else None,
        library_metadata={"library": meta.get("library") or crypto.get("library")},
        provider=meta.get("library"),
        usage=crypto.get("purpose") or data.get("purpose"),
        operation=crypto.get("api_type") or data.get("api_type"),
        confidence=str(meta.get("confidence") or data.get("confidence") or "LOW"),
        evidence_quality="STATIC",
        metadata={
            "mode": crypto.get("mode"),
            "padding": crypto.get("padding"),
            "raw_transformation": crypto.get("raw_transformation"),
            "class_name": source.get("class_name"),
            "method_name": source.get("method_name"),
            "is_hardcoded_key": bool(meta.get("is_hardcoded_key")),
        },
    )
