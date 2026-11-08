"""Artifact identity (§1/§11): SHA-256 is the immutable identity.

An existing artifact is NEVER overwritten with a different digest —
a changed artifact is a NEW artifact version. The original bytes are
kept separate from extracted metadata, and every scan run links back to
the artifact's digest.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from binary_intelligence.formats import BinaryFormat, identify_format

#: §14: resource exhaustion controls — bounded artifact size by default.
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024   # 256 MiB default ceiling


@dataclass(frozen=True)
class ArtifactIdentity:
    artifact_id: str
    tenant_id: str
    sha256: str
    file_size: int
    detected_format: BinaryFormat
    format_reason: str
    original_filename: str
    source_type: str
    source_location: Optional[str]
    uploaded_by: str
    received_at: datetime

    def as_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "tenant_id": self.tenant_id,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "detected_format": self.detected_format.value,
            "format_reason": self.format_reason,
            "original_filename": self.original_filename,
            "source_type": self.source_type,
            "source_location": self.source_location,
            "uploaded_by": self.uploaded_by,
            "received_at": self.received_at,
        }


def artifact_identity(*, tenant_id: str, data: bytes,
                      original_filename: str, source_type: str,
                      uploaded_by: str,
                      source_location: Optional[str] = None,
                      received_at: Optional[datetime] = None,
                      max_bytes: int = MAX_ARTIFACT_BYTES
                      ) -> ArtifactIdentity:
    """Compute the immutable identity. The content decides the format;
    the size limit is enforced BEFORE hashing; the digest is the
    identity — a different digest is a different artifact, never an
    overwrite of this one."""
    if len(data) > max_bytes:
        raise ValueError(
            f"artifact is {len(data)} bytes, above the {max_bytes}-byte "
            "limit — resource limits are a security control (§14), not "
            "a suggestion")
    if not data:
        raise ValueError("an empty file has no identity to establish")
    digest = hashlib.sha256(data).hexdigest()
    fmt, reason = identify_format(data)
    import re as _re
    safe_name = _re.sub(r"[^A-Za-z0-9._-]", "_", original_filename)[:120]
    return ArtifactIdentity(
        artifact_id=f"bin-{digest[:16]}",
        tenant_id=tenant_id,
        sha256=digest,
        file_size=len(data),
        detected_format=fmt,
        format_reason=reason,
        original_filename=safe_name,
        source_type=source_type,
        source_location=source_location,
        uploaded_by=uploaded_by,
        received_at=received_at or datetime.now(timezone.utc),
    )
