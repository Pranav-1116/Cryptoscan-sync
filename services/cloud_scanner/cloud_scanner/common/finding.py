"""Normalize cloud / IaC observations into evidence-shaped findings."""

from __future__ import annotations

import uuid
from typing import Any


def cloud_finding(
    *,
    source_type: str,
    resource: str,
    algorithm: str | None,
    purpose: str,
    file_path: str,
    line_number: int = 1,
    provider: str = "AWS",
    issue: str | None = None,
    extra: dict[str, Any] | None = None,
    key_size: int | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    # Algorithm registry enrichment: resource findings carry key sizes too
    # (AES-256 -> 256 bits, DES -> 56, 3DES -> 168) even when the cloud API
    # did not report one.
    try:
        from shared_models.algorithm_registry import infer_key_size

        if key_size is None:
            key_size = infer_key_size(algorithm)
    except Exception:
        pass

    finding_id = str(uuid.uuid4())
    return {
        "finding_id": finding_id,
        "scanner_id": "cloud-config-scanner-v1.0",
        "algorithm": algorithm or "NONE",
        "key_size": key_size,
        "mode": mode,
        "purpose": purpose,
        "file_path": file_path,
        "line_number": line_number,
        "confidence": "HIGH",
        "compliance_issue": issue,
        "source": {
            "type": source_type,
            "file_path": file_path,
            "line_number": line_number,
            "language": "HCL" if file_path.endswith(".tf") else "YAML",
        },
        "crypto": {
            "algorithm": algorithm or "NONE",
            "key_size": key_size,
            "mode": mode,
            "purpose": purpose,
            "raw_transformation": resource,
        },
        "metadata": {
            "confidence": "HIGH",
            "library": provider.lower(),
            "cloud_provider": provider,
            "resource": resource,
            "scan_method": "IAC",
            **(extra or {}),
        },
    }
