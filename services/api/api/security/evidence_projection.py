"""Response-only projection for historical evidence containing raw detector text."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from shared_models.safe_finding import safe_finding


def project_finding(data: Any) -> tuple[dict[str, Any], bool]:
    """Return safe JSON and whether it differs from the original commitment.

    Never modify ORM JSON: content/chain hashes refer to the original stored
    finding, not this response view.
    """
    original = data if isinstance(data, Mapping) else {}
    projected = safe_finding(original)
    return projected, projected != data


def public_evidence_row(row: Any) -> dict[str, Any]:
    data = row.to_dict()
    data["finding_data"], data["redacted_projection"] = project_finding(
        data.get("finding_data")
    )
    return data
