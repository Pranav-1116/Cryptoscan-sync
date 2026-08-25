"""Multi-region scan coordination."""

from __future__ import annotations

from typing import Any

from cloud_scanner.aws.live import scan_aws


def scan_regions(
    regions: list[str] | None = None,
    *,
    session: Any | None = None,
) -> list[dict[str, Any]]:
    return scan_aws(regions=regions, session=session)
