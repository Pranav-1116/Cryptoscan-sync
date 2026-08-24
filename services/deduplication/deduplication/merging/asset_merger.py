"""Merge raw findings into crypto assets."""

from __future__ import annotations

from typing import Any

from deduplication.core.engine import DeduplicationEngine


def merge_assets(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return DeduplicationEngine().merge(findings)
