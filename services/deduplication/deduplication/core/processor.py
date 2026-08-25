"""Process one evidence record through the deduplication engine."""

from __future__ import annotations

from typing import Any

from deduplication.core.engine import DeduplicationEngine
from deduplication.merging.asset_creator import create_asset
from deduplication.merging.asset_merger import merge_assets


def process_record(record: dict[str, Any], existing: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    findings = list(existing or [])
    findings.append(record)
    return DeduplicationEngine().merge(findings)


def process_new(record: dict[str, Any]) -> dict[str, Any]:
    return create_asset(record)


def process_batch(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return merge_assets(records)
