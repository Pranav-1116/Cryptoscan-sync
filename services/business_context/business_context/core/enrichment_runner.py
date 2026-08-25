"""Run business-context enrichment after each scan."""

from __future__ import annotations

from typing import Any, Iterable

from business_context.core.enricher import enrich_assets


def run_enrichment(
    assets: Iterable[dict[str, Any]],
    *,
    systems: Iterable[dict[str, Any]] = (),
    edges: Iterable[dict[str, Any]] = (),
    processes: Iterable[dict[str, Any]] = (),
    owners: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    return enrich_assets(assets, systems=systems, edges=edges, processes=processes, owners=owners)
