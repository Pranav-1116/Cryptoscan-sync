"""Read the latest stored estate discovery back into a graph — no HTTP layer.

The API routes rebuild the twin from the newest ``estate_discovery`` run; the CLI
needs the same thing without FastAPI's 404 semantics. Returning ``None`` rather than
raising keeps the distinction the twin cares about at the call site: *no observation
yet* is ``NOT_OBSERVED``, which is not the same as *an estate with nothing in it*.
"""

from __future__ import annotations

from typing import Any

from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant
from shared_models.estate_graph import build_graph

#: the scan-run ``target_kind`` an estate discovery writes
RUN_KIND = "estate-discovery"


def latest_twin_graph(session: Any, tenant: str | None = None) -> Any | None:
    """The newest stored discovery as an ``EstateGraph``, or ``None`` if none ran."""
    runs = ScanRunRepository(session).list_runs(
        limit=1, target_kind=RUN_KIND, owner=tenant or current_tenant()
    )
    if not runs:
        return None
    return build_graph((runs[0].result or {}).get("estate_discovery") or {})


__all__ = ["RUN_KIND", "latest_twin_graph"]
