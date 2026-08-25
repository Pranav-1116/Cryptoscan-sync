"""Poll service mesh telemetry on a schedule."""

from __future__ import annotations

from typing import Any

from graph_engine.service_mesh.istio_client import fetch_istio_calls, parse_prometheus_result
from graph_engine.service_mesh.service_call_extractor import extract_calls


def poll_mesh(prometheus_url: str | None = None, *, raw: Any = None) -> list[dict[str, Any]]:
    if raw is not None:
        if isinstance(raw, dict) and isinstance(raw.get("data"), dict):
            return extract_calls(parse_prometheus_result(raw))
        rows = raw if isinstance(raw, list) else [raw]
        return extract_calls(rows)
    if not prometheus_url:
        return []
    return fetch_istio_calls(prometheus_url)
