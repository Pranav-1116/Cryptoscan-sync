"""Query Istio metrics (Prometheus) for service-to-service TLS metadata."""

from __future__ import annotations

from typing import Any

try:
    from graph_engine.service_mesh.istio_client import fetch_istio_calls, parse_prometheus_result
except Exception:  # pragma: no cover - graph engine optional at import time

    def fetch_istio_calls(prometheus_url: str, *, timeout: float = 5.0) -> list[dict[str, Any]]:
        return []

    def parse_prometheus_result(body: dict[str, Any]) -> list[dict[str, Any]]:
        return []


__all__ = ["fetch_istio_calls", "parse_prometheus_result"]
