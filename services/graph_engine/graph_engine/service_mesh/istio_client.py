"""Pull Istio request totals from Prometheus and turn them into CALLS edges."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode
from urllib.request import urlopen

logger = logging.getLogger(__name__)


def fetch_istio_calls(prometheus_url: str, *, timeout: float = 5.0) -> list[dict[str, Any]]:
    if not prometheus_url:
        return []
    base = prometheus_url.rstrip("/")
    query = "sum by (source_workload, destination_workload) (istio_requests_total)"
    url = f"{base}/api/v1/query?{urlencode({'query': query})}"
    try:
        with urlopen(url, timeout=timeout) as response:  # noqa: S310 — operator-configured URL
            raw = response.read().decode("utf-8")
    except Exception:
        logger.warning("istio_prometheus_unreachable", extra={"url": base})
        return []
    try:
        import json

        body = json.loads(raw)
    except Exception:
        logger.warning("istio_prometheus_invalid_json")
        return []
    return parse_prometheus_result(body)


def parse_prometheus_result(body: dict[str, Any]) -> list[dict[str, Any]]:
    result = ((body.get("data") or {}).get("result")) or []
    edges: list[dict[str, Any]] = []
    for item in result:
        metric = item.get("metric") or {}
        source = metric.get("source_workload") or metric.get("source")
        dest = metric.get("destination_workload") or metric.get("destination")
        value = item.get("value") or [None, "0"]
        try:
            frequency = int(float(value[1]))
        except (TypeError, ValueError, IndexError):
            frequency = 0
        if source and dest and source != dest:
            edges.append(
                {
                    "parent_id": source,
                    "child_id": dest,
                    "protocol": "istio",
                    "frequency": frequency,
                    "relation": "CALLS",
                    "data_source": "istio-telemetry",
                }
            )
    return edges
