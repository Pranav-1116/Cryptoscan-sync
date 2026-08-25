"""Istio / mesh endpoint discovery from YAML or Prometheus."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from network_scanner.discovery.kubernetes_discoverer import discover_from_tree
from network_scanner.passive.istio_telemetry_client import fetch_istio_calls


def discover_mesh_endpoints(root: str | Path | None = None, *, prometheus_url: str | None = None) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    if root:
        endpoints.extend(discover_from_tree(Path(root)))
    if prometheus_url:
        for edge in fetch_istio_calls(prometheus_url):
            dest = edge.get("child_id")
            if dest:
                endpoints.append({"endpoint": f"{dest}:443", "system_id": dest, "source": "istio"})
    return endpoints
