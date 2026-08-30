"""ZELNX Cloud Discovery Engine — full cloud asset inventory (spec §2).

Discovers compute workloads across all three clouds with their full identity
context (owner, runtime, network, crypto usage, certificate usage, key
dependencies) and normalizes them into one ``Workload`` model:

Compute
- AWS:        EC2, ECS, EKS, Lambda, Elastic Beanstalk
- Azure:      Virtual Machines, AKS, Functions, Container Apps, App Service
- GCP:        Compute Engine, GKE, Cloud Run, Cloud Functions, App Engine

The workload inventory powers the dependency graph (RUNS_ON), the CBOM and
the posture engine.  All I/O is injected via provider adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import Workload

WorkloadEnumerator = Callable[[], list[dict[str, Any]]]

COMPUTE_TYPES = {
    "aws": ("ec2", "ecs", "eks", "lambda", "elastic_beanstalk"),
    "azure": ("vm", "aks", "functions", "container_apps", "app_service"),
    "gcp": ("compute_engine", "gke", "cloud_run", "cloud_functions", "app_engine"),
}


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


def normalize_workload(row: dict[str, Any], *, provider: str) -> Workload:
    """Normalize one raw provider workload row into the shared model."""
    account = str(_pick(row, "account", "account_id", "subscription", "subscription_id",
                        "project", "project_id", default="") or "")
    workload_id = str(_pick(row, "workload_id", "id", "name", "resource_id", default="") or "")
    return Workload(
        workload_id=workload_id,
        cloud_provider=provider,
        account=account,
        subscription=str(_pick(row, "subscription", "subscription_id", default=account) or ""),
        project=str(_pick(row, "project", "project_id", default=account) or ""),
        region=str(_pick(row, "region", default="") or ""),
        zone=str(_pick(row, "zone", default="") or ""),
        environment=str(_pick(row, "environment", default="") or ""),
        network=str(_pick(row, "network", "vpc", "vnet", default="") or ""),
        application=str(_pick(row, "application", default="") or ""),
        owner=str(_pick(row, "owner", default="") or ""),
        runtime=str(_pick(row, "runtime", default="") or ""),
        os=str(_pick(row, "os", "operating_system", default="") or ""),
        container=str(_pick(row, "container", "image", default="") or ""),
        crypto_usage=[str(item) for item in (_pick(row, "crypto_usage", default=[]) or [])],
        certificate_usage=[str(item) for item in (_pick(row, "certificate_usage", default=[]) or [])],
        key_dependencies=[str(item) for item in (_pick(row, "key_dependencies", default=[]) or [])],
        metadata=dict(_pick(row, "metadata", default={}) or {}),
    )


@dataclass
class AssetInventory:
    """Normalized multi-cloud workload inventory."""

    workloads: list[Workload] = field(default_factory=list)
    truncated: bool = False
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [workload.to_dict() for workload in self.workloads]

    def by_provider(self, provider: str) -> list[Workload]:
        return [w for w in self.workloads if w.cloud_provider == provider]

    def count(self, provider: str | None = None) -> int:
        return len(self.by_provider(provider)) if provider else len(self.workloads)

    def summary(self) -> dict[str, Any]:
        from collections import Counter

        by_provider: Counter[str] = Counter()
        by_type: Counter[str] = Counter()
        for workload in self.workloads:
            by_provider[workload.cloud_provider] += 1
            by_type[workload.cloud_provider + "/" + str(workload.metadata.get("compute_type", "unknown"))] += 1
        return {
            "workloads": len(self.workloads),
            "by_provider": dict(by_provider),
            "by_compute_type": dict(by_type),
            "truncated": self.truncated,
            "errors": self.errors,
        }


class AssetInventoryBuilder:
    """Run the workload inventory for a set of injected provider adapters.

    Adapter shape: ``{"provider": "aws", "enumerate_workloads": fn}`` where
    ``enumerate_workloads()`` returns raw rows per compute service; each row
    is normalized via :func:`normalize_workload`.
    """

    def __init__(self, providers: list[dict[str, Any]], *, max_workloads: int = 2000) -> None:
        self._providers = list(providers)
        self._max_workloads = max_workloads

    def discover(self) -> AssetInventory:
        inventory = AssetInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_workloads")
            if enumerator is None:
                inventory.errors.append(
                    {"provider": provider, "kind": "no_enumerator",
                     "detail": "no enumerate_workloads callable injected"}
                )
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if len(inventory.workloads) >= self._max_workloads:
                    inventory.truncated = True
                    break
                workload = normalize_workload(row if isinstance(row, dict) else {"workload_id": str(row)},
                                              provider=provider)
                inventory.workloads.append(workload)
        return inventory
