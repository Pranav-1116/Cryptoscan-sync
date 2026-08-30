"""ZELNX Cloud Discovery Engine — provider adapters.

Adapters are the *only* I/O boundary of the engine.  Each adapter exposes
injected enumerator callables returning **raw rows**; the engine normalizes
them.  Live SDK discovery is never implied — adapters for real clouds are
built from explicit credentials/roles and fail-open with recorded errors,
exactly like the rest of ``cloud_scanner``.

Adapter keys:

- ``enumerate_accounts``       §1  org/account rows
- ``enumerate_regions``        §1  region rows for an account
- ``enumerate_workloads``      §2  compute workloads
- ``enumerate_keys``           §3  crypto key metadata
- ``enumerate_certificates``   §4  certificate metadata
- ``enumerate_relations``      §4  explicit certificate graph edges
- ``enumerate_cas``            §5  CA rows
- ``enumerate_encryption``     §6  storage/database encryption rows
- ``enumerate_tls``            §7  TLS termination profiles
- ``enumerate_ipsec``          §7  IPsec/IKE profiles
- ``enumerate_tunnels``        §7  tunnel relationships
- ``enumerate_tls_endpoints``  §8  TLS endpoint rows
- ``enumerate_clusters``       §9  Kubernetes clusters
- ``enumerate_serverless``     §10 serverless functions
- ``enumerate_secrets``        §11 secret/key references
- ``enumerate_access``         §12 IAM access bindings
- ``enumerate_cross_cloud``    §14 cross-cloud relationships
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

Enumerator = Callable[[], list[dict[str, Any]]]


@dataclass
class ProviderAdapter:
    """One cloud provider's injected discovery surface."""

    provider: str
    enumerate_accounts: Enumerator | None = None
    enumerate_regions: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None
    enumerate_workloads: Enumerator | None = None
    enumerate_keys: Enumerator | None = None
    enumerate_certificates: Enumerator | None = None
    enumerate_relations: Enumerator | None = None
    enumerate_cas: Enumerator | None = None
    enumerate_encryption: Enumerator | None = None
    enumerate_tls: Enumerator | None = None
    enumerate_ipsec: Enumerator | None = None
    enumerate_tunnels: Enumerator | None = None
    enumerate_tls_endpoints: Enumerator | None = None
    enumerate_clusters: Enumerator | None = None
    enumerate_serverless: Enumerator | None = None
    enumerate_secrets: Enumerator | None = None
    enumerate_access: Enumerator | None = None
    enumerate_cross_cloud: Enumerator | None = None

    def to_provider_entry(self) -> dict[str, Any]:
        """Convert to the dict shape the discovery modules consume."""
        return {
            "provider": self.provider,
            "enumerate_accounts": self.enumerate_accounts,
            "enumerate_regions": self.enumerate_regions,
            "enumerate_workloads": self.enumerate_workloads,
            "enumerate_keys": self.enumerate_keys,
            "enumerate_certificates": self.enumerate_certificates,
            "enumerate_relations": self.enumerate_relations,
            "enumerate_cas": self.enumerate_cas,
            "enumerate_encryption": self.enumerate_encryption,
            "enumerate_tls": self.enumerate_tls,
            "enumerate_ipsec": self.enumerate_ipsec,
            "enumerate_tunnels": self.enumerate_tunnels,
            "enumerate_tls_endpoints": self.enumerate_tls_endpoints,
            "enumerate_clusters": self.enumerate_clusters,
            "enumerate_serverless": self.enumerate_serverless,
            "enumerate_secrets": self.enumerate_secrets,
            "enumerate_access": self.enumerate_access,
            "enumerate_cross_cloud": self.enumerate_cross_cloud,
        }


def fake_provider(provider: str, rows: dict[str, list[dict[str, Any]]],
                  *, accounts: list[dict[str, Any]] | None = None,
                  region_rows: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
                  ) -> ProviderAdapter:
    """Build an adapter from static rows — the unit-test fast path."""
    return ProviderAdapter(
        provider=provider,
        enumerate_accounts=(
            (lambda: {"accounts": accounts or [], "truncated": False, "errors": []})
            if accounts is not None
            else (lambda: {"accounts": [], "truncated": False, "errors": []})
        ),
        enumerate_regions=region_rows or (lambda account: []),
        enumerate_workloads=_static(rows.get("workloads")),
        enumerate_keys=_static(rows.get("keys")),
        enumerate_certificates=_static(rows.get("certificates")),
        enumerate_relations=_static(rows.get("relations")),
        enumerate_cas=_static(rows.get("cas")),
        enumerate_encryption=_static(rows.get("encryption")),
        enumerate_tls=_static(rows.get("tls_profiles")),
        enumerate_ipsec=_static(rows.get("ipsec_profiles")),
        enumerate_tunnels=_static(rows.get("tunnels")),
        enumerate_tls_endpoints=_static(rows.get("tls_endpoints")),
        enumerate_clusters=_static(rows.get("clusters")),
        enumerate_serverless=_static(rows.get("serverless")),
        enumerate_secrets=_static(rows.get("secrets")),
        enumerate_access=_static(rows.get("access")),
        enumerate_cross_cloud=_static(rows.get("cross_cloud")),
    )


def _static(rows: list[dict[str, Any]] | None) -> Enumerator | None:
    if rows is None:
        return None
    return lambda: list(rows)
