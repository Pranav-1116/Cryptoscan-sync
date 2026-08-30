"""ZELNX Cloud Discovery Engine — multi-cloud account discovery (spec §1).

Builds the estate tree from injectable provider enumerators:

    Organization
       ├── Business Unit
       │      └── Cloud Account / Subscription / Project
       └── Region
              └── Resources

- AWS:        Organizations → management/member accounts, OUs, regions,
              partitions
- Azure:      tenant → management groups → subscriptions → resource groups
              → regions
- GCP:        organization → folders → projects → regions and zones

Providers are injected as callables returning account rows, so unit tests
need no cloud SDKs (same contract as ``cloud_scanner.org.enumerators``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import CloudAccount, CloudRegion

AccountEnumerator = Callable[[], dict[str, Any]]  # {"accounts": [...], "truncated": bool, "errors": [...]}
RegionEnumerator = Callable[[dict[str, Any]], list[dict[str, Any]]]  # account -> region rows


def _attr(item: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(item, dict) and item.get(name) is not None:
            return item[name]
        if hasattr(item, name):
            value = getattr(item, name)
            if value is not None:
                return value
    return default


@dataclass
class OrganizationNode:
    """A node in the organization tree."""

    node_id: str
    kind: str  # organization | business_unit | account | region
    name: str = ""
    provider: str = ""
    parent_id: str = ""
    children: list["OrganizationNode"] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "name": self.name,
            "provider": self.provider,
            "parent_id": self.parent_id,
            "attributes": dict(self.attributes),
            "children": [child.to_dict() for child in self.children],
        }


@dataclass
class OrgHierarchy:
    """The full multi-cloud estate tree + discovery telemetry."""

    roots: list[OrganizationNode] = field(default_factory=list)
    accounts: list[CloudAccount] = field(default_factory=list)
    truncated: bool = False
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "roots": [root.to_dict() for root in self.roots],
            "accounts": [account.to_dict() for account in self.accounts],
            "account_count": len(self.accounts),
            "truncated": self.truncated,
            "errors": list(self.errors),
        }

    @property
    def account_count(self) -> int:
        return len(self.accounts)

    def accounts_for(self, provider: str | None = None) -> list[CloudAccount]:
        if provider is None:
            return list(self.accounts)
        return [account for account in self.accounts if account.provider == provider]

    def tree(self) -> dict[str, Any]:
        """Compact tree: provider -> business unit -> account list."""
        tree: dict[str, dict[str, list[str]]] = {}
        for account in self.accounts:
            branch = tree.setdefault(account.provider, {})
            unit = account.org_path[-1] if account.org_path else ""
            branch.setdefault(unit, []).append(account.account_id)
        return tree


class OrgHierarchyBuilder:
    """Build the estate tree from provider enumerators.

    Each provider entry is ``{"provider": str, "enumerate_accounts": fn,
    "enumerate_regions": fn | None, "organization": name, "partition": str}``.
    All discovery is injected; failures are recorded, never fatal.
    """

    def __init__(self, providers: list[dict[str, Any]], *, max_accounts: int = 500) -> None:
        self._providers = list(providers)
        self._max_accounts = max_accounts

    def discover(self) -> OrgHierarchy:
        hierarchy = OrgHierarchy()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerate_accounts = entry.get("enumerate_accounts")
            enumerate_regions = entry.get("enumerate_regions")
            org_name = str(entry.get("organization") or f"{provider}-organization")
            partition = str(entry.get("partition") or "public")
            if enumerate_accounts is None:
                hierarchy.errors.append(
                    {"provider": provider, "kind": "no_enumerator",
                     "detail": "no enumerate_accounts callable injected"}
                )
                continue
            try:
                result = enumerate_accounts() or {}
            except Exception as exc:  # noqa: BLE001 — enumeration never crashes a scan
                hierarchy.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            hierarchy.truncated = hierarchy.truncated or bool(result.get("truncated"))
            for exc in result.get("errors") or []:
                hierarchy.errors.append({"provider": provider, "kind": "account", "detail": str(exc)[:300]})
            root = OrganizationNode(
                node_id=f"{provider}-org://{org_name}",
                kind="organization",
                name=org_name,
                provider=provider,
                attributes={"partition": partition, "management_account": result.get("management_account")},
            )
            hierarchy.roots.append(root)
            count = 0
            for row in result.get("accounts") or []:
                if count >= self._max_accounts:
                    hierarchy.truncated = True
                    break
                count += 1
                account = self._account(row, provider=provider, org_name=org_name,
                                        partition=partition, root=root)
                if enumerate_regions is not None:
                    try:
                        account.regions = [self._region(r) for r in (enumerate_regions(account) or [])]
                    except Exception as exc:  # noqa: BLE001
                        hierarchy.errors.append(
                            {"provider": provider, "account": account.account_id,
                             "kind": "regions", "detail": str(exc)[:300]}
                        )
                hierarchy.accounts.append(account)
        return hierarchy

    # ------------------------------------------------------------------

    def _account(self, row: dict[str, Any], *, provider: str, org_name: str,
                 partition: str, root: OrganizationNode) -> CloudAccount:
        account_id = str(_attr(row, "account_id", "id", "subscription_id", "project_id", default="") or "")
        name = str(_attr(row, "name", "display_name", default=account_id) or account_id)
        org_path = [str(part) for part in (_attr(row, "org_path", default=[]) or [])]
        status = str(_attr(row, "status", default="ACTIVE") or "ACTIVE")
        metadata = dict(_attr(row, "metadata", default={}) or {})
        metadata.setdefault("partition", partition)
        metadata.setdefault("organization", org_name)
        if _attr(row, "email"):
            metadata["email"] = _attr(row, "email")
        account = CloudAccount(
            provider=provider,
            account_id=account_id,
            name=name,
            org_path=[org_name, *org_path],
            status=status,
            metadata=metadata,
        )
        # attach a business-unit node under the root when org_path present
        if org_path:
            bu_name = org_path[-1]
            child = next(
                (c for c in root.children if c.node_id == f"{provider}-bu://{bu_name}"),
                None,
            )
            if child is None:
                child = OrganizationNode(
                    node_id=f"{provider}-bu://{bu_name}", kind="business_unit",
                    name=bu_name, provider=provider, parent_id=root.node_id,
                )
                root.children.append(child)
        return account

    @staticmethod
    def _region(row: dict[str, Any]) -> CloudRegion:
        return CloudRegion(
            name=str(_attr(row, "name", "region", default="") or ""),
            zones=[str(z) for z in (_attr(row, "zones", default=[]) or [])],
            resource_count=int(_attr(row, "resource_count", default=0) or 0),
        )


def default_region_rows(provider: str, names: list[str]) -> list[dict[str, Any]]:
    """Standard region rows for tests / static region tables."""
    zone_suffix = {"aws": ("a", "b", "c"), "azure": ("1", "2", "3"), "gcp": ("a", "b", "c")}
    suffixes = zone_suffix.get(provider, ("a",))
    return [
        {"name": name, "zones": [f"{name}{s}" for s in suffixes], "resource_count": 0}
        for name in names
    ]
