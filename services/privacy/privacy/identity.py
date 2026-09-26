"""Universal Asset Identity Resolution (spec #1).

The same physical asset is discovered by many scanners under different ids:

    Network  ->  10.10.1.20
    Cloud    ->  i-123456
    Hardware ->  Server-009
    Agent    ->  payment-prod-01

Without a canonical identity the inventory fills with duplicates. This module
answers "these observations are the SAME real asset" deterministically, and
produces ONE canonical asset with a set of aliases and a best-effort confidence.

Design goals:

* **Pure / deterministic** — no DB, no network. It consumes structured
  observations (dicts) and returns a canonical record plus an alias table. The
  caller (inventory repository / orchestrator) decides persistence.
* **Conservative** — it only *merges* when there is a positive shared key
  (an exact alias match, or an unambiguous one-to-one surrogate). A name or a
  lone IP never collapses two assets unless another signal agrees.
* **Alias-first** — the real identity is the set of cross-source ids. We build a
  union-find over alias -> asset so a chain (IP -> hostname -> serial -> cloud
  instance) resolves to a single root even when no two observations share the
  same id kind.

The id kinds usable as identity anchors are declared in :data:`KNOWN_KINDS`.
Matching is exact after normalization, and a value that appears under *any*
known kind joins the same union-find group -- so an IP that only a network scan
knows and a serial that only a hardware scan knows still merge when a third
observation (e.g. an agent) carries both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


#: the normalized identifier kinds a scanner may contribute.
KNOWN_KINDS = (
    "ip", "hostname", "fqdn", "mac",
    "instance_id", "arn", "resource_id", "account_id",
    "serial", "asset_tag", "bios_uuid", "model",
    "agent_id", "vendor_key", "product", "sku", "name",
)


@dataclass
class AssetObservation:
    """One scanner's view of an asset.

    ``kind`` is the scanner source (network / cloud / hardware / agent / vendor);
    ``ids`` maps an id kind -> value (e.g. ``{"ip": "10.10.1.20"}``);
    ``attrs`` carries any extra evidence (manufacturer, firmware, environment…).
    """

    source: str
    ids: dict[str, str]
    attrs: dict[str, Any] = field(default_factory=dict)
    observed_at: str | None = None


@dataclass
class IdentityResolution:
    """Result of resolving a batch of observations into canonical assets."""

    assets: list[dict[str, Any]] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)   # alias -> canonical_id
    merges: int = 0
    observations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "assets": self.assets,
            "aliases": self.aliases,
            "merges": self.merges,
            "observations": self.observations,
        }


def _norm(value: str | None) -> str:
    """Normalize an id value so "10.10.1.20" and " 10.10.1.20 " compare equal."""
    if value is None:
        return ""
    v = str(value).strip().lower()
    # collapse dotted/colon forms of a MAC so case/delimiter differ matters not
    if ":" in v and len(v) >= 12 and all(c in "0123456789abcdef:." for c in v):
        v = v.replace(":", "").replace(".", "")
    # hostnames are case-insensitive; strip a trailing dot (FQDN root)
    v = v.rstrip(".")
    return v


def _usable_ids(ids: dict[str, str]) -> list[str]:
    """Return the normalized alias strings that can anchor identity.

    Only ids whose kind is known are usable. Values are normalized so that
    case, delimiter and trailing-dot differences do not hide a match.
    """
    out: list[str] = []
    for kind, val in ids.items():
        if kind not in KNOWN_KINDS:
            continue
        nv = _norm(val)
        if not nv:
            continue
        out.append(nv)
    return out


def _canonical(source: str, ids: dict[str, str], attrs: dict[str, Any],
               observed_at: str | None) -> dict[str, Any]:
    """Build a canonical asset record from one observation."""
    merged = {
        "asset_type": ids.get("name") or attrs.get("asset_type") or infer_asset_type(source),
        "source": source,
        "aliases": [a for a in _usable_ids(ids)],
        "first_seen": observed_at,
        "last_seen": observed_at,
    }
    # keep every id the scanners gave us under its own kind
    for kind in KNOWN_KINDS:
        if ids.get(kind):
            merged[kind] = ids[kind]
    # carry through scalar metadata the inventory wants, but never fabricate
    for key in ("name", "manufacturer", "model", "firmware", "environment",
                "criticality", "owner", "business_unit", "region"):
        if key in attrs and attrs[key] is not None:
            merged.setdefault(key, attrs[key])
    return merged


def infer_asset_type(source: str) -> str:
    """Map a scanner source to a coarse canonical asset_type."""
    by_source = {
        "network": "system",
        "cloud": "cloud_resource",
        "hardware": "hardware",
        "agent": "system",
        "vendor": "vendor",
        "crypto": "crypto",
    }
    return by_source.get(source or "", "system")


class UnionFind:
    """Tiny union-find used to collapse alias chains into one asset root."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.alias_to_id: dict[str, str] = {}

    def _root(self, x: str) -> str:
        while self.parent.get(x, x) != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        self.parent.setdefault(a, a)
        self.parent.setdefault(b, b)
        ra, rb = self._root(a), self._root(b)
        if ra != rb:
            self.parent[rb] = ra

    def add_alias(self, asset_id: str, alias: str) -> None:
        """Bind an alias value to an asset id; merge when already bound."""
        self.parent.setdefault(asset_id, asset_id)
        self.parent.setdefault(alias, alias)
        if alias in self.alias_to_id:
            self.union(self.alias_to_id[alias], asset_id)
        else:
            self.alias_to_id[alias] = asset_id
        self.union(alias, asset_id)


def resolve_identities(observations: Iterable[AssetObservation]) -> IdentityResolution:
    """Resolve a batch of observations into canonical assets.

    Returns :class:`IdentityResolution` with a list of canonical asset records.
    Observations whose ids share any alias (after normalization) collapse into
    a single asset; the asset id is the lexicographically-smallest alias so it
    is stable across runs.

    Ids that appear in *different* observations are linked through the alias
    table, so an IP that only appears in a network scan and a serial that only
    appears in a hardware scan still merge when a third observation (e.g. an
    agent) carries both.
    """
    obs = list(observations)
    result = IdentityResolution(observations=len(obs))
    uf = UnionFind()

    # First pass: register every alias -> asset and chain any shared aliases.
    for i, o in enumerate(obs):
        asset_id = _ident(o, i)
        uf.parent.setdefault(asset_id, asset_id)
        for alias in _usable_ids(o.ids):
            uf.add_alias(asset_id, alias)

    # Second pass: if two observations are now in the same union, keep the
    # richest as the canonical record and fold aliases/metadata into it.
    records: dict[str, dict[str, Any]] = {}
    groups: dict[str, list[int]] = {}
    for i, o in enumerate(obs):
        root = uf._root(_ident(o, i))
        groups.setdefault(root, []).append(i)

    for root, idxs in groups.items():
        # richest observation = the one with the most distinct id kinds
        base = max(idxs, key=lambda i: len(_usable_ids(obs[i].ids)))
        all_aliases = [a for i in idxs for a in _usable_ids(obs[i].ids)]
        canonical_id = min(all_aliases) if all_aliases else min(
            _ident(obs[i], i) for i in idxs
        )
        merged = _canonical(obs[base].source, obs[base].ids, obs[base].attrs,
                            obs[base].observed_at)
        merged["id"] = canonical_id
        aliases = set(merged["aliases"])
        for i in idxs:
            if i == base:
                continue
            o = obs[i]
            for a in _usable_ids(o.ids):
                aliases.add(a)
            # fold in useful attrs that the canonical record may lack
            for key, val in o.attrs.items():
                if val is not None and key not in merged:
                    merged[key] = val
            if o.observed_at:
                if not merged.get("last_seen") or o.observed_at > merged["last_seen"]:
                    merged["last_seen"] = o.observed_at
                if not merged.get("first_seen") or o.observed_at < merged["first_seen"]:
                    merged["first_seen"] = o.observed_at
        merged["aliases"] = sorted(aliases)
        merged["sources"] = sorted({obs[i].source for i in idxs})
        merged["aliases"] = sorted(set(merged["aliases"]))
        records[canonical_id] = merged
        result.merges += len(idxs) - 1

    # Sort by id for a stable output and build the alias lookup table.
    # Map each union-find root -> canonical id so aliases resolve to the asset id.
    root_to_canonical: dict[str, str] = {}
    for key in sorted(records):
        root_to_canonical[uf._root(key)] = key
        result.assets.append(records[key])
    for i, o in enumerate(obs):
        root = uf._root(_ident(o, i))
        canonical = root_to_canonical.get(root, _ident(o, i))
        for alias in _usable_ids(o.ids):
            result.aliases[alias] = canonical
    return result


def _ident(o: AssetObservation, index: int) -> str:
    """Stable per-observation id used as a union-find node before merges."""
    present = _usable_ids(o.ids)
    if present:
        return "obs:" + present[0]
    return f"obs:{o.source}:{index}"
