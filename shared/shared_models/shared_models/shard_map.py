"""Tenant → shard mapping for a sharded deployment.

Every row in this product already carries ``tenant_id`` (the RLS axis); a
sharded deployment puts each tenant's data on exactly one shard, and this
map is the single place that decides which. Two backends, one precedence:

* **Directory** — an explicit tenant→shard entry (config or control-plane
  row). A directory entry is authoritative: this is how a tenant MOVED
  between shards keeps reading from its new home. The map never silently
  rehashes a tenant that has a directory entry.
* **Hash fallback** — tenants with no entry land on a stable hash ring
  (``md5(tenant)`` across ``hash_buckets`` virtual buckets assigned to
  shards). Deterministic: the same tenant resolves to the same shard on
  every process, forever, as long as the shard list and bucket count hold
  still.

Honest boundaries — the map moves NOTHING:

* Resharding is a copy → verify → cutover → directory-entry operation
  performed by operators and drills; this module only guarantees that
  after the directory entry lands, every process resolves the tenant to
  its new shard immediately (config reload / restart semantics are the
  deployment's).
* Changing ``hash_buckets`` WOULD rehash fallback tenants — the config
  names it (``hash_buckets`` in ``as_dict()``) and the module refuses to
  pretend otherwise. Move tenants through the directory, not by rehashing.
* A platform-estate tenant (``None`` — the RLS ``NULL`` axis) resolves to
  the named platform shard, never hashed: the platform's own rows are not
  a lottery ticket.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Optional

DEFAULT_HASH_BUCKETS = 256
PLATFORM_SHARD = "platform"


class ShardMap:
    """Directory-first, hash-fallback tenant→shard resolution."""

    def __init__(self, shards: Iterable[str], *,
                 directory: Optional[dict[str, str]] = None,
                 hash_buckets: int = DEFAULT_HASH_BUCKETS,
                 platform_shard: str = PLATFORM_SHARD) -> None:
        shards = sorted(set(shards))
        if not shards:
            raise ValueError("a shard map names at least one shard — an "
                             "empty map is a black hole, not a deployment")
        if hash_buckets <= 0:
            raise ValueError("hash_buckets is positive")
        unknown = {s for s in (directory or {}).values() if s not in shards}
        if unknown:
            raise ValueError(
                f"directory entries name unknown shards: {sorted(unknown)} — "
                "a mapping to a shard that does not exist is worse than none")
        self.shards = shards
        self.directory = dict(directory or {})
        self.hash_buckets = hash_buckets
        self.platform_shard = platform_shard

    def resolve(self, tenant_id: Optional[str]) -> str:
        """The one shard this tenant lives on. None (platform estate) goes
        to the platform shard; a directory entry wins; everyone else lands
        on the stable hash ring."""
        if tenant_id is None:
            return self.platform_shard
        tenant_id = str(tenant_id)
        if tenant_id in self.directory:
            return self.directory[tenant_id]
        return self._hash_shard(tenant_id)

    def move(self, tenant_id: str, shard: str) -> None:
        """Record a resharding cutover: from now on, every process resolves
        this tenant to ``shard``. The map moves no data — the copy and the
        verification are the operator's, and this entry is the cutover."""
        if shard not in self.shards:
            raise ValueError(
                f"cannot move to unknown shard {shard!r} — known: {self.shards}")
        self.directory[str(tenant_id)] = shard

    def tenants_on(self, shard: str) -> list[str]:
        return sorted(t for t, s in self.directory.items() if s == shard)

    def _hash_shard(self, tenant_id: str) -> str:
        digest = hashlib.md5(tenant_id.encode("utf-8")).hexdigest()
        bucket = int(digest, 16) % self.hash_buckets
        return self.shards[bucket % len(self.shards)]

    def as_dict(self) -> dict:
        return {
            "shards": list(self.shards),
            "directory_entries": len(self.directory),
            "hash_buckets": self.hash_buckets,
            "platform_shard": self.platform_shard,
            "note": ("directory-first, stable hash fallback — a moved tenant "
                     "stays moved (the directory is the cutover) and the map "
                     "itself never moves data; changing hash_buckets WOULD "
                     "rehash fallback tenants, so resharding goes through "
                     "move(), never through a config edit"),
        }
