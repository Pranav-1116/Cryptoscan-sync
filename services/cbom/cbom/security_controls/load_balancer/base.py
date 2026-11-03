"""Load balancers: VIPs, pools, backends, TLS termination and the certificates presented.

A load balancer is where the estate most often learns three things at once: which public
name resolves to which pool, whether TLS terminates or re-encrypts, and which certificate
and cipher profile the client actually meets. The collector reads all three. It does not
drain a member, add a pool node or rebalance anything.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, DeviceCollector

CONTROL = "LOAD_BALANCER"

COLLECTS: tuple[str, ...] = (
    "vips", "pools", "backend_mappings", "tls_termination", "certificates",
    "cipher_suites", "protocol_profiles",
)
MUST_NOT: tuple[str, ...] = (
    "add_or_drain_a_pool_member", "rebalance_traffic", "change_a_cipher_profile",
    "replace_a_certificate", "read_session_persistence_cookies",
)


class LoadBalancerCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def vips(self) -> list[dict[str, Any]]:
        return [{"vip": self._field(raw, "vip") or self._field(raw, "name"),
                 "address": self._field(raw, "address"),
                 "port": self._field(raw, "port"),
                 "pool": self._field(raw, "pool"),
                 "tls": str(self._field(raw, "tls") or "TERMINATE").upper(),
                 "certificate": self._field(raw, "certificate"),
                 "protocol": str(self._field(raw, "protocol") or "https").lower(),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("VIP", index, raw)}
                for index, raw in enumerate(self._section_rows("vips"), start=1)]

    def pools(self) -> list[dict[str, Any]]:
        pools: list[dict[str, Any]] = []
        for index, raw in enumerate(self._section_rows("pools"), start=1):
            members = self._field(raw, "members") or []
            pools.append({
                "pool": self._field(raw, "pool") or self._field(raw, "name"),
                "members": [str(member) for member in members],
                "monitor": self._field(raw, "monitor"),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("POOL", index, raw),
            })
        return pools

    def backends(self) -> list[dict[str, Any]]:
        """VIP → pool → member, flattened, each hop carrying the evidence that states it."""
        by_pool = {pool["pool"]: pool for pool in self.pools()}
        rows: list[dict[str, Any]] = []
        for vip in self.vips():
            pool = by_pool.get(vip["pool"])
            for member in (pool or {}).get("members", []) or [None]:
                rows.append({
                    "vip": vip["vip"],
                    "pool": vip["pool"],
                    "backend": member,
                    "evidence_ids": [vip["evidence_id"]]
                    + ([pool["evidence_id"]] if pool else []),
                    "fact": CONFIGURED,
                })
        return rows

    def tls_profiles(self) -> list[dict[str, Any]]:
        return [{"profile": self._field(raw, "profile") or self._field(raw, "name"),
                 "tls_version": self._field(raw, "tls_version"),
                 "cipher_suites": list(self._field(raw, "cipher_suites") or []),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("TLS_PROFILE", index, raw)}
                for index, raw in enumerate(self._section_rows("tls_profiles"), start=1)]


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> LoadBalancerCollector:
    from .vendors import spec_for

    return LoadBalancerCollector(spec_for(vendor), feed)
