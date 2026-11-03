"""VPN: tunnels, IKE, encryption, DH group, PFS and the certificates — read, never rekeyed.

Every field here is cryptographic and every one of them is metadata. The collector records
what a tunnel negotiates so the estate can answer "which tunnels depend on a 1024-bit DH
group" or "which peers still offer 3DES". It never brings a tunnel up or down, never rotates a
pre-shared key (and never reads one: ``psk`` is a prohibited field, redacted by name).
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, DeviceCollector

CONTROL = "VPN"

#: vendors say "1", "ikev1", "IKEv1"; the estate has two versions and no opinions
IKE_VERSIONS: dict[str, str] = {
    "1": "IKEV1", "IKEV1": "IKEV1", "V1": "IKEV1", "IKEV1_ONLY": "IKEV1",
    "2": "IKEV2", "IKEV2": "IKEV2", "V2": "IKEV2",
}

COLLECTS: tuple[str, ...] = (
    "tunnels", "ike_version", "encryption_algorithms", "hash_algorithms", "dh_group",
    "pfs", "certificates", "peers",
)
MUST_NOT: tuple[str, ...] = (
    "bring_a_tunnel_up_or_down", "rotate_or_read_a_preshared_key",
    "change_a_proposal", "decrypt_tunnel_traffic",
)


class VpnCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def tunnels(self) -> list[dict[str, Any]]:
        tunnels: list[dict[str, Any]] = []
        for index, raw in enumerate(self._section_rows("tunnels"), start=1):
            tunnels.append({
                "tunnel": self._field(raw, "tunnel") or self._field(raw, "name"),
                "peer": self._field(raw, "peer"),
                "local": self._field(raw, "local"),
                "ike_version": IKE_VERSIONS.get(
                    _norm_ike(self._field(raw, "ike_version")) or "IKEV2", "UNKNOWN"),
                "encryption": [str(item).upper() for item in
                               (self._field(raw, "encryption") or [])],
                "hash": [str(item).upper() for item in (self._field(raw, "hash") or [])],
                "dh_group": self._field(raw, "dh_group"),
                "pfs": bool(self._field(raw, "pfs", True)),
                "certificate": self._field(raw, "certificate"),
                "state": str(self._field(raw, "state") or "UP").upper(),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("TUNNEL", index, raw),
            })
        return tunnels

    def weak_crypto(self) -> list[dict[str, Any]]:
        """Tunnels whose declared crypto is below the estate's floor — a finding, not a fix."""
        weak: list[dict[str, Any]] = []
        for tunnel in self.tunnels():
            reasons: list[str] = []
            if tunnel["ike_version"] == "IKEV1":
                reasons.append("IKEv1")
            if any(algorithm in {"DES", "3DES", "RC4", "MD5"} for algorithm in
                   [*tunnel["encryption"], *tunnel["hash"]]):
                reasons.append("legacy-algorithm")
            if str(tunnel["dh_group"] or "") in {"1", "2", "1024", "MODP1024", "GROUP2"}:
                reasons.append("dh-group-1024")
            if not tunnel["pfs"]:
                reasons.append("no-pfs")
            if reasons:
                weak.append({"tunnel": tunnel["tunnel"], "reasons": reasons,
                             "evidence_id": tunnel["evidence_id"], "fact": CONFIGURED})
        return weak


def _norm_ike(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", "").replace(" ", "")


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> VpnCollector:
    from .vendors import spec_for

    return VpnCollector(spec_for(vendor), feed)
