"""Active Discovery Modes — SAFE by default, DEEP/AGGRESSIVE only with scope.

Every scan records scan_mode, rate_limit, concurrency, authorization_scope,
start_time and end_time. No mode ever performs exploitation; AGGRESSIVE only
increases probe depth/frequency within the authorized estate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

MODES = ("SAFE", "STANDARD", "DEEP", "AGGRESSIVE")

_MODE_PRESETS: dict[str, dict[str, Any]] = {
    "SAFE": {
        "concurrency": 4,
        "rate_limit_per_second": 5,
        "probe_timeout": 3.0,
        "udp_init_probes": False,     # no WireGuard/OpenVPN/IKE init packets
        "credentialed": False,
        "active_scan": True,
        "description": "low concurrency, minimal probes, protocol-safe checks, "
                       "no auth attempts without credentials, no exploitation",
    },
    "STANDARD": {
        "concurrency": 16,
        "rate_limit_per_second": 20,
        "probe_timeout": 5.0,
        "udp_init_probes": True,
        "credentialed": False,
        "active_scan": True,
        "description": "balanced sweep + single-packet protocol probes",
    },
    "DEEP": {
        "concurrency": 32,
        "rate_limit_per_second": 50,
        "probe_timeout": 8.0,
        "udp_init_probes": True,
        "credentialed": True,
        "active_scan": True,
        "description": "comprehensive authorized inspection incl. credentialed "
                       "config collection (NETCONF/RESTCONF/gNMI/SNMP)",
    },
    "AGGRESSIVE": {
        "concurrency": 64,
        "rate_limit_per_second": 200,
        "probe_timeout": 10.0,
        "udp_init_probes": True,
        "credentialed": True,
        "active_scan": True,
        "description": "maximum authorized depth — full config pull + sweep; "
                       "still never exploitation",
    },
}

PASSIVE_ONLY = {"PASSIVE"}


@dataclass
class ScanAuthorization:
    """What the scan is allowed to touch. DEEP/AGGRESSIVE require a scope."""

    authorization_scope: str = ""  # e.g. 'global', 'emirates-dc', 'branch-12'
    networks: list[str] = field(default_factory=list)
    credentialed: bool = False
    authorized_by: str | None = None
    notes: str = ""

    def authorizes(self, target: Any) -> bool:
        """Best-effort containment: any authorization covers its own networks;
        empty networks means the scope string itself is the boundary."""
        if not self.authorization_scope and not self.networks:
            return False
        if not self.networks:
            return True
        from ipaddress import ip_address, ip_network

        ip = getattr(target, "value", None) or (target if isinstance(target, str) else None)
        if not ip:
            return True
        try:
            addr = ip_address(ip.split("/")[0].split(":")[0] if ip.count(":") < 2 else ip)
        except ValueError:
            return True
        return any(addr in ip_network(net, strict=False) for net in self.networks)


@dataclass
class ScanMode:
    mode: str = "SAFE"
    authorization: ScanAuthorization = field(default_factory=ScanAuthorization)

    def __post_init__(self) -> None:
        self.mode = self.mode.upper()
        if self.mode not in MODES:
            raise ValueError(f"unknown scan mode '{self.mode}' (choose from {', '.join(MODES)})")
        if self.mode in ("DEEP", "AGGRESSIVE") and not self.authorization.authorization_scope:
            raise ValueError(f"scan mode {self.mode} requires an authorization_scope")

    @property
    def concurrency(self) -> int:
        return int(_MODE_PRESETS[self.mode]["concurrency"])

    @property
    def rate_limit(self) -> int:
        return int(_MODE_PRESETS[self.mode]["rate_limit_per_second"])

    @property
    def probe_timeout(self) -> float:
        return float(_MODE_PRESETS[self.mode]["probe_timeout"])

    @property
    def udp_init_probes(self) -> bool:
        return bool(_MODE_PRESETS[self.mode]["udp_init_probes"])

    @property
    def credentialed(self) -> bool:
        return bool(_MODE_PRESETS[self.mode]["credentialed"])

    @property
    def description(self) -> str:
        return str(_MODE_PRESETS[self.mode]["description"])

    def allows(self, feature: str) -> bool:
        """Feature gates: 'udp_init', 'credentialed', 'sweep'."""
        if feature == "udp_init":
            return self.udp_init_probes
        if feature == "credentialed":
            return self.credentialed and self.authorization.credentialed
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_mode": self.mode,
            "rate_limit": self.rate_limit,
            "concurrency": self.concurrency,
            "authorization_scope": self.authorization.authorization_scope,
            "description": self.description,
        }


@dataclass
class ScanMetadata:
    """Every scan records how it ran and under what authority."""

    scan_mode: ScanMode
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str | None = None
    targets_probed: int = 0
    assets_discovered: int = 0
    observations: int = 0

    def finish(self) -> None:
        self.end_time = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.scan_mode.to_dict(),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "targets_probed": self.targets_probed,
            "assets_discovered": self.assets_discovered,
            "observations": self.observations,
        }


def default_scan_mode(authorization_scope: str = "") -> ScanMode:
    return ScanMode("SAFE", ScanAuthorization(authorization_scope=authorization_scope))
