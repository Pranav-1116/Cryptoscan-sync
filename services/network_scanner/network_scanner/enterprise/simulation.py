"""Network Migration Simulation — connect discovery to the simulation engine.

Simulates replacing a classical crypto configuration with a hybrid/post-
quantum one and evaluates, per affected network path:

compatibility, latency, packet overhead, MTU impact, bandwidth, hardware
support, peer compatibility and rollback feasibility.

The simulator works on the dependency graph: changing a certificate, VPN
profile or TLS policy affects exactly the paths the graph says it affects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from network_scanner.enterprise.topology import NetworkGraph

# per-algorithm cost model (conservative defaults, overridable by vendor data)
_ALGO_MODEL: dict[str, dict[str, Any]] = {
    "ML-KEM-768": {"overhead_bytes": 1088, "latency_multiplier": 1.0, "mtu_reduction": 0},
    "ML-KEM-1024": {"overhead_bytes": 1568, "latency_multiplier": 1.0, "mtu_reduction": 0},
    "ML-DSA-65": {"overhead_bytes": 2509, "latency_multiplier": 1.05, "mtu_reduction": 0},
    "SLH-DSA": {"overhead_bytes": 7856, "latency_multiplier": 1.2, "mtu_reduction": 0},
    "KYBER": {"overhead_bytes": 1088, "latency_multiplier": 1.0, "mtu_reduction": 0},
    "DILITHIUM": {"overhead_bytes": 2509, "latency_multiplier": 1.05, "mtu_reduction": 0},
    "X25519MLKEM768": {"overhead_bytes": 1184, "latency_multiplier": 1.0, "mtu_reduction": 0},
    "RSA": {"overhead_bytes": 256, "latency_multiplier": 0.8, "mtu_reduction": 0},
    "ECDH": {"overhead_bytes": 96, "latency_multiplier": 0.7, "mtu_reduction": 0},
    "ECDSA": {"overhead_bytes": 96, "latency_multiplier": 0.7, "mtu_reduction": 0},
}


@dataclass
class MigrationStep:
    """One configuration replacement in a simulation."""

    algorithm: str
    replacement: str
    protocol: str | None = None
    asset: str | None = None
    hybrid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"algorithm": self.algorithm, "replacement": self.replacement,
                "protocol": self.protocol, "asset": self.asset, "hybrid": self.hybrid}


@dataclass
class PathImpact:
    """Impact of a migration on one network path."""

    path: list[str]
    compatible: bool
    latency_delta_percent: float
    packet_overhead_bytes: int
    mtu_impact: int
    bandwidth_delta_percent: float
    hardware_support: str  # SUPPORTED / UNKNOWN / UNSUPPORTED
    peer_compatibility: str
    rollback_feasible: bool
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": list(self.path),
            "compatible": self.compatible,
            "latency_delta_percent": round(self.latency_delta_percent, 2),
            "packet_overhead_bytes": self.packet_overhead_bytes,
            "mtu_impact": self.mtu_impact,
            "bandwidth_delta_percent": round(self.bandwidth_delta_percent, 2),
            "hardware_support": self.hardware_support,
            "peer_compatibility": self.peer_compatibility,
            "rollback_feasible": self.rollback_feasible,
            "blockers": list(self.blockers),
        }


class MigrationSimulator:
    """Simulates hybrid config rollout over the dependency graph."""

    def __init__(self, graph: NetworkGraph, *, algorithm_model: dict[str, Any] | None = None,
                 hardware_capability: dict[str, str] | None = None) -> None:
        self.graph = graph
        self.algorithm_model = dict(algorithm_model or _ALGO_MODEL)
        # asset -> SUPPORTED / UNKNOWN / UNSUPPORTED (PQC capable?)
        self.hardware_capability = dict(hardware_capability or {})

    def evaluate(self, steps: list[MigrationStep], *, peer_map: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Run a simulation: replace classical config, evaluate every path."""
        peer_map = peer_map or {}
        impacts: list[PathImpact] = []
        affected_pairs = self._affected_pairs(steps)
        for start, end in affected_pairs:
            for path in self.graph.paths(start, end, max_depth=8):
                impacts.append(self._evaluate_path(path, steps, peer_map=peer_map))
                if len(impacts) > 200:
                    break
        aggregated = self._aggregate(steps, impacts)
        return aggregated

    # ------------------------------------------------------------------

    def _affected_pairs(self, steps: list[MigrationStep]) -> list[tuple[str, str]]:
        """Every (start, end) pair connected through an affected asset."""
        assets = {step.asset for step in steps if step.asset}
        pairs: list[tuple[str, str]] = []
        nodes = self.graph.nodes()
        for affected in assets:
            for node in nodes:
                if node == affected:
                    continue
                if self.graph.paths(affected, node, max_depth=8):
                    pairs.append((affected, node))
        return pairs[:50]

    def _evaluate_path(self, path: list[str], steps: list[MigrationStep],
                       *, peer_map: dict[str, list[str]]) -> PathImpact:
        blockers: list[str] = []
        overhead = 0
        latency_delta = 0.0
        hardware = "SUPPORTED"
        peer_compat = "COMPATIBLE"
        hybrid_count = 0
        for step in steps:
            if step.asset and step.asset not in path:
                continue
            model = self.algorithm_model.get(step.replacement, self.algorithm_model.get(step.algorithm, {}))
            overhead += int(model.get("overhead_bytes", 0) or 0)
            latency_delta += float(model.get("latency_multiplier", 1.0) or 1.0) - 1.0
            if not step.hybrid:
                blockers.append(f"{step.algorithm}->{step.replacement} is not hybrid (no rollback path)")
            if step.asset:
                support = self.hardware_capability.get(step.asset, "UNKNOWN")
                if support == "UNSUPPORTED":
                    hardware = "UNSUPPORTED"
                    blockers.append(f"hardware unsupported on {step.asset}")
                elif support != "SUPPORTED" and hardware == "SUPPORTED":
                    hardware = "UNKNOWN"
            hybrid_count += 1
        for node in path:
            for peer in peer_map.get(node, []):
                if peer not in path and peer_map:
                    # peer not migrated yet -> compatibility question
                    peer_compat = "UNKNOWN" if peer_compat == "COMPATIBLE" else peer_compat
        compatible = not blockers
        mtu_impact = -overhead if overhead else 0
        # conservative bandwidth estimate: overhead shrinks effective payload
        bandwidth_delta = -(overhead / 1500 * 100) if overhead else 0.0
        return PathImpact(
            path=path,
            compatible=compatible,
            latency_delta_percent=latency_delta * 100,
            packet_overhead_bytes=overhead,
            mtu_impact=mtu_impact,
            bandwidth_delta_percent=bandwidth_delta,
            hardware_support=hardware,
            peer_compatibility=peer_compat,
            rollback_feasible=all(step.hybrid for step in steps if step.asset and step.asset in path),
            blockers=blockers,
        )

    def _aggregate(self, steps: list[MigrationStep], impacts: list[PathImpact]) -> dict[str, Any]:
        if not impacts:
            return {
                "simulation": "no_impact_paths",
                "steps": [s.to_dict() for s in steps],
                "paths_evaluated": 0,
                "verdict": "NO_AFFECTED_PATHS",
                "note": "no graph path connects the changed assets — verify topology",
            }
        all_compatible = all(impact.compatible for impact in impacts)
        return {
            "simulation": "hybrid-migration",
            "steps": [s.to_dict() for s in steps],
            "paths_evaluated": len(impacts),
            "verdict": "COMPATIBLE" if all_compatible else "BLOCKED",
            "max_packet_overhead_bytes": max(i.packet_overhead_bytes for i in impacts),
            "max_mtu_reduction": min(i.mtu_impact for i in impacts),
            "max_latency_delta_percent": round(max(i.latency_delta_percent for i in impacts), 2),
            "max_bandwidth_delta_percent": round(min(i.bandwidth_delta_percent for i in impacts), 2),
            "worst_hardware_support": max((i.hardware_support for i in impacts), key=lambda v: {"SUPPORTED": 0, "UNKNOWN": 1, "UNSUPPORTED": 2}[v]),
            "rollback_feasible": all(i.rollback_feasible for i in impacts),
            "blockers": sorted({b for i in impacts for b in i.blockers}),
            "paths": [i.to_dict() for i in impacts],
        }


def default_steps_from_crypto(crypto: list[str], *, asset: str | None = None) -> list[MigrationStep]:
    """Classical -> hybrid PQC steps from a crypto algorithm list."""
    try:
        from quantum.risk import PQC_REPLACEMENTS  # type: ignore
    except Exception:
        PQC_REPLACEMENTS = {}
    steps: list[MigrationStep] = []
    for algorithm in crypto:
        upper = algorithm.upper()
        replacement = (PQC_REPLACEMENTS.get(upper) or {}).get("key_exchange") or (
            PQC_REPLACEMENTS.get(upper) or {}).get("signing")
        if replacement:
            steps.append(MigrationStep(algorithm=upper, replacement=replacement, asset=asset))
    return steps
