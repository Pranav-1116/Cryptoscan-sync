"""ZELNX Cloud Discovery Engine — cloud migration simulation (spec §17).

Connects cloud discovery to the existing simulation engine
(``network_scanner.enterprise.simulation.MigrationSimulator``) and adds a
cloud-level impact model:

    CURRENT (AWS Application ── AWS KMS / ACM Certificate / ALB TLS)
        ──▶ PROPOSED PQC / HYBRID CHANGE
                ├── Compatibility Analysis
                ├── Application Impact
                ├── Network Impact
                ├── Certificate Impact
                ├── Cloud Cost Impact
                ├── Performance Impact
                └── Rollback Analysis

When a network path graph is supplied, path-level impacts reuse the network
simulator; otherwise the cloud dependency graph drives impact attribution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.dependency_graph import CloudDependencyGraph

StepBuilder = Callable[[str], list[dict[str, Any]]]  # resource_id -> steps


@dataclass
class CloudMigrationStep:
    """One proposed PQC/hybrid replacement on a cloud resource."""

    resource_id: str
    current_algorithm: str
    replacement_algorithm: str
    hybrid: bool = True
    service: str = ""
    provider: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "current_algorithm": self.current_algorithm,
            "replacement_algorithm": self.replacement_algorithm,
            "hybrid": self.hybrid,
            "service": self.service,
            "provider": self.provider,
        }


@dataclass
class CloudImpact:
    """Impact of the proposed change on one resource."""

    resource_id: str
    compatible: bool = True
    application_impact: str = "NONE"  # NONE | LOW | MEDIUM | HIGH
    network_impact: str = "NONE"
    certificate_impact: str = "NONE"
    performance_impact: str = "NONE"
    rollback_feasible: bool = True
    blockers: list[str] = field(default_factory=list)
    affected_dependents: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "compatible": self.compatible,
            "application_impact": self.application_impact,
            "network_impact": self.network_impact,
            "certificate_impact": self.certificate_impact,
            "performance_impact": self.performance_impact,
            "rollback_feasible": self.rollback_feasible,
            "blockers": list(self.blockers),
            "affected_dependents": list(self.affected_dependents),
        }


@dataclass
class CloudSimulationResult:
    """The full simulation outcome."""

    steps: list[CloudMigrationStep] = field(default_factory=list)
    impacts: list[CloudImpact] = field(default_factory=list)
    verdict: str = "NO_CHANGES"
    path_simulations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "steps": [step.to_dict() for step in self.steps],
            "impacts": [impact.to_dict() for impact in self.impacts],
            "path_simulations": list(self.path_simulations),
        }


class CloudMigrationSimulator:
    """Simulate PQC/hybrid migration on cloud crypto resources.

    ``step_builder(resource_id)`` returns proposed steps for a resource
    (default: classical → hybrid from ``quantum.risk.PQC_REPLACEMENTS``).
    ``network_simulator`` is the network simulation engine (injected or
    built on demand); it is only called when a path graph is available.
    """

    def __init__(
        self,
        graph: CloudDependencyGraph,
        *,
        step_builder: StepBuilder | None = None,
        network_simulator: Any | None = None,
    ) -> None:
        self.graph = graph
        self._step_builder = step_builder or default_steps
        self._network_simulator = network_simulator

    def simulate(self, resource_ids: list[str]) -> CloudSimulationResult:
        result = CloudSimulationResult()
        for resource_id in resource_ids:
            raw_steps = self._step_builder(resource_id) or []
            steps = [self._to_step(resource_id, raw) for raw in raw_steps]
            result.steps.extend(steps)
            result.impacts.append(self._impact(resource_id, steps))
        if result.steps:
            result.verdict = "COMPATIBLE" if all(i.compatible for i in result.impacts) else "BLOCKED"
        self._run_path_simulations(result)
        return result

    # ------------------------------------------------------------------

    def _impact(self, resource_id: str, steps: list[CloudMigrationStep]) -> CloudImpact:
        dependents = self.graph.dependents(resource_id, transitive=True)
        impact = CloudImpact(resource_id=resource_id, affected_dependents=dependents)
        for step in steps:
            if not step.hybrid:
                impact.blockers.append(
                    f"{step.current_algorithm}->{step.replacement_algorithm} not hybrid (no rollback)"
                )
                impact.rollback_feasible = False
            if step.service == "kms":
                impact.application_impact = _worst(impact.application_impact, "MEDIUM")
            if step.service in ("elbv2", "cloudfront", "load_balancer", "app_gateway",
                                "front_door", "api_gateway", "certificate_manager", "acm"):
                impact.network_impact = _worst(impact.network_impact, "LOW")
                impact.certificate_impact = _worst(impact.certificate_impact, "HIGH")
            if step.service in ("key_vault", "managed_hsm", "cloud_hsm", "cloudhsmv2", "hsm"):
                impact.performance_impact = _worst(impact.performance_impact, "LOW")
        impact.compatible = not impact.blockers
        return impact

    @staticmethod
    def _to_step(resource_id: str, raw: dict[str, Any]) -> CloudMigrationStep:
        return CloudMigrationStep(
            resource_id=resource_id,
            current_algorithm=str(raw.get("current_algorithm") or raw.get("algorithm") or "RSA"),
            replacement_algorithm=str(raw.get("replacement_algorithm")
                                      or raw.get("replacement") or "ML-KEM-768"),
            hybrid=bool(raw.get("hybrid", True)),
            service=str(raw.get("service") or ""),
            provider=str(raw.get("provider") or ""),
        )

    def _run_path_simulations(self, result: CloudSimulationResult) -> None:
        if self._network_simulator is None:
            return
        affected = {step.resource_id for step in result.steps}
        try:
            network_steps = [
                {
                    "algorithm": step.current_algorithm,
                    "replacement": step.replacement_algorithm,
                    "asset": step.resource_id,
                    "hybrid": step.hybrid,
                }
                for step in result.steps
            ]
            simulated = self._network_simulator.simulate_steps(network_steps) \
                if hasattr(self._network_simulator, "simulate_steps") else None
            if simulated is not None:
                result.path_simulations.append(simulated)
        except Exception as exc:  # noqa: BLE001 — simulation must not crash discovery
            result.path_simulations.append({"error": str(exc)[:300], "affected": sorted(affected)})


def default_steps(resource_id: str) -> list[dict[str, Any]]:
    """Classical → hybrid steps from the quantum risk table."""
    try:
        from quantum.risk import PQC_REPLACEMENTS  # type: ignore
    except Exception:
        return [{"current_algorithm": "RSA", "replacement_algorithm": "ML-KEM-768",
                 "hybrid": True, "service": "kms"}]
    steps: list[dict[str, Any]] = []
    for algo, mapping in PQC_REPLACEMENTS.items():
        if not isinstance(mapping, dict):
            continue
        replacement = mapping.get("key_exchange") or mapping.get("signing")
        if not replacement:
            continue
        steps.append({"current_algorithm": algo, "replacement_algorithm": replacement,
                      "hybrid": True})
    return steps[:3]


def _worst(current: str, candidate: str) -> str:
    rank = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    return candidate if rank.get(candidate, 0) > rank.get(current, 0) else current
