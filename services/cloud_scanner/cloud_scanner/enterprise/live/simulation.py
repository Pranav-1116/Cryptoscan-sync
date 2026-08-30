"""ZELNX Live Cloud Intelligence Engine — live migration simulation bridge.

Live-layer counterpart of the discovery engine's migration simulation:
takes a proposed crypto change (e.g. replace a certificate, rotate a
key, upgrade a TLS endpoint) and evaluates its blast radius against the
live dependency graph, reusing the network scanner's migration simulator
for path-level verdicts when a graph is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.live.live_graph import LiveCloudDependencyGraph

SimulateFn = Callable[[list[dict[str, Any]]], dict[str, Any]]


@dataclass
class LiveMigrationEvaluation:
    """Result of evaluating a proposed crypto change on the live graph."""

    change_id: str
    change_kind: str = ""  # KEY_ROTATION | CERTIFICATE_REPLACEMENT | TLS_UPGRADE
    affected_assets: list[str] = field(default_factory=list)
    affected_edges: list[str] = field(default_factory=list)
    verdict: str = "COMPATIBLE"  # COMPATIBLE | INCOMPATIBLE | RISK
    path_simulations: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "change_kind": self.change_kind,
            "affected_assets": list(self.affected_assets),
            "affected_edges": list(self.affected_edges),
            "verdict": self.verdict,
            "path_simulations": list(self.path_simulations),
            "notes": list(self.notes),
        }


class LiveSimulationEngine:
    """Evaluate crypto changes against the live dependency graph.

    ``path_simulator`` (injectable) receives a list of change steps and
    returns a dict with keys like verdict / paths_evaluated — matching
    the discovery engine's migration-simulation contract.
    """

    def __init__(self, *, graph: LiveCloudDependencyGraph | None = None,
                 path_simulator: SimulateFn | None = None) -> None:
        self.graph = graph or LiveCloudDependencyGraph()
        self._simulator = path_simulator or (lambda steps: {"verdict": "COMPATIBLE",
                                                            "paths_evaluated": 0})
        self._evaluations: list[LiveMigrationEvaluation] = []

    def evaluate_change(self, *, change_id: str, change_kind: str,
                        target: str, steps: list[dict[str, Any]] | None = None) -> LiveMigrationEvaluation:
        steps = list(steps or [])
        affected_assets = self.graph.dependents(target, transitive=True)
        affected_edges = [edge.to_dict() for edge in self.graph.edges()
                          if edge.target == target]
        path_result = self._simulator(steps) or {}
        verdict = str(path_result.get("verdict") or "COMPATIBLE")
        evaluation = LiveMigrationEvaluation(
            change_id=change_id,
            change_kind=change_kind,
            affected_assets=affected_assets,
            affected_edges=[f"{edge['source']}--{edge['relation']}-->"
                            f"{edge['target']}" for edge in affected_edges],
            verdict=verdict,
            path_simulations=[dict(path_result)],
            notes=[f"{len(affected_assets)} dependents re-evaluated"],
        )
        self._evaluations.append(evaluation)
        return evaluation

    def evaluations(self) -> list[LiveMigrationEvaluation]:
        return list(self._evaluations)

    def summary(self) -> dict[str, Any]:
        return {
            "evaluations": len(self._evaluations),
            "verdicts": {
                verdict: sum(1 for e in self._evaluations if e.verdict == verdict)
                for verdict in ("COMPATIBLE", "INCOMPATIBLE", "RISK")
            },
        }
