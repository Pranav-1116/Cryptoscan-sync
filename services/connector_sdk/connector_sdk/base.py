"""BaseConnector — the interface every ZELNX connector implements.

A connector declares its ``kind`` / ``method`` / ``mode`` (how it integrates and
whether it may mutate), and implements ``scan`` to return normalized
``Observation`` objects. ``run`` wraps ``scan`` with the tenant
``ConnectorContext`` guardrails (read-only, allowed methods, rate limit,
maintenance window, exclusions) and a global-rate-limit shim per context, so
no connector can accidentally exceed its authorization.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable

from connector_sdk.context import ConnectorContext
from connector_sdk.observations import Observation


class BaseConnector(ABC):
    """Template for all ZELNX connectors (network, aws, azure, gcp, k8s,
    vmware, hsm, git, hardware, siem…)."""

    #: connector kind (must match CONNECTOR_KINDS in the onboarding model)
    kind: str = "other"
    #: connector method (must match CONNECTOR_METHODS in the onboarding model)
    method: str = "api"
    #: "passive" (read-only) or "active" (may mutate under explicit approval)
    mode: str = "passive"

    def __init__(self, *, name: str | None = None, **options: Any) -> None:
        self.name = name or f"{self.kind}:{self.method}"
        self.options = options

    # -- what the connector does -------------------------------------------------
    @abstractmethod
    def scan(self, context: ConnectorContext, targets: Iterable[str] = ()) -> list[Observation]:
        """Produce normalized observations for the given targets."""

    # -- guarded execution -------------------------------------------------------
    def run(self, context: ConnectorContext, targets: Iterable[str] = (),
            *, mutating: bool = False) -> list[Observation]:
        """Execute ``scan`` under the context guardrails.

        Raises ``PermissionError`` / ``RuntimeError`` before touching a target
        when the run is not authorized (read-only, excluded, rate-limited).
        """
        targets = list(targets)
        if mutating and self.mode != "active":
            raise PermissionError(
                f"connector {self.name} is mode={self.mode!r}; mutating runs require mode='active'")
        for t in targets:
            context.guard(t, mutating=mutating)
        observations = self.scan(context, targets)
        # normalize the emit contract (Observation instances or dicts)
        return [_as_observation(o) for o in observations]

    def describe(self) -> dict[str, Any]:
        return {"kind": self.kind, "method": self.method, "mode": self.mode, "name": self.name,
                "support_status": "REGISTERED_NOT_QUALIFIED",
                "note": "Registry presence is implementation discovery, not exercised vendor/product/version/profile support."}


def _as_observation(o: Any) -> Observation:
    if isinstance(o, Observation):
        return o
    if isinstance(o, dict):
        return Observation(**o)
    raise TypeError(f"connector emitted unsupported type {type(o).__name__!r}: expected Observation or dict")


__all__ = ["BaseConnector"]
