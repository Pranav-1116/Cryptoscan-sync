"""ZELNX Control Plane — deterministic core logic (P0).

Pure, import-light modules implementing authorization, safe-scanning
decisions, asset identity resolution, detection benchmark scoring, durable
queue semantics and credential health. Router/repository code in the API
service persists and enforces these; the logic here is unit-tested in
isolation per the "Deterministic Truth First" doctrine.
"""

from control_plane.benchmark import meets_target, score_predictions
from control_plane.credentials import CredentialHealth, assess_credential
from control_plane.iam import Scope, is_authorized, residency_permitted
from control_plane.identity import (
    confidence_from_evidence,
    resolve_identity,
)
from control_plane.observability import (
    credential_health,
    fleet_health,
    overall_status,
    queue_health,
)
from control_plane.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    emergency_engaged,
    scanner_for_event,
)
from control_plane.queue import (
    backoff_delay,
    classify_after_failure,
    lease_event,
    next_available,
)
from control_plane.safety import (
    ScanDecision,
    evaluate_scan,
    maintenance_window_open,
    should_auto_stop,
)
from control_plane.vault import VaultError, get_adapter, lease_credential

__all__ = [
    "CredentialHealth",
    "Orchestrator",
    "OrchestratorConfig",
    "ScanDecision",
    "Scope",
    "VaultError",
    "assess_credential",
    "backoff_delay",
    "classify_after_failure",
    "confidence_from_evidence",
    "credential_health",
    "emergency_engaged",
    "evaluate_scan",
    "fleet_health",
    "get_adapter",
    "is_authorized",
    "lease_credential",
    "lease_event",
    "maintenance_window_open",
    "meets_target",
    "next_available",
    "overall_status",
    "queue_health",
    "residency_permitted",
    "resolve_identity",
    "scanner_for_event",
    "score_predictions",
    "should_auto_stop",
]
