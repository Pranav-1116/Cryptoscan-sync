"""ZELNX Control Plane — deterministic core logic (P0).

Pure, import-light modules implementing authorization, safe-scanning
decisions, asset identity resolution, detection benchmark scoring, durable
queue semantics and credential health. Router/repository code in the API
service persists and enforces these; the logic here is unit-tested in
isolation per the "Deterministic Truth First" doctrine.
"""

from control_plane.benchmark import meets_target, score_predictions
from control_plane.compliance import framework_posture
from control_plane.credentials import CredentialHealth, assess_credential
from control_plane.iam import Scope, is_authorized, residency_permitted
from control_plane.identity import (
    confidence_from_evidence,
    resolve_identity,
)
from control_plane.integrations import (
    build_signed_export,
    load_signed_export,
    normalize_siem_events,
    resolve_cmdb_assets,
    ticket_state_machine,
    to_cef,
)
from control_plane.knowledge import (
    is_deprecated_or_worse,
    lookup,
    lookup_vendor,
    migration_target,
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
from control_plane.pipeline import classify_finding, finding_to_target, run_pipeline
from control_plane.policy_as_code import (
    evaluate_policy,
    merge_policy_layers,
    policy_version,
)
from control_plane.queue import (
    backoff_delay,
    classify_after_failure,
    lease_event,
    next_available,
)
from control_plane.regions import assess_dr, residency_violations, route_region
from control_plane.safety import (
    ScanDecision,
    evaluate_scan,
    maintenance_window_open,
    should_auto_stop,
)
from control_plane.vault import VaultError, get_adapter, lease_credential
from control_plane.worker import process_event, worker_tick

__all__ = [
    "CredentialHealth",
    "Orchestrator",
    "OrchestratorConfig",
    "ScanDecision",
    "Scope",
    "VaultError",
    "assess_credential",
    "assess_dr",
    "backoff_delay",
    "build_signed_export",
    "classify_after_failure",
    "classify_finding",
    "confidence_from_evidence",
    "credential_health",
    "emergency_engaged",
    "evaluate_policy",
    "evaluate_scan",
    "finding_to_target",
    "fleet_health",
    "framework_posture",
    "get_adapter",
    "is_authorized",
    "is_deprecated_or_worse",
    "lease_credential",
    "lease_event",
    "load_signed_export",
    "lookup",
    "lookup_vendor",
    "maintenance_window_open",
    "meets_target",
    "merge_policy_layers",
    "migration_target",
    "next_available",
    "normalize_siem_events",
    "overall_status",
    "policy_version",
    "process_event",
    "queue_health",
    "residency_permitted",
    "residency_violations",
    "resolve_cmdb_assets",
    "resolve_identity",
    "route_region",
    "run_pipeline",
    "scanner_for_event",
    "score_predictions",
    "should_auto_stop",
    "ticket_state_machine",
    "to_cef",
    "worker_tick",
]
