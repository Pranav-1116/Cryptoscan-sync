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

__all__ = [
    "CredentialHealth",
    "ScanDecision",
    "Scope",
    "assess_credential",
    "backoff_delay",
    "classify_after_failure",
    "confidence_from_evidence",
    "evaluate_scan",
    "is_authorized",
    "lease_event",
    "maintenance_window_open",
    "meets_target",
    "next_available",
    "residency_permitted",
    "resolve_identity",
    "score_predictions",
    "should_auto_stop",
]
