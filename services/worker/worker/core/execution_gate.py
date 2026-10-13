"""Execution-time re-validation for dequeued scan jobs (§4.1, round 46).

Admission at ENQUEUE proves the request was acceptable when the API saw it.
Between enqueue and dequeue an emergency stop can be engaged, the safe-scan
policy can tighten, or the declared source roots can change — the worker is
the last point that can still refuse. This gate re-derives the same
decisions the API made, without FastAPI machinery:

* the safe-scan policy (emergency stop, mode, exclusions) via the SAME
  ``control_plane.safety.evaluate_scan`` the API admission uses, reading the
  SAME control-plane tables — a policy refusal fails the job row with the
  reason and no collector runs;
* source-root containment for repository targets via the SAME
  ``validate_source_target`` choke point every API scanner route uses —
  a target that no longer resolves inside the declared roots is refused.

Fail-closed, exactly like the API's ``admit_scan``: if the control plane
cannot be read, the job is refused — "emergency stop becomes advisory when
the database hurts" is the failure mode this prevents on both sides.
"""

from __future__ import annotations

import logging

from worker.core.job_consumer import ScanJob

logger = logging.getLogger(__name__)


class GateUnavailable(Exception):
    """The control plane could not be read — the gate fails closed."""


def _matching_policy() -> dict | None:
    """The active safe-scan policy, or raise :class:`GateUnavailable`."""
    from db.connection.session import SessionLocal
    from db.repositories.control_plane_repository import ControlPlaneRepository

    session = SessionLocal()
    try:
        policy_row = ControlPlaneRepository(session).matching_policy()
        return policy_row.to_dict() if policy_row else None
    except Exception as exc:  # noqa: BLE001 — any lookup failure is a refusal
        raise GateUnavailable(f"control plane unreadable: {exc}") from exc
    finally:
        session.close()


def policy_decision(target_repo: str | None = None) -> tuple[bool, str | None]:
    """Safe-scan policy check for a job about to execute.

    Returns ``(permitted, refusal_reason)``. Applies to every job kind —
    an engaged emergency stop halts binary, org, cloud and repository scans
    alike. ``target_repo`` feeds the policy's asset exclusions, exactly as
    the API admission feeds it the requested asset.
    """
    from control_plane.safety import evaluate_scan

    try:
        policy = _matching_policy()
    except GateUnavailable as exc:
        return False, f"execution gate fail-closed: {exc}"
    decision = evaluate_scan(policy, asset=target_repo)
    if not decision.permitted:
        return False, f"safe-scan policy refuses execution: {decision.reason}"
    return True, None


def target_decision(target_repo: str) -> tuple[bool, str | None]:
    """Source-root containment for repository targets (§4.1 execution half).

    The API validated the target at enqueue; this re-derives the decision at
    execution so a scope change between queue and dequeue cannot make the
    worker walk a path the platform no longer declares.
    """
    from api.security.target_validation import TargetValidationError, validate_source_target

    try:
        validate_source_target(target_repo, label="execution_gate.target_repo")
    except TargetValidationError as exc:
        return False, f"target refused at execution: {exc}"
    return True, None


def gate_job(job: ScanJob, *, repository_target: bool) -> tuple[bool, str | None]:
    """Full execution gate: policy for every job, containment for repo targets.

    ``repository_target`` tells the gate whether this job walks a filesystem
    repository (the pipeline branch) — binary, org and cloud jobs carry their
    own bounds and are policy-checked only.
    """
    permitted, reason = policy_decision(job.target_repo)
    if not permitted:
        return False, reason
    if repository_target:
        permitted, reason = target_decision(job.target_repo)
        if not permitted:
            return False, reason
    return True, None
