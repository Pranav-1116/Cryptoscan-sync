"""One fail-closed admission decision for every scan the API accepts.

History of the holes this closes (see ``docs/PRODUCTION-GAP-HANDOFF-2026-10-08.md``):

* The manual trigger's safe-scan gate failed **open** — a control-plane
  lookup error was logged at debug level and the scan queued anyway, which
  makes an emergency stop advisory exactly when the database is hurting.
* The gate read its OT flag from a request field that does not exist, so OT
  policy was never applied on that path.
* The shared enqueue helper every other scan route uses had **no gate at
  all**, and the network live-probe endpoints (CIDR sweep, due rotation,
  SSH scan) probed with no admission decision whatsoever.

This module is the single decision every entry point must pass before a scan
is accepted or a live probe runs:

* emergency stop → 409, always;
* safe-scan policy refusing the scan → 409 with the policy's reason;
* OT is **derived from trusted declarations** (an enabled onboarding
  environment of type ``ot``), never from the request body;
* active probing (an active ``scan_mode``, or an endpoint that probes by
  nature — a CIDR sweep, a TLS handshake rotation, an SSH banner read) must
  be authorized by the decision: outside an approved maintenance window OT
  estates get passive-only, so an active request is refused with 409 while
  passive/safe modes remain available;
* any lookup failure → 503 and **no scan accepted**. Failing open here is
  how "emergency stop" becomes a suggestion.

The module-level ``_control_plane_state`` / ``_ot_declared`` /
``_authorized_network_scope`` helpers are the test seams: they are the only
places that touch the database, so tests can pin them without one.
"""

from __future__ import annotations

import ipaddress
import logging

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

#: scan modes that actively probe the target (control_plane.safety's ordering)
ACTIVE_SCAN_MODES = frozenset({"low_impact", "standard", "deep"})


# --------------------------------------------------------------------------- #
# database seams
# --------------------------------------------------------------------------- #

def _control_plane_state() -> tuple[list[dict], dict | None]:
    """(control-plane events, matching safe-scan policy) or raise on outage."""
    from db.connection.session import SessionLocal
    from db.repositories.control_plane_repository import ControlPlaneRepository

    session = SessionLocal()
    try:
        cp = ControlPlaneRepository(session)
        events = [e.to_dict() for e in cp.list_events(None, limit=500)]
        policy_row = cp.matching_policy()
        return events, (policy_row.to_dict() if policy_row else None)
    finally:
        session.close()


def _ot_declared() -> bool:
    """Trusted OT declaration: an enabled onboarding environment of type
    ``ot`` exists in the caller's scope. Runs inside the request's tenant
    scope (the ORM guard filters the read), so one tenant declaring OT does
    not put every other tenant into passive-only mode."""
    from db.connection.session import SessionLocal
    from db.models.onboarding import Environment

    session = SessionLocal()
    try:
        row = (
            session.query(Environment)
            .filter(Environment.env_type == "ot", Environment.enabled.is_(True))
            .first()
        )
        return row is not None
    finally:
        session.close()


def _authorized_network_scope() -> list[str]:
    """Enabled network scope targets declared at onboarding (the authorization
    surface for network sweeps), plus currently registered due-scan targets.
    Tenant-scoped by the ORM guard like every other read."""
    from db.connection.session import SessionLocal
    from db.models.network_scan_target import NetworkScanTarget
    from db.models.onboarding import ScopeEntry

    session = SessionLocal()
    try:
        scope_targets = [
            str(row.target)
            for row in session.query(ScopeEntry)
            .filter(ScopeEntry.kind == "network", ScopeEntry.enabled.is_(True))
            .all()
        ]
        registered = [
            str(row.endpoint)
            for row in session.query(NetworkScanTarget)
            .filter(NetworkScanTarget.enabled.is_(True))
            .all()
        ]
        return scope_targets + registered
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# pure target classification (shared with onboarding registration)
# --------------------------------------------------------------------------- #

def host_part(endpoint: str) -> str:
    """The host portion of a target string: strips a single ``:port``
    suffix. IPv6 literals (``[::1]:443`` or bare ``::1``) are returned
    unchanged for the caller's parser to deal with."""
    if endpoint.startswith("["):
        return endpoint
    if endpoint.count(":") == 1:
        host, _, port = endpoint.rpartition(":")
        if port and port.isdigit():
            return host
    return endpoint


def is_range_target(endpoint: str) -> bool:
    """True when the endpoint names an address RANGE (a CIDR with more than
    one address) rather than one concrete host. Ranges are *authorization
    scope* — materializing them as always-enabled TLS probe targets turns
    "we may scan this network" into "we actively sweep this network" without
    anyone asking for that."""
    if endpoint.startswith(("vlan:", "snmp:")):
        return False
    try:
        return ipaddress.ip_network(host_part(endpoint), strict=False).num_addresses > 1
    except ValueError:
        return False


def sweep_is_authorized(cidr: str, authorized_targets: list[str]) -> tuple[bool, str | None]:
    """Pure containment decision: may this CIDR be swept given the declared
    scope entries and registered targets?

    * a sweep inside a declared network scope entry is authorized;
    * a single-host sweep (``/32`` / ``/128``) of a registered target is
      authorized — the operator already registered that host for probing;
    * everything else is refused. A CIDR that merely *overlaps* authorized
      space is NOT authorized: containment only, never partial.
    """
    try:
        wanted = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False, "target is not a valid CIDR"
    for target in authorized_targets:
        if target.startswith(("vlan:", "snmp:")):
            continue
        try:
            net = ipaddress.ip_network(host_part(target), strict=False)
        except ValueError:
            continue
        try:
            if wanted.version == net.version and wanted.subnet_of(net):
                return True, f"inside authorized scope {target}"
        except TypeError:  # pragma: no cover — mixed IP versions
            continue
    if wanted.num_addresses == 1:
        host_str = str(wanted.network_address)
        for target in authorized_targets:
            if host_part(target) == host_str:
                return True, f"{host_str} is a registered scan target"
    return False, "target is outside the authorized network scope"


# --------------------------------------------------------------------------- #
# the decision
# --------------------------------------------------------------------------- #

def admit_scan(
    *,
    scan_mode: str | None = None,
    active_probing_requested: bool = False,
    is_ot_trusted: bool | None = None,
    asset: str | None = None,
    region: str | None = None,
    environment: str | None = None,
) -> dict:
    """The single admission decision. Returns the decision dict when the
    scan may run; raises ``HTTPException`` 409 when refused and 503 when the
    decision cannot be made (fail-closed — no scan is accepted then).

    ``is_ot_trusted`` exists for server-side callers that *know* the target
    is OT from trusted state; request bodies never get to set it.
    """
    from control_plane.orchestrator import emergency_engaged
    from control_plane.safety import evaluate_scan

    try:
        events, policy = _control_plane_state()
        if emergency_engaged(events):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Scan rejected: emergency stop is engaged",
            )
        is_ot = bool(_ot_declared()) if is_ot_trusted is None else bool(is_ot_trusted)
        decision = evaluate_scan(policy, asset=asset, is_ot=is_ot)
        if not decision.permitted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Scan rejected by safe-scan policy: {decision.reason}",
            )
        wants_active = bool(active_probing_requested) or str(scan_mode or "").lower() in ACTIVE_SCAN_MODES
        if is_ot and wants_active:
            # An OT estate needs an ACTUAL approved maintenance window for
            # active probing — "no window declared" is not "window open".
            # (evaluate_scan treats empty windows as unrestricted for
            # general scanning, which is right for IT; for OT active probes
            # the absence of a declared window must mean "not now".)
            windows = (policy or {}).get("maintenance_windows") or []
            if not windows:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Scan rejected: OT estate has no approved maintenance window — "
                        "active probing requires a declared, currently-open window; "
                        "passive/safe modes remain available"
                    ),
                )
        if wants_active and not decision.active_probing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Scan rejected: active probing is not authorized now "
                    f"({decision.reason}); passive/safe modes remain available"
                ),
            )
        return {
            "mode": decision.mode,
            "active_probing": bool(decision.active_probing),
            "reason": decision.reason,
            "budgets": dict(decision.budgets),
            "is_ot": is_ot,
        }
    except HTTPException:
        raise
    except Exception as exc:
        # Fail closed: an admission we cannot make is an admission we refuse.
        # Logging-and-continuing here is precisely how an emergency stop turns
        # advisory during an outage.
        logger.exception("scan_admission_undecidable")
        from api.observability.operational_counters import incr

        incr("scan_admission_unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan admission is unavailable; no scan was accepted",
        ) from exc


def authorize_network_sweep(cidr: str) -> tuple[bool, str | None]:
    """Execution-time authorization for a CIDR sweep: the range must sit
    inside the tenant's declared network scope (or be a registered host).
    Registration-time enforcement lives in onboarding; this is the second
    half — validating *at execution* — so an authorized-at-registration
    target cannot be replaced by an unauthorized range at run time."""
    try:
        return sweep_is_authorized(cidr, _authorized_network_scope())
    except Exception as exc:
        logger.exception("network_sweep_authorization_unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Network scope could not be verified; no sweep was run",
        ) from exc
