"""One authority decision per collector plane: who, what, which revision, when,
how long, which permission.

Guide 116 graded the authorization model GAP on ten of eleven collector planes.
The reason was not that controls were missing — admission, budgets, windows and
permissions all existed *somewhere* — but that each plane got a different subset
of them, and nothing bound the subset to the collector. Two planes proved their
target admission; the rest were a shared import that a new adapter could simply
not call.

This module is the binding. Every plane declares a :class:`PlaneSpec` in code
(its entry point, the permission it needs, the shape of the target it accepts,
and the defaults for its window and budget), and every collection is authorized
through :func:`evaluate`, which answers all six questions in one place and
refuses with a named code for each one that fails.

The answers are not documentation: :func:`evaluate` is the function the route
calls, so the matrix in guide 116 is produced by running the same code path that
a real collection runs.

Two deliberate choices:

* **No descriptor, no collection.** The spec says what a plane *may* be approved
  for; a row in ``collector_authorities`` says an estate *did* approve it, with
  an owner and an expiry. A missing row is a refusal (``NO_APPROVAL``), never a
  default — an approval nobody signed is not an approval.
* **The revision is pinned.** A collection names the revision it was authorized
  under. A descriptor that has been re-approved since then refuses the stale
  name, which is what "which approved revision" has to mean to be worth asking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from db.models.collector_authority import CollectorAuthority

#: The six questions, in the order the matrix reads them.
QUESTIONS = ("who", "what_target", "which_revision", "when", "how_long", "permission")

QUESTION_TEXT = {
    "who": "who is asking (authenticated principal and role)",
    "what_target": "what may be touched (scope admission, not a free-form string)",
    "which_revision": "which approved revision of that scope (pinned, not re-read)",
    "when": "when it is allowed (window start and expiry)",
    "how_long": "how long and how much (runtime and traffic budget)",
    "permission": "which permission the route demands",
}

#: Refusal codes. One per question, so a caller can say which question failed
#: rather than "403".
NO_APPROVAL = "NO_APPROVAL"
UNKNOWN_PLANE = "UNKNOWN_PLANE"
REVOKED = "REVOKED"
STALE_REVISION = "STALE_REVISION"
OUTSIDE_WINDOW = "OUTSIDE_WINDOW"
EXHAUSTED = "EXHAUSTED"
TARGET_REFUSED = "TARGET_REFUSED"
PERMISSION_DENIED = "PERMISSION_DENIED"


@dataclass(frozen=True)
class PlaneSpec:
    """What a plane may be approved for. Reviewed with the routes, not with data."""

    name: str
    entry: str
    permission: str
    target_kind: str
    target_pattern: str
    default_max_targets: int = 64
    default_max_requests: int = 100
    default_max_runtime_seconds: int = 900
    default_window_seconds: int = 3600
    note: str = ""


#: The eleven planes guide 116 measured, with the entry point each one really has.
#: Where a plane is a catalogue adapter rather than a route, the entry names the
#: adapter — and the authority still applies, because the adapter is what the
#: collector runs.
PLANE_SPECS: dict[str, PlaneSpec] = {
    "NETWORK": PlaneSpec(
        name="NETWORK", entry="POST /api/v1/network/crypto-observe",
        permission="scan.trigger", target_kind="endpoint",
        target_pattern=r"^(?=.{4,253}$)(?!-)[a-z0-9][a-z0-9.\-]{1,250}:[0-9]{1,5}$",
        default_max_targets=256, default_max_requests=32, default_max_runtime_seconds=300,
        note="the only plane that opens a socket; the target must be one host and one port",
    ),
    "RUNTIME": PlaneSpec(
        name="RUNTIME", entry="POST /api/v1/runtime/crypto-events",
        permission="runtime.ingest", target_kind="agent-host",
        target_pattern=r"^[a-z0-9][a-z0-9._\-]{2,120}$",
        default_max_targets=500, default_max_requests=60, default_max_runtime_seconds=600,
        note="agent-produced events; the target is the host the agent runs on",
    ),
    "STATIC": PlaneSpec(
        name="STATIC", entry="POST /api/v1/scans",
        permission="scan.trigger", target_kind="repository",
        target_pattern=r"^[A-Za-z0-9_.\-]{1,80}/[A-Za-z0-9_.\-]{1,120}(@[0-9a-f]{7,64})?$",
        default_max_targets=50, default_max_requests=20, default_max_runtime_seconds=3600,
        note="a repository reference, optionally pinned to a commit",
    ),
    "PKI": PlaneSpec(
        name="PKI", entry="certificate inventory sync",
        permission="certificates.manage", target_kind="inventory",
        target_pattern=r"^inventory:[A-Za-z0-9_.\-]{1,120}$",
        default_max_targets=200, default_max_requests=30, default_max_runtime_seconds=900,
        note="certificate rows already in the inventory, named by inventory id",
    ),
    "CLOUD": PlaneSpec(
        name="CLOUD", entry="POST /api/v1/cloud/discover",
        permission="scan.manage", target_kind="account-region",
        target_pattern=r"^[a-z]{2,12}:account:[A-Za-z0-9\-]{4,64}/region:[a-z0-9\-]{2,32}$",
        default_max_targets=50, default_max_requests=40, default_max_runtime_seconds=1800,
        note="a named provider account and region, never a provider-wide sweep",
    ),
    "KUBERNETES": PlaneSpec(
        name="KUBERNETES", entry="kubectl adapter",
        permission="scan.trigger", target_kind="cluster-namespace",
        target_pattern=r"^cluster:[a-z0-9][a-z0-9\-]{1,60}/namespace:[a-z0-9][a-z0-9\-]{0,62}$",
        default_max_targets=100, default_max_requests=40, default_max_runtime_seconds=900,
        note="one cluster and one namespace; a cluster-wide read is a separate approval",
    ),
    "CMDB": PlaneSpec(
        name="CMDB", entry="CMDB adapter",
        permission="scan.trigger", target_kind="configuration-item",
        target_pattern=r"^cmdb:[A-Za-z0-9_.\-]{3,120}$",
        default_max_targets=200, default_max_requests=40, default_max_runtime_seconds=900,
        note="a configuration item, resolved through the CMDB adapter",
    ),
    "KMS": PlaneSpec(
        name="KMS", entry="KMS adapter",
        permission="crypto.ingest", target_kind="key",
        target_pattern=r"^kms:[A-Za-z0-9_.\-/:]{3,200}$",
        default_max_targets=100, default_max_requests=30, default_max_runtime_seconds=600,
        note="a key identifier; the collector never receives key material",
    ),
    "HSM": PlaneSpec(
        name="HSM", entry="HSM adapter",
        permission="hardware.ingest", target_kind="partition",
        target_pattern=r"^hsm:[A-Za-z0-9_.\-]{2,80}$",
        default_max_targets=50, default_max_requests=20, default_max_runtime_seconds=600,
        note="an HSM label; operations are approved individually elsewhere",
    ),
    "HARDWARE": PlaneSpec(
        name="HARDWARE", entry="POST /api/v1/host-evidence",
        permission="hardware.ingest", target_kind="host",
        target_pattern=r"^host:[A-Za-z0-9_.\-]{1,120}$",
        default_max_targets=200, default_max_requests=60, default_max_runtime_seconds=900,
        note="one enrolled host, by host evidence id",
    ),
    "VENDOR": PlaneSpec(
        name="VENDOR", entry="vendor attestation intake",
        permission="assurance.manage", target_kind="vendor",
        target_pattern=r"^vendor:[A-Za-z0-9_.\-]{2,120}$",
        default_max_targets=50, default_max_requests=20, default_max_runtime_seconds=600,
        note="a vendor record the attestation is attached to",
    ),
}

PLANES = tuple(PLANE_SPECS)


@dataclass
class Decision:
    """The answer to all six questions for one collection, plus any refusal."""

    plane: str
    allowed: bool
    answers: dict[str, dict[str, Any]] = field(default_factory=dict)
    refusals: list[dict[str, str]] = field(default_factory=list)
    revision: int | None = None
    remaining_requests: int | None = None
    remaining_runtime_seconds: int | None = None
    note: str = ""

    @property
    def refused(self) -> bool:
        return not self.allowed

    def as_dict(self) -> dict[str, Any]:
        return {
            "plane": self.plane,
            "allowed": self.allowed,
            "answers": self.answers,
            "refusals": self.refusals,
            "revision": self.revision,
            "remaining_requests": self.remaining_requests,
            "remaining_runtime_seconds": self.remaining_runtime_seconds,
            "note": self.note,
        }


def _answer(question: str, mechanism: str, detail: str) -> dict[str, Any]:
    return {"question": question, "mechanism": mechanism, "detail": detail,
            "meaning": QUESTION_TEXT[question]}


def target_problem(spec: PlaneSpec, target: str) -> str | None:
    """Why this target is not acceptable for this plane, or ``None``.

    A single host and a single port is a different kind of permission from "the
    network"; a shared validator that only checks non-emptiness is how a subnet
    sweep becomes a collection. The pattern is per plane and refuses the shapes
    that would turn one approval into a wider one.
    """
    if not target or not isinstance(target, str):
        return "a target is required: this authority is issued for named targets"
    value = target.strip().lower()
    if value in {"*", "all", "any", "0.0.0.0/0", "::/0"}:
        return "a wildcard target is not a target; name what may be collected"
    # A CIDR or a bare address is never a named target, on any plane — including
    # the source-scan plane, where "10.0.0.0/8" would otherwise parse as a
    # perfectly good owner/repository pair.
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
        return "an address or subnet is refused: approval binds exact destinations"
    except ValueError:
        pass
    if re.search(r"/\d{1,2}$", value):
        return "a CIDR is refused: approval binds exact destinations, not subnets"
    if not re.fullmatch(spec.target_pattern, value):
        return (f"{value!r} is not a valid {spec.target_kind} target for {spec.name}; "
                f"expected a value matching {spec.target_pattern}")
    return None


def _as_utc(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def descriptor(db: Any, plane: str, *, tenant_id: str | None = None
               ) -> CollectorAuthority | None:
    """The approved authority for this plane, if there is one.

    Authority rows are platform state, read under :func:`db.tenancy.platform_scope`
    the way the shared execution budget is: a collection is authorized for the
    platform's approval of that plane, not for whichever estate the request
    happens to carry. ``tenant_id`` remains an escape hatch for a per-estate
    approval, which is a later refinement rather than a different rule.
    """
    from sqlalchemy import select

    from db.tenancy import platform_scope

    stmt = select(CollectorAuthority).where(CollectorAuthority.plane == plane)
    stmt = stmt.where(
        CollectorAuthority.tenant_id == tenant_id
        if tenant_id else CollectorAuthority.tenant_id.is_(None)
    )
    with platform_scope():
        return db.execute(stmt).scalars().first()


def matrix(db: Any, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Every plane with its spec and its approval — the matrix the route serves."""
    rows: list[dict[str, Any]] = []
    for name, spec in PLANE_SPECS.items():
        row = descriptor(db, name, tenant_id=tenant_id)
        approved = row is not None and row.revoked_at is None
        gaps: list[str] = []
        if row is None:
            gaps.append(NO_APPROVAL)
        elif row.revoked_at is not None:
            gaps.append(REVOKED)
        elif _as_utc(row.expires_at) <= datetime.now(timezone.utc):
            gaps.append(OUTSIDE_WINDOW)
        rows.append({
            "plane": name,
            "entry": spec.entry,
            "permission": spec.permission,
            "target_kind": spec.target_kind,
            "note": spec.note,
            "approved": approved and not gaps,
            "gaps": gaps,
            "revision": row.revision if row else None,
            "approved_by": row.approved_by if row else None,
            "expires_at": _as_utc(row.expires_at).isoformat() if row and row.expires_at else None,
            "budget": {
                "window_seconds": row.window_seconds if row else spec.default_window_seconds,
                "max_targets": row.max_targets if row else spec.default_max_targets,
                "max_requests": row.max_requests if row else spec.default_max_requests,
                "max_runtime_seconds": (row.max_runtime_seconds if row
                                        else spec.default_max_runtime_seconds),
                "requests_used": row.requests_used if row else 0,
            },
        })
    return rows


# ------------------------------------------------------------------- approval --- #
class AuthorityRefused(Exception):
    """A refusal with a code, so the caller can say which question failed."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def approve(db: Any, *, plane: str, approver: str, permission: str | None = None,
            valid_days: int = 90, max_targets: int | None = None,
            max_requests: int | None = None, max_runtime_seconds: int | None = None,
            window_seconds: int | None = None,
            tenant_id: str | None = None) -> CollectorAuthority:
    """Record an approval, bumping the revision. Revives a revoked plane."""
    spec = PLANE_SPECS.get(plane)
    if spec is None:
        raise AuthorityRefused(UNKNOWN_PLANE, f"{plane!r} is not a collector plane")
    permission = permission or spec.permission
    from api.security.rbac import PERMISSION_MATRIX

    if permission not in PERMISSION_MATRIX:
        raise AuthorityRefused(
            PERMISSION_DENIED,
            f"{permission!r} is not a permission this platform defines; an authority "
            "granted against a permission nothing checks is decoration",
        )
    if valid_days < 1 or valid_days > 366:
        raise AuthorityRefused(
            OUTSIDE_WINDOW,
            "an approval window must be between 1 and 366 days: an authority without an "
            "expiry is a standing permission nobody revisits",
        )
    from db.tenancy import platform_scope

    now = datetime.now(timezone.utc)
    row = descriptor(db, plane, tenant_id=tenant_id)
    with platform_scope():
        return _write_approval(db, row, spec, permission, approver, now, valid_days,
                               max_targets, max_requests, max_runtime_seconds,
                               window_seconds, tenant_id)


def _write_approval(db: Any, row: CollectorAuthority | None, spec: PlaneSpec,
                    permission: str, approver: str, now: datetime, valid_days: int,
                    max_targets: int | None, max_requests: int | None,
                    max_runtime_seconds: int | None, window_seconds: int | None,
                    tenant_id: str | None) -> CollectorAuthority:
    if row is None:
        row = CollectorAuthority(
            tenant_id=tenant_id, plane=spec.name, entry=spec.entry,
            permission=permission, target_kind=spec.target_kind,
            revision=1, approved_by=approver, approved_at=now,
            expires_at=now + timedelta(days=valid_days),
            max_targets=max_targets or spec.default_max_targets,
            max_requests=max_requests or spec.default_max_requests,
            max_runtime_seconds=max_runtime_seconds or spec.default_max_runtime_seconds,
            window_seconds=window_seconds or spec.default_window_seconds,
        )
        db.add(row)
    else:
        row.entry = spec.entry
        row.permission = permission
        row.target_kind = spec.target_kind
        row.revision = int(row.revision) + 1
        row.approved_by = approver
        row.approved_at = now
        row.expires_at = now + timedelta(days=valid_days)
        row.revoked_at = None
        row.revoked_by = None
        row.max_targets = max_targets or row.max_targets
        row.max_requests = max_requests or row.max_requests
        row.max_runtime_seconds = max_runtime_seconds or row.max_runtime_seconds
        row.window_seconds = window_seconds or row.window_seconds
        row.requests_used = 0
        row.runtime_seconds_used = 0
        row.window_started_at = None
    db.commit()
    return row


def revoke(db: Any, *, plane: str, revoked_by: str,
           tenant_id: str | None = None) -> CollectorAuthority:
    """Withdraw an approval. Rows are kept: a revocation is a fact, not a delete."""
    if plane not in PLANE_SPECS:
        raise AuthorityRefused(UNKNOWN_PLANE, f"{plane!r} is not a collector plane")
    row = descriptor(db, plane, tenant_id=tenant_id)
    if row is None:
        raise AuthorityRefused(NO_APPROVAL, f"{plane} has no approval to revoke")
    from db.tenancy import platform_scope

    with platform_scope():
        row.revoked_at = datetime.now(timezone.utc)
        row.revoked_by = revoked_by
        db.commit()
    return row


# ------------------------------------------------------------------ evaluation --- #
def evaluate(db: Any, *, plane: str, principal: str, roles: Iterable[str],
             target: str, revision: int | None, requests: int = 1,
             runtime_seconds: int = 0, now: datetime | None = None,
             consume: bool = True, tenant_id: str | None = None) -> Decision:
    """Answer all six questions and refuse for the first that fails.

    Every refusal names the question it came from. The decision is recorded with
    the same six answers whether it allowed the collection or not, which is what
    makes the matrix in guide 116 a measurement rather than a diagram.
    """
    from api.security.rbac import PERMISSION_MATRIX, has_permission, normalize_roles

    moment = _as_utc(now) or datetime.now(timezone.utc)
    decision = Decision(plane=plane, allowed=True, note=PLANE_SPECS.get(plane).note
                        if plane in PLANE_SPECS else "")
    spec = PLANE_SPECS.get(plane)
    if spec is None:
        decision.allowed = False
        decision.refusals.append({"question": "who", "code": UNKNOWN_PLANE,
                                  "detail": f"{plane!r} is not a collector plane"})
        return decision

    role_list = normalize_roles(list(roles))

    # WHO — the session gate named a principal and its durable roles.
    decision.answers["who"] = _answer(
        "who", "session principal + role store",
        f"principal {principal!r} with roles {role_list or ['none']}; a request with no "
        "session never reaches this function")

    # PERMISSION — the plane's own permission, not the route's.
    allowed_roles = sorted(PERMISSION_MATRIX.get(spec.permission, frozenset()))
    if not has_permission(role_list, spec.permission):
        decision.allowed = False
        decision.refusals.append({
            "question": "permission", "code": PERMISSION_DENIED,
            "detail": f"{plane} requires {spec.permission}; roles {role_list} do not "
                      f"include {allowed_roles}",
        })
    decision.answers["permission"] = _answer(
        "permission", f"PERMISSION_MATRIX[{spec.permission!r}]",
        f"{spec.permission} is granted to {allowed_roles}")

    # WHAT — the target has to be a named target of the right kind.
    problem = target_problem(spec, target)
    if problem:
        decision.allowed = False
        decision.refusals.append({"question": "what_target", "code": TARGET_REFUSED,
                                  "detail": problem})
    decision.answers["what_target"] = _answer(
        "what_target", f"{spec.target_kind} validator",
        f"target {target!r}" + (f" — {problem}" if problem else " accepted"))

    # The rest needs an approval; without one there is nothing to check against.
    row = descriptor(db, plane, tenant_id=tenant_id)
    if row is None:
        decision.allowed = False
        decision.refusals.append({
            "question": "which_revision", "code": NO_APPROVAL,
            "detail": f"{plane} has no approved authority in this estate; approve one "
                      "before collecting",
        })
        decision.answers["which_revision"] = _answer(
            "which_revision", "none", "no approval exists")
        for question in ("when", "how_long"):
            decision.answers[question] = _answer(question, "none", "no approval exists")
        return decision

    decision.revision = int(row.revision)

    # WHICH REVISION — pinned, and a stale name is refused rather than ignored.
    if row.revoked_at is not None:
        decision.allowed = False
        decision.refusals.append({
            "question": "which_revision", "code": REVOKED,
            "detail": f"{plane} was revoked by {row.revoked_by} at "
                      f"{_as_utc(row.revoked_at).isoformat()}",
        })
    elif revision is None:
        decision.allowed = False
        decision.refusals.append({
            "question": "which_revision", "code": STALE_REVISION,
            "detail": f"{plane} is approved at revision {row.revision}; a collection must "
                      f"name the revision it runs under",
        })
    elif int(revision) != int(row.revision):
        decision.allowed = False
        decision.refusals.append({
            "question": "which_revision", "code": STALE_REVISION,
            "detail": f"{plane} is approved at revision {row.revision}, not {revision}; "
                      "re-read the approval before collecting",
        })
    decision.answers["which_revision"] = _answer(
        "which_revision", "collector_authorities.revision",
        f"approved revision {row.revision}, approved by {row.approved_by}")

    # WHEN — inside the approval window.
    expires = _as_utc(row.expires_at)
    approved_at = _as_utc(row.approved_at)
    if expires is None or moment >= expires:
        decision.allowed = False
        decision.refusals.append({
            "question": "when", "code": OUTSIDE_WINDOW,
            "detail": f"the approval expired at {expires.isoformat() if expires else 'never'}",
        })
    decision.answers["when"] = _answer(
        "when", "collector_authorities.expires_at",
        f"[{approved_at.isoformat() if approved_at else '—'}, "
        f"{expires.isoformat() if expires else '—'})")

    # HOW LONG — a rolling window budget, charged under a compare-and-set.
    # The window is computed into locals, never by mutating the row: this session
    # may be the request's tenant-scoped one, and a platform row left dirty in its
    # identity map is refused at flush time by the tenancy guard. The only write
    # is the compare-and-set below, which is the reservation itself.
    started = _as_utc(row.window_started_at)
    window = int(row.window_seconds or 3600)
    lapsing = started is None or (moment - started) >= timedelta(seconds=window)
    used = 0 if lapsing else int(row.requests_used or 0)
    runtime_used = 0 if lapsing else int(row.runtime_seconds_used or 0)
    window_started = moment if lapsing else started
    if requests < 1 or requests > int(row.max_requests):
        decision.allowed = False
        decision.refusals.append({
            "question": "how_long", "code": EXHAUSTED,
            "detail": f"{requests} requests exceeds the {row.max_requests}-request budget "
                      "of one approval",
        })
    elif used + requests > int(row.max_requests):
        decision.allowed = False
        decision.refusals.append({
            "question": "how_long", "code": EXHAUSTED,
            "detail": f"{used} of {row.max_requests} requests already spent in "
                      f"this {window}-second window",
        })
    elif runtime_seconds > int(row.max_runtime_seconds):
        decision.allowed = False
        decision.refusals.append({
            "question": "how_long", "code": EXHAUSTED,
            "detail": f"{runtime_seconds}s exceeds the {row.max_runtime_seconds}s runtime "
                      "budget of one approval",
        })
    elif runtime_used + runtime_seconds > int(row.max_runtime_seconds):
        decision.allowed = False
        decision.refusals.append({
            "question": "how_long", "code": EXHAUSTED,
            "detail": f"{runtime_used}s of {row.max_runtime_seconds}s runtime already spent "
                      f"in this {window}-second window",
        })

    if decision.allowed:
        decision.remaining_requests = int(row.max_requests) - (used + requests)
        decision.remaining_runtime_seconds = (int(row.max_runtime_seconds)
                                              - (runtime_used + runtime_seconds))
        if consume:
            from sqlalchemy import update

            from db.tenancy import platform_scope

            with platform_scope():
                result = db.execute(
                    update(CollectorAuthority)
                    .execution_options(synchronize_session=False)
                    .where(CollectorAuthority.id == row.id,
                           CollectorAuthority.version == row.version)
                    .values(requests_used=used + requests,
                            runtime_seconds_used=runtime_used + runtime_seconds,
                            window_started_at=window_started,
                            version=int(row.version) + 1)
                )
                reserved = result.rowcount == 1
                if reserved:
                    db.commit()
            if not reserved:
                # Two collections spent the same unit; neither may proceed on a
                # budget it did not actually reserve.
                db.rollback()
                decision.allowed = False
                decision.refusals.append({
                    "question": "how_long", "code": EXHAUSTED,
                    "detail": "the budget changed while this decision was being made; "
                              "nothing was authorized",
                })
    else:
        decision.remaining_requests = max(0, int(row.max_requests) - used)
        decision.remaining_runtime_seconds = max(0, int(row.max_runtime_seconds) - runtime_used)

    decision.answers["how_long"] = _answer(
        "how_long", "collector_authorities rolling window",
        f"{requests} request(s) and {runtime_seconds}s against "
        f"{row.max_requests} requests / {row.max_runtime_seconds}s per {window}s window",
    )
    return decision
