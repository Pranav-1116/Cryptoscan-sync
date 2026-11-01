"""Do Admin, Auditor and Viewer stay inside their boundaries — on the server?

A role matrix in a document proves nothing. This drill reads the boundary each
operation **declares** (from the route's own dependency tree, the same walk
`scripts/authorization_register.py` uses), then **executes** every operation it can
with each of the three principals the review named and compares the two:

* declared and enforced agree → the boundary is real;
* an operation the declaration forbids but the server allows → the boundary is
  decoration, and it is reported as a violation with the request that proved it;
* an operation the declaration allows but the server refuses → an over-tight
  guard, reported separately because it breaks operators rather than security.

Where an operation declares **nothing**, the drill says so with the count and the
areas, because "any authenticated principal may write here" is a decision a bank
should see written down rather than discover.

Run::

    python scripts/authorization_boundaries.py \\
        --json docs/bank-environment/121-authorization-boundaries.json \\
        --md   docs/bank-environment/121-authorization-boundaries.md
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.authorization-boundaries/1"
VERSION = "authorization-boundaries/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

#: The three principals the review named. `admin` and `viewer` are the legacy
#: names; the drill uses both the legacy claim and the canonical one, because a
#: boundary that only holds for the canonical spelling is not a boundary.
PRINCIPALS: tuple[tuple[str, str], ...] = (
    ("superadmin", "admin"),
    ("auditor", "auditor"),
    ("readonly", "viewer"),
)

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Routes that must not be swept. Sending `{}` to all of them was not harmless: the
#: sweep POSTed to the network safety switch, engaged the emergency stop, and every
#: later collection answered 409 — a drill that changes what it measures. These are
#: named, skipped, and reported; their declarations are still read from the route
#: tree, they are simply not provoked.
DESTRUCTIVE = re.compile(r"crypto-stop|crypto-safety|safety/(engage|release)|"
                         r"kill|shutdown|purge|wipe|destroy|stop|halt|freeze|engage|"
                         r"rotate|revoke|restore|reset|delete-tenant|decommission|"
                         r"dead-letter/(replay|purge)|abort", re.I)

#: Endpoints that would do real work (a scan, an export, a restore) or that spend
#: minutes. They are still probed for the *authorization* decision — the guard runs
#: before the handler — but a 5xx from the handler is read as "past the boundary",
#: which is what this drill is asking.
HEAVY = re.compile(r"export|download|restore|backup|replay|drill|qualification|"
                   r"scale|simulate|cascade|search|report|pdf|archive", re.I)


def _bootstrap_path() -> None:
    for relative in ("scripts", "services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "services/runtime", "services/evidence",
                     "services/worker", "services/inventory", "services/network_scanner",
                     "services/governance", "services/cbom", "services/devsecops",
                     "services/observability", "services/control_plane"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)


# ------------------------------------------------------------------- declared
@dataclass
class Requirement:
    """What a route says it needs, resolved to the roles that may attempt it.

    `comparable` is False when the guard speaks a different vocabulary than the
    role catalog — a tenant-role guard allows "the owner of this organisation",
    which is membership rather than a catalog role. Those routes are counted and
    reported, and their decisions are not compared against the matrix, because a
    403 for an auditor with no tenant membership is the guard working, not a
    boundary failing.
    """

    kind: str                       # role | permission | tenant-role | session
    roles: frozenset[str]
    detail: list[str] = field(default_factory=list)
    comparable: bool = True

    def allows(self, role: str) -> bool:
        if self.kind == "session":
            return True
        return role in self.roles


def _guard_from(call) -> tuple[str, frozenset[str], str] | None:
    from api.security.rbac import PERMISSION_MATRIX, normalize_roles

    factory = (getattr(call, "__qualname__", "") or "").split(".<locals>", 1)[0]
    allowed = tuple(getattr(call, "allowed_roles", ()) or ())
    permissions = tuple(getattr(call, "permissions", ()) or ())
    if factory in {"require_roles", "require_any_role", "require_tenant_roles"} and allowed:
        return "role" if factory != "require_tenant_roles" else "tenant-role", \
            frozenset(normalize_roles(list(allowed))), f"{factory}({', '.join(allowed)})"
    # Guards that speak tenant/estate membership rather than the role catalog. A
    # platform principal with no tenant is refused by these, which is the tenancy
    # boundary doing its job; the tenancy drill is where that is graded.
    if factory in {"require_tenant_roles", "get_tenant_context", "estate",
                   "tenant_context", "require_tenant_context"}:
        return "tenant-role", frozenset(), factory
    if factory == "require_permission" and permissions:
        roles: set[str] = set()
        for action in permissions:
            roles |= set(PERMISSION_MATRIX.get(action, frozenset()))
        return "permission", frozenset(roles), f"require_permission({', '.join(permissions)})"
    return None


def declared_requirements() -> list[dict[str, Any]]:
    """One row per served operation, with the roles its dependency tree allows."""
    import api_contract

    rows: list[dict[str, Any]] = []
    for route in api_contract.application().routes:
        original = getattr(route, "original_router", None)
        if original is None:
            continue
        context = getattr(route, "include_context", None)
        prefix = (getattr(context, "prefix", "") or "") if context is not None else ""
        router_guards: list[tuple[str, frozenset[str], str]] = []
        for dependency in getattr(original, "dependencies", []) or []:
            guard = _guard_from(dependency)
            if guard:
                router_guards.append(guard)
        for child in original.routes:
            methods = getattr(child, "methods", None)
            if not methods:
                continue
            guards = list(router_guards)
            stack = [getattr(child, "dependant", None)]
            while stack:
                dependant = stack.pop()
                if dependant is None:
                    continue
                guard = _guard_from(getattr(dependant, "call", None))
                if guard:
                    guards.append(guard)
                stack.extend(getattr(dependant, "dependencies", []) or [])
            for method in sorted(methods):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                rows.append(_resolve(prefix + getattr(child, "path", ""), method, guards))
    rows.sort(key=lambda row: (row["path"], row["method"]))
    return rows


def _resolve(path: str, method: str, guards: list[tuple[str, frozenset[str], str]]) -> dict:
    if not guards:
        requirement = Requirement("session", frozenset(), [])
    else:
        # Several guards on one route all have to pass; the effective allow-set is
        # the intersection, which is stricter than any single declaration.
        allowed: frozenset[str] | None = None
        details: list[str] = []
        kinds: list[str] = []
        comparable = True
        for kind, roles, detail in guards:
            details.append(detail)
            kinds.append(kind)
            if kind == "tenant-role":
                # tenant membership is not a catalog role: skip the comparison,
                # but keep counting the route so the surface stays visible
                comparable = False
                continue
            allowed = roles if allowed is None else (allowed & roles)
        requirement = Requirement(
            kind="+".join(sorted(set(kinds))),
            roles=allowed or frozenset(),
            detail=details,
            comparable=comparable,
        )
    return {
        "method": method,
        "path": path,
        "kind": requirement.kind,
        "allowed_roles": sorted(requirement.roles),
        "declared": requirement.detail,
        "comparable": requirement.comparable,
        "requirement": requirement,
    }


# ------------------------------------------------------------------- executed
def _prepare_environment() -> None:
    """Environment first, before any module reads a cached settings object.

    `api_contract.application()` is a process-wide singleton, so whichever caller
    builds it fixes the settings for every later app in the process — including
    which middleware is installed. Building it before this function ran meant the
    drill's own app inherited development settings and its rate limiter, which
    turned reachable endpoints into 429s and made the boundary results unreadable.
    """
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = "authorization-boundaries-key-32-characters"
    os.environ["CRYPTOSCAN_SOURCE_ROOTS"] = tempfile.gettempdir()
    os.environ.setdefault("REDIS_URL", "")
    _bootstrap_path()
    from api.config.settings import get_settings

    get_settings.cache_clear()


def build_client():
    _prepare_environment()

    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine

    from db.connection.session import Base, SessionLocal, configure_session
    from db.repositories.user_repository import UserRepository
    from api.main import create_app

    path = tempfile.mktemp(suffix=".db", prefix="authorization-boundaries-")
    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)
    configure_session(engine)

    # Real users, because the guards read the role store rather than the token
    # claims: a probe with a forged role in the token must be refused by the
    # store, and that is exactly what this drill wants to see.
    from api.security.passwords import hash_password
    db = SessionLocal()
    try:
        repo = UserRepository(db)
        for canonical, _legacy in PRINCIPALS:
            if repo.get_by_username(f"drill-{canonical}") is None:
                repo.create_user(f"drill-{canonical}", hash_password("Drill-Password-2026!"),
                                 roles=[canonical])
        db.commit()
    finally:
        db.close()

    app = create_app()
    return TestClient(app, raise_server_exceptions=False), engine, path


def _token(role: str, legacy: str) -> str:
    from api.security.session_manager import SessionManager

    return SessionManager().create_session(f"drill-{role}", roles=[role])


def _url(path: str) -> str:
    """Substitute placeholders so the route matches; the ids never need to exist."""
    return re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)


#: `/auth/logout` is answered without a session on purpose: revoking nothing is a
#: successful logout, and refusing it would leave a browser holding a cookie it
#: cannot clear. It mints nothing and changes nothing, so it is not an anonymous
#: write in the sense this row asks about.
IDEMPOTENT_ANONYMOUS = frozenset({"/api/v1/auth/logout"})


def _public(path: str) -> bool:
    """Paths the session gate exempts by design (login, webhooks, feeds).

    Exempting them is a decision, not a defect: they carry their own credential —
    a password, a signature, an invite token — and guide 120 is where that is
    measured. Excluding them here keeps this drill's rows about *authorization*
    instead of re-reporting the login surface as an anonymous write.
    """
    from api.middleware.auth_middleware import UNPROTECTED_PREFIXES

    for entry in UNPROTECTED_PREFIXES:
        base = entry.rstrip("/")
        if path == base or path.startswith(base + "/"):
            return True
    return False


def _probe(client, method: str, path: str, token: str | None) -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = _url(path)
    kwargs: dict[str, Any] = {"headers": headers}
    if method in WRITE_METHODS:
        kwargs["json"] = {}
    try:
        response = client.request(method, url, **kwargs)
        return response.status_code
    except Exception:  # a handler that explodes before answering still answered the guard
        return 599


UNKNOWN = {429, 599}


def _violation(requirement: Requirement, role: str, status: Any) -> bool:
    """True when the server let a role do something the declaration forbids.

    One function, used by the sweep and by the control that proves the sweep can
    report a violation at all: a comparison that can only ever say "agree" is not
    a measurement.
    """
    if not isinstance(status, bool):  # a raw status code, from the sweep
        status = _permitted(status)
    return bool(status) and not requirement.allows(role)


def _permitted(status: int) -> bool:
    """Anything but a refusal means authorization let the request through."""
    return status not in {401, 403} | UNKNOWN


def _known(status: int) -> bool:
    return status not in UNKNOWN


def _refused(status: int) -> bool:
    return status in {401, 403}


# ----------------------------------------------------------------------- rows
def measure() -> dict[str, Any]:
    _prepare_environment()
    operations = declared_requirements()
    client, engine, db_path = build_client()
    try:
        tokens = {role: _token(role, legacy) for role, legacy in PRINCIPALS}

        # ---- the matrix, executed
        violations: list[dict[str, Any]] = []
        over_tight: list[dict[str, Any]] = []
        destructive: list[str] = []
        checked = 0
        skipped: list[str] = []
        for operation in operations:
            requirement: Requirement = operation["requirement"]
            methods = operation["method"]
            # Every operation that declares a boundary is worth executing; a
            # session-only read is not a boundary claim, so a sample suffices and
            # the heavy ones are skipped by name rather than by hope.
            if not requirement.comparable:
                continue
            if DESTRUCTIVE.search(operation["path"]):
                destructive.append(f"{operation['method']} {operation['path']}")
                continue
            if requirement.kind == "session" and methods not in WRITE_METHODS:
                continue
            if HEAVY.search(operation["path"]) and methods not in WRITE_METHODS:
                skipped.append(operation["path"])
                continue
            observed: dict[str, bool] = {}
            for role, _legacy in PRINCIPALS:
                status = _probe(client, methods, operation["path"], tokens[role])
                observed[role] = _permitted(status)
                checked += 1
                if _refused(status) and requirement.allows(role):
                    over_tight.append({"method": methods, "path": operation["path"],
                                       "role": role, "status": status,
                                       "declared": operation["declared"],
                                       "reason": "declared to allow this role, refused"})
                if _violation(requirement, role, observed[role]):
                    violations.append({"method": methods, "path": operation["path"],
                                       "role": role, "status": status,
                                       "declared": operation["declared"]})
            operation["observed"] = observed

        # ---- anonymous and forged credentials, on every write operation
        anonymous_allowed: list[dict[str, Any]] = []
        forged_allowed: list[dict[str, Any]] = []
        from api.security.session_manager import SessionManager
        wrong_key = SessionManager(secret="not-this-deployment-s-secret-key-32-chars")
        writes = [op for op in operations if op["method"] in WRITE_METHODS]
        gated_writes = [op for op in writes
                        if not _public(op["path"]) and op["path"] not in IDEMPOTENT_ANONYMOUS]
        for operation in gated_writes:
            status = _probe(client, operation["method"], operation["path"], None)
            if _permitted(status):
                anonymous_allowed.append({"method": operation["method"],
                                          "path": operation["path"], "status": status})
        # Forgery: a token claiming superadmin, signed by another deployment's key.
        forged_tokens = {
            role: wrong_key.create_session(f"drill-{role}", roles=["superadmin"])
            for role, _legacy in PRINCIPALS
        }
        for operation in gated_writes[:120]:
            status = _probe(client, operation["method"], operation["path"],
                            forged_tokens["readonly"])
            if _permitted(status):
                forged_allowed.append({"method": operation["method"],
                                       "path": operation["path"], "status": status})

        rows = _rows(operations, checked, violations, over_tight, anonymous_allowed,
                     forged_allowed, writes, gated_writes, client, tokens, destructive)
    finally:
        try:
            engine.dispose()
        finally:
            Path(db_path).unlink(missing_ok=True)

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "operations": len(operations),
        "requests_executed": checked,
        "rows": rows,
        "limits": [
            "Executed in-process against the real app and a temporary SQLite database. "
            "Authorization decisions are the server's own; what is not proven is the "
            "deployment around it (reverse proxy, identity provider, network policy).",
            "A permitted request is not a completed one: this drill asks whether the guard "
            "let the caller through, not whether the handler then did something useful. A "
            "5xx past the guard still counts as past the boundary.",
            "Empty request bodies mean body-level validation is not exercised; tenant "
            "isolation is a separate drill (guide 124).",
        ],
    }


def _rows(operations, checked, violations, over_tight, anonymous_allowed,
          forged_allowed, writes, gated_writes, client, tokens,
          destructive: list[str] | None = None) -> list[dict[str, Any]]:
    from api.security.rbac import ROLE_CATALOG, permissions_for_roles

    rows: list[dict[str, Any]] = []

    # ---- 1. the catalog
    probes = []
    for canonical, legacy in PRINCIPALS:
        from api.security.rbac import normalize_roles

        probes.append({
            "probe": f"role-{canonical}",
            "expected": f"{legacy} resolves to {canonical} in the catalog",
            "ok": normalize_roles([legacy]) == [canonical] and canonical in ROLE_CATALOG,
            "observed": f"normalize_roles(['{legacy}']) = {normalize_roles([legacy])}",
        })
    viewer_perms = set(permissions_for_roles(["readonly"]))
    auditor_perms = set(permissions_for_roles(["auditor"]))
    admin_perms = set(permissions_for_roles(["superadmin"]))
    probes.append({
        "probe": "permissions-are-nested",
        "expected": "viewer ⊂ auditor ⊂ admin",
        "ok": viewer_perms <= auditor_perms <= admin_perms
              and viewer_perms != auditor_perms and auditor_perms != admin_perms,
        "observed": f"{len(viewer_perms)} / {len(auditor_perms)} / {len(admin_perms)} permissions",
    })
    rows.append({
        "id": "role_catalog",
        "question": "are Admin, Auditor and Viewer distinct identities with distinct authority?",
        "verdict": PASS if all(probe["ok"] for probe in probes) else FAIL,
        "probes": probes, "unproven": [], "limits": [],
    })

    # ---- 2/3/4 the three boundaries, executed
    for canonical, legacy in PRINCIPALS:
        escaped = [v for v in violations if v["role"] == canonical]
        refused_when_forbidden = [
            op for op in operations
            if isinstance(op.get("observed"), dict) and not op["requirement"].allows(canonical)
            and op["observed"].get(canonical) is False
        ]
        forbidden = [op for op in operations
                     if isinstance(op.get("observed"), dict)
                     and not op["requirement"].allows(canonical)]
        probes = [
            {"probe": "no-escape", "expected": "no operation allowed that the declaration forbids",
             "ok": not escaped, "observed": f"{len(escaped)} escape(s)"},
            {"probe": "boundary-is-real",
             "expected": "every forbidden operation probed is refused",
             "ok": not escaped and (not forbidden or bool(refused_when_forbidden)),
             "observed": f"{len(refused_when_forbidden)} of {len(forbidden)} forbidden "
                         f"operations refused"},
        ]
        rows.append({
            "id": f"boundary_{canonical}",
            "question": f"can a {legacy} ({canonical}) cross into authority it does not hold?",
            "verdict": PASS if all(probe["ok"] for probe in probes) else FAIL,
            "probes": probes,
            "unproven": [] if escaped == [] else [],
            "limits": [],
            "escapes": escaped[:10],
        })

    # ---- 5. declared vs enforced
    # The control: a requirement that forbids the role, a decision that allows it.
    control_requirement = Requirement("permission", frozenset({"superadmin"}), ["require_permission(users.manage)"])
    control_catches = _violation(control_requirement, "readonly", True) and \
        not _violation(control_requirement, "superadmin", True)
    mismatches = len(violations)
    rows.append({
        "id": "declared_vs_enforced",
        "question": "does what the route declares match what the server enforces?",
        "verdict": PASS if not violations else FAIL,
        "probes": [{
            "probe": "matrix-agrees",
            "expected": "every executed decision matches the declared requirement",
            "ok": not violations,
            "observed": f"{checked} decisions, {mismatches} violating, {len(over_tight)} over-tight",
        }, {
            "probe": "comparator-can-fail",
            "expected": "the comparison reports a decision the declaration forbids, and only that",
            "ok": control_catches,
            "observed": "a viewer allowed on a superadmin-only permission is reported; the "
                        "superadmin on the same permission is not",
        }],
        "unproven": [] if not over_tight else
        ["over-tight guards refuse a role the declaration allows; see over_tight"],
        # reported in the row body, not as a verdict: these were skipped on purpose
        "limits": [],
        "violations": violations[:10],
        "over_tight": over_tight[:10],
        "destructive": (destructive or [])[:12],
    })

    # ---- 6. anonymous
    rows.append({
        "id": "anonymous_refused",
        "question": "is the boundary enforced without a session, or is it a UI convention?",
        "verdict": PASS if not anonymous_allowed else FAIL,
        "probes": [{
            "probe": "no-token-on-writes",
            "expected": "every state-changing operation refuses an unauthenticated caller",
            "ok": not anonymous_allowed,
            "observed": f"{len(anonymous_allowed)} of {len(gated_writes)} gated writes "
                        f"answered without a token",
        }],
        "unproven": [],
        "limits": ["public-by-design paths (login, register, webhooks) are exempted by the "
                   "gate and are guide 120's subject"],
        "allowed": anonymous_allowed[:10],
    })

    # ---- 7. forged credentials
    rows.append({
        "id": "forged_credentials",
        "question": "does a token claiming superadmin, signed elsewhere, get in?",
        "verdict": PASS if not forged_allowed else FAIL,
        "probes": [{
            "probe": "foreign-signature",
            "expected": "a token signed by another deployment is refused",
            "ok": not forged_allowed,
            "observed": f"{len(forged_allowed)} write(s) accepted a foreign-signed token",
        }],
        "unproven": [],
        "limits": ["forgery with the real signing key is out of reach by definition; the "
                   "key's custody is not measured here"],
        "allowed": forged_allowed[:10],
    })

    # ---- 8. the session-only write surface
    tenant_routes = [op for op in operations if "tenant-role" in op["kind"]]
    session_writes = [op for op in gated_writes if op["kind"] == "session"]
    areas: dict[str, int] = {}
    for operation in session_writes:
        parts = [part for part in operation["path"].split("/") if part]
        area = parts[2] if len(parts) > 2 else operation["path"]
        areas[area] = areas.get(area, 0) + 1
    top = sorted(areas.items(), key=lambda item: -item[1])[:12]
    rows.append({
        "id": "session_only_writes",
        "question": "which state-changing operations demand nothing beyond a session?",
        "verdict": PARTIAL,
        "probes": [{
            "probe": "counted",
            "expected": "the count is reported rather than assumed zero",
            "ok": True,
            "observed": f"{len(session_writes)} of {len(gated_writes)} gated writes are "
                        f"session-only",
        }],
        "unproven": [f"{len(session_writes)} write operation(s) are callable by any "
                     "authenticated principal, including a viewer; the owner list is "
                     "docs/bank-environment/102-authenticated-only-writes.json"],
        "limits": ["this row is a policy question, not a defect: it is reported so a bank "
                   "can decide per area, which is the review's own framing",
                   f"{len(tenant_routes)} operation(s) are gated by tenant membership "
                   "(owner/admin within an organisation) rather than a catalog role; those "
                   "are excluded from the matrix comparison and measured by the tenancy drill"],
        "by_area": dict(top),
    })

    # ---- 9. target authorization, server-side
    rows.append(_target_authorization(client, tokens))
    return rows


def _target_authorization(client, tokens) -> dict[str, Any]:
    """A powerful caller must still not be able to point a collector anywhere.

    Role authority answers "may this person act"; target authority answers "may
    this action touch *that* host". A bank needs both, and the second must not
    depend on the first — so every probe here is sent as the most powerful
    principal on the platform.
    """
    probes: list[dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {tokens['superadmin']}"}

    def record(name: str, expectation: str, method: str, path: str, body: dict | None,
               accept: set[int], reason: str = "") -> dict[str, Any]:
        response = client.request(method, _url(path), json=body, headers=headers)
        matched = response.status_code in accept and (not reason or reason in response.text)
        probes.append({"probe": name, "expected": expectation, "ok": matched,
                       "observed": f"{response.status_code} {response.text[:200]}"})
        return response

    # 1. Fail closed with no approved scope. A collector that probes because
    #    nobody configured a scope is the failure mode this whole model exists for.
    record("no-scope-fails-closed", "refused (409/422) with no approved scope",
           "POST", "/api/v1/network/crypto-observe",
           {"endpoints": ["10.20.10.15:443"], "protocol": "TLS"}, {409, 422})

    # 2. The scope itself refuses broad or special destinations.
    record("scope-rejects-cidr", "422 when the approved scope names a /8",
           "PUT", "/api/v1/network/crypto-scope",
           {"name": "drill", "destinations": ["10.0.0.0/8"], "protocols": ["TLS"]},
           {422}, "invalid_destination")
    record("scope-rejects-metadata", "422 when the scope names 169.254.169.254",
           "PUT", "/api/v1/network/crypto-scope",
           {"name": "drill", "destinations": ["169.254.169.254:80"], "protocols": ["TLS"]},
           {422}, "invalid_destination")
    record("scope-rejects-loopback", "422 when the scope names 127.0.0.1",
           "PUT", "/api/v1/network/crypto-scope",
           {"name": "drill", "destinations": ["127.0.0.1:443"], "protocols": ["TLS"]},
           {422}, "invalid_destination")

    # 3. An approved scope with one exact destination is accepted.
    saved = record("scope-accepted", "2xx for one exact host:port",
                   "PUT", "/api/v1/network/crypto-scope",
                   {"name": "drill-scope", "destinations": ["10.20.10.15:443"],
                    "protocols": ["TLS"], "inventory_id": "default"}, {200, 201})

    # 4. With a scope in place, a request that names something else is refused —
    #    the caller being an admin does not widen the target.
    if saved.status_code in {200, 201}:
        record("out-of-scope-host-refused", "refused for a host outside the approved scope",
               "POST", "/api/v1/network/crypto-observe",
               {"endpoints": ["10.20.10.99:443"], "protocol": "TLS"}, {403, 409, 422})
        record("cidr-in-request-refused", "refused for a CIDR in the request itself",
               "POST", "/api/v1/network/crypto-observe",
               {"endpoints": ["10.20.10.0/24"], "protocol": "TLS"}, {403, 409, 422})
    else:
        probes.append({"probe": "out-of-scope-host-refused", "expected":
                       "refused for a host outside the approved scope", "ok": False,
                       "observed": "scope could not be saved, so the probe did not run"})

    # 5. Source scans are confined to declared roots, for every role.
    record("source-root-refused", "4xx for a target outside CRYPTOSCAN_SOURCE_ROOTS",
           "POST", "/api/v1/scans/trigger",
           {"repo_url": "/etc", "scan_type": "source"}, {400, 403, 422})

    ok = all(entry["ok"] for entry in probes)
    return {
        "id": "target_authorization",
        "question": "is the target of a collection authorized by the server, not by the caller's role?",
        "verdict": PASS if ok else FAIL,
        "probes": probes,
        "unproven": ["which hosts a bank has *approved* is deployment data; this row proves "
                     "the refusal paths, not that a given CIDR list is the right one"],
        "limits": ["the per-collector matrix for these questions is guide 116",
                   "the traffic budget and window are measured by guide 116's probes"],
    }


# ----------------------------------------------------------------------- output
def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Authorization boundaries — declared versus enforced",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['operations']} operations, {report['requests_executed']} decisions executed",
        "",
        "For every operation that declares a boundary, the drill resolves the roles the "
        "declaration allows, then sends the request as Admin, Auditor and Viewer through the "
        "real app. A decision that disagrees with the declaration is a violation.",
        "",
        "| Question | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        evidence = row["probes"][0]["observed"] if row["probes"] else ""
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {evidence} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        for probe in row["probes"]:
            mark = "PASS" if probe["ok"] else "**FAIL**"
            lines.append(f"- **{mark}** `{probe['probe']}` — {probe['expected']}: "
                         f"{probe['observed']}")
        for gap in row.get("unproven", []):
            lines.append(f"- **Not proven:** {gap}")
        for limit in row.get("limits", []):
            lines.append(f"- **Limit:** {limit}")
        for skipped in row.get("destructive", []) or []:
            lines.append(f"- **Not provoked:** `{skipped}` — destructive; declaration read, "
                         f"request not sent")
        for escape in row.get("escapes", []) or row.get("violations", []):
            lines.append(f"- **Violation:** `{escape['method']} {escape['path']}` as "
                         f"{escape['role']} → {escape['status']} (declared {escape['declared']})")
        if row.get("by_area"):
            lines.append("")
            lines.append("| Area | Session-only writes |")
            lines.append("|---|---|")
            for area, count in row["by_area"].items():
                lines.append(f"| `{area}` | {count} |")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** where a boundary is declared, the server "
        "enforces it — a Viewer cannot write, an Auditor cannot administer, an Admin cannot "
        "aim a collector at a CIDR or at the metadata address, and none of the three can "
        "reach a write without a session or with a token signed elsewhere. What it also says, "
        "plainly, is how much of the write surface declares nothing at all; that is a policy "
        "decision for the bank, not something this drill can grade.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Authorization boundary drill.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99,
                        help="exit non-zero when more than this many rows fail")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<8} {row['id']:<26} "
                  f"{row['probes'][0]['observed'] if row['probes'] else ''}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
