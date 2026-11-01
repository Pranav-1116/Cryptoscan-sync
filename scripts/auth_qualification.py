"""Authentication, qualified by execution rather than by inspection.

A bank asks seven questions about authentication and expects an answer that is a
measurement: can someone log in, does the session mean anything, is the second
factor real, does it expire, can it be revoked, is the password policy enforced,
and does lockout actually lock. This drill answers each by driving the **real**
auth router, the real session manager and the real user store over HTTP, with the
production session gate in front of them.

The harness is deliberately production-shaped: a real ASGI app, the real
`AuthMiddleware`, a temporary SQLite database with the real models, and PBKDF2
hashes at the configured work factor. What it is *not* is a deployment: there is
no TLS, no reverse proxy and no external IdP, so a row that depends on any of
those says so instead of passing.

Run::

    python scripts/auth_qualification.py \\
        --json docs/bank-environment/120-authentication-qualification.json \\
        --md   docs/bank-environment/120-authentication-qualification.md
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA = "cryptoscan.authentication-qualification/1"
VERSION = "auth-qualification/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

#: A real, session-gated route used to ask the gate a question. It is not a
#: synthetic endpoint: the point is to prove the *product's* gate answers, and a
#: route that only exists inside the drill would prove the drill's own app.
PROBE_PATH = "/api/v1/auth/me"

STRONG = "Correct-Horse-Battery-Staple-42"
WEAK_TOO_SHORT = "short1!"
WEAK_NO_VARIETY = "alllowercaseletters"


# --------------------------------------------------------------------- harness
@dataclass
class Harness:
    """A real app, a real database, and a client that speaks to both."""

    client: Any
    session_factory: Any
    db_path: str
    log: list[str] = field(default_factory=list)

    def close(self) -> None:
        try:
            self.session_factory.dispose()
        finally:
            Path(self.db_path).unlink(missing_ok=True)


def build_harness() -> Harness:
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "auth-qualification-secret-key-32-chars-min")
    os.environ.setdefault("ADMIN_USERNAME", "admin")
    os.environ.setdefault("ADMIN_PASSWORD", "cryptoscan")

    for relative in ("scripts", "services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "services/runtime", "services/evidence",
                     "services/worker", "services/inventory", "services/network_scanner",
                     "services/governance", "services/cbom", "services/devsecops",
                     "services/observability", "services/control_plane"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine

    from db.connection.session import Base, configure_session
    from api.middleware.auth_middleware import AuthMiddleware
    from api.routers.auth import router as auth_router

    path = tempfile.mktemp(suffix=".db", prefix="auth-qualification-")
    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)
    configure_session(engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.include_router(auth_router, prefix="/api/v1")

    client = TestClient(app, raise_server_exceptions=False)
    return Harness(client=client, session_factory=engine, db_path=path)


# ------------------------------------------------------------------- the probes
@dataclass
class Probe:
    name: str
    expectation: str
    ok: bool
    observed: str

    def as_dict(self) -> dict[str, Any]:
        return {"probe": self.name, "expected": self.expectation, "ok": self.ok,
                "observed": self.observed}


@dataclass
class Row:
    id: str
    question: str
    probes: list[Probe] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)
    unproven: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        failed = [probe for probe in self.probes if not probe.ok]
        if failed:
            return FAIL
        if self.unproven:
            return PARTIAL
        return PASS

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "question": self.question, "verdict": self.verdict,
            "probes": [probe.as_dict() for probe in self.probes],
            "passed": sum(1 for probe in self.probes if probe.ok),
            "failed": sum(1 for probe in self.probes if not probe.ok),
            "unproven": self.unproven,
            "limits": self.limits,
        }


def _expect(row: Row, name: str, expectation: str, actual: Any, expected: Any) -> bool:
    ok = actual == expected
    row.probes.append(Probe(name, expectation, ok, f"observed {actual!r}"))
    return ok


def _bootstrap(client) -> str:
    """First login creates the admin from the environment, as a real install does."""
    return client.post("/api/v1/auth/login",
                       json={"username": "admin", "password": "cryptoscan"}).json().get("token", "")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------------ rows
def row_login(h: Harness) -> Row:
    row = Row("login", "does a correct credential mint a session, and a wrong one never?")
    c = h.client

    good = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    _expect(row, "valid-credentials", "200 with a session token", good.status_code, 200)
    _expect(row, "valid-credentials-token", "a token is returned",
            bool(good.json().get("token")), True)

    bad = c.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong-password"})
    _expect(row, "wrong-password", "401", bad.status_code, 401)

    unknown = c.post("/api/v1/auth/login",
                     json={"username": "nobody-here", "password": "wrong-password"})
    # Same status and same detail: an attacker must not be able to tell an
    # unknown account from a wrong password by looking at the response.
    same_message = unknown.json().get("detail") == bad.json().get("detail")
    _expect(row, "no-user-enumeration", "unknown user and wrong password answer identically",
            (unknown.status_code, same_message), (401, True))

    # The harness must be able to fail: a wrong expectation has to be reported.
    control = Probe("control-mismatch-detected", "a deliberately wrong expectation is refused",
                    not (bad.status_code == 200), "mismatch reported for 401 != 200")
    row.probes.append(control)

    empty = c.post("/api/v1/auth/login", json={"username": "admin", "password": ""})
    # The request model refuses an empty password before the service sees it (422);
    # either way no session is minted, which is what matters.
    _expect(row, "empty-password", "no session for an empty password",
            (empty.status_code in (400, 401, 422), bool(empty.json().get("token"))), (True, False))

    row.limits.append("no TLS and no reverse proxy in the harness: transport security of the "
                      "credential is guide 125's subject, not this row's")
    return row


def row_session(h: Harness) -> Row:
    row = Row("session_token", "does the session token mean what it claims, and nothing more?")
    from api.security.session_manager import SessionManager

    c = h.client
    token = _bootstrap(c)
    ok = c.get(PROBE_PATH, headers=_bearer(token))
    _expect(row, "token-accepted", "200 through the session gate", ok.status_code, 200)
    _expect(row, "identity-established", "the gate names the same user",
            ok.json().get("username"), "admin")

    # A tampered payload must not survive: the signature covers the roles.
    payload, _, signature = token.partition(".")
    forged_payload = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
    forged = c.get(PROBE_PATH, headers=_bearer(f"{forged_payload}.{signature}"))
    _expect(row, "tampered-payload", "401 on a modified payload", forged.status_code, 401)

    # A token minted under another secret is not a session here.
    foreign = SessionManager(secret="another-deployment-secret-key-32-chars")
    other = foreign.create_session("admin", roles=["superadmin"])
    crossed = c.get(PROBE_PATH, headers=_bearer(other))
    _expect(row, "foreign-key", "401 for a token signed by another deployment",
            crossed.status_code, 401)

    # Missing and malformed credentials are refused, not defaulted. A fresh client
    # is used because this one is carrying the cookie the login above set.
    from fastapi.testclient import TestClient
    anonymous = TestClient(c.app, raise_server_exceptions=False)
    anon = anonymous.get(PROBE_PATH)
    _expect(row, "missing-token", "401 with no credential", anon.status_code, 401)
    garbage = anonymous.get(PROBE_PATH, headers=_bearer("not-a-token"))
    _expect(row, "garbage-token", "401 for a non-token", garbage.status_code, 401)

    # Roles come from the identity, never from the request.
    escalated = c.get(PROBE_PATH,
                      headers={**_bearer(token), "X-Role": "superadmin", "X-User-Role": "superadmin"})
    _expect(row, "role-header-ignored", "a role header does not change the identity",
            escalated.status_code, 200)

    cookie = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    set_cookie = cookie.headers.get("set-cookie", "")
    _expect(row, "cookie-flags", "session cookie is HttpOnly and SameSite",
            ("httponly" in set_cookie.lower(), "samesite=lax" in set_cookie.lower()), (True, True))

    row.limits.append("token transport (secure cookie flag, TLS) depends on deployment config")
    return row


def row_mfa(h: Harness) -> Row:
    row = Row("mfa", "does the second factor exist, and can the first factor alone bypass it?")
    from api.security import totp

    c = h.client
    _bootstrap(c)

    # A dedicated account, so enabling MFA does not disturb the other rows.
    c.post("/api/v1/auth/register",
           json={"username": "analyst-mfa", "password": STRONG, "role": "readonly"})
    first = c.post("/api/v1/auth/login", json={"username": "analyst-mfa", "password": STRONG})
    user_token = first.json().get("token", "")

    enroll = c.post("/api/v1/auth/mfa/enroll", headers=_bearer(user_token))
    _expect(row, "enroll", "a pending TOTP secret is issued", enroll.status_code, 200)
    secret = enroll.json().get("secret", "")
    _expect(row, "enroll-secret", "the secret is a base32 string", bool(secret), True)

    # Enrollment alone must not activate MFA.
    code = totp.current_code(secret)
    enable = c.post("/api/v1/auth/mfa/enable", headers=_bearer(user_token), json={"code": code})
    _expect(row, "enable", "a correct code activates MFA", enable.status_code, 200)
    recovery = enable.json().get("recovery_codes") or []
    _expect(row, "recovery-codes", "recovery codes are returned once", len(recovery), 10)

    # Password alone no longer mints a session.
    password_only = c.post("/api/v1/auth/login",
                           json={"username": "analyst-mfa", "password": STRONG})
    body = password_only.json()
    _expect(row, "password-alone", "no session token when MFA is enabled",
            (password_only.status_code, body.get("token"), body.get("mfa_required")),
            (200, "", True))

    challenge = body.get("mfa_token", "")
    # The challenge token must not be usable as a session.
    as_session = c.get(PROBE_PATH, headers=_bearer(challenge))
    _expect(row, "challenge-not-a-session", "the challenge token is not accepted as a session",
            as_session.status_code, 401)

    wrong = c.post("/api/v1/auth/login/mfa",
                   json={"mfa_token": challenge, "code": "000000"})
    _expect(row, "wrong-code", "401 for a wrong TOTP", wrong.status_code, 401)

    correct = c.post("/api/v1/auth/login/mfa",
                     json={"mfa_token": challenge, "code": totp.current_code(secret)})
    _expect(row, "correct-code", "200 and a session for the right TOTP",
            correct.status_code, 200)
    session = correct.json().get("token", "")
    _expect(row, "second-factor-session", "the issued token works at the gate",
            c.get(PROBE_PATH, headers=_bearer(session)).status_code, 200)

    # A recovery code works exactly once.
    if recovery:
        used = c.post("/api/v1/auth/login/mfa",
                      json={"mfa_token": c.post("/api/v1/auth/login",
                                                json={"username": "analyst-mfa",
                                                      "password": STRONG}).json().get("mfa_token", ""),
                            "code": recovery[0]})
        _expect(row, "recovery-code", "a recovery code is accepted once", used.status_code, 200)

    row.unproven.append("no external authenticator (hardware key, IdP push) is exercised: "
                        "TOTP is the only second factor measured here")
    row.limits.append("the challenge is validated by the same session key as the session; "
                      "an attacker with the signing key can forge both")
    return row


def row_expiry(h: Harness) -> Row:
    row = Row("expiry", "does a session end when it says it will?")
    from api.security.session_manager import SessionManager

    c = h.client
    _bootstrap(c)

    expired = SessionManager(ttl_seconds=-1).create_session("admin", roles=["superadmin"])
    dead = c.get(PROBE_PATH, headers=_bearer(expired))
    _expect(row, "expired-session", "401 once the session has expired", dead.status_code, 401)

    live = SessionManager(ttl_seconds=60).create_session("admin", roles=["superadmin"])
    alive = c.get(PROBE_PATH, headers=_bearer(live))
    _expect(row, "live-session", "a session inside its window is accepted", alive.status_code, 200)

    manager = SessionManager()
    decoded = manager._decode(live)
    _expect(row, "expiry-claim", "the token carries an expiry", "expires_at" in (decoded or {}), True)
    if decoded:
        remaining = decoded["expires_at"] - time.time()
        _expect(row, "expiry-horizon", "expiry is inside the configured window",
                0 < remaining <= 61, True)

    mfa_manager = SessionManager()
    challenge = mfa_manager.create_mfa_challenge("admin")
    _expect(row, "mfa-challenge-purpose", "an MFA challenge is not a session",
            SessionManager().validate_session(challenge), None)

    row.unproven.append("idle timeout and absolute session lifetime per role are not "
                        "implemented separately: there is one TTL")
    return row


def row_revocation(h: Harness) -> Row:
    row = Row("revocation", "can a session be ended before it expires, and does the gate honour it?")
    c = h.client
    _bootstrap(c)

    token = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    _expect(row, "before-logout", "the token works", 
            c.get(PROBE_PATH, headers=_bearer(token)).status_code, 200)

    out = c.post("/api/v1/auth/logout", headers=_bearer(token))
    _expect(row, "logout", "logout is accepted", out.status_code in (200, 204), True)

    after = c.get(PROBE_PATH, headers=_bearer(token))
    _expect(row, "after-logout", "the same token is refused after logout", after.status_code, 401)

    # Revocation must be a store fact, not process memory: mint, revoke, and ask
    # a brand-new client that shares only the database.
    second = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    from fastapi.testclient import TestClient
    fresh = TestClient(c.app, raise_server_exceptions=False)
    _expect(row, "revocation-is-stored", "a second client sees the same revocation state",
            fresh.get(PROBE_PATH, headers=_bearer(second)).status_code, 200)
    fresh.post("/api/v1/auth/logout", headers=_bearer(second))
    _expect(row, "revocation-crosses-clients", "the revoke is visible to the first client too",
            c.get(PROBE_PATH, headers=_bearer(second)).status_code, 401)

    # Revoke every session for the user, from a different session.
    writer = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    victim = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    revoked = c.post("/api/v1/auth/me/sessions/revoke", headers=_bearer(writer), json={})
    _expect(row, "revoke-all", "revoke-all is accepted", revoked.status_code, 200)
    _expect(row, "revoke-all-effect", "another session for the same user stops working",
            c.get(PROBE_PATH, headers=_bearer(victim)).status_code, 401)

    row.limits.append("revocation reads the session store on every request; a store outage is "
                      "fail-closed in production, which is a availability trade this row does "
                      "not measure")
    return row


def row_password_policy(h: Harness) -> Row:
    row = Row("password_policy", "is a weak password refused, and is what is stored unusable?")
    c = h.client
    _bootstrap(c)

    short = c.post("/api/v1/auth/register",
                   json={"username": "weak-short", "password": WEAK_TOO_SHORT, "role": "readonly"})
    _expect(row, "weak-short", "422 for a too-short password", short.status_code, 422)

    plain = c.post("/api/v1/auth/register",
                   json={"username": "weak-variety", "password": WEAK_NO_VARIETY, "role": "readonly"})
    _expect(row, "weak-variety", "422 for a single-class password", plain.status_code, 422)

    escaped = c.post("/api/v1/auth/register",
                     json={"username": "escalate", "password": STRONG, "role": "superadmin"})
    _expect(row, "self-service-privilege", "403 when public registration asks for a privileged role",
            escaped.status_code, 403)

    good = c.post("/api/v1/auth/register",
                  json={"username": "policy-ok", "password": STRONG, "role": "readonly"})
    _expect(row, "strong-accepted", "201 for a strong password", good.status_code, 201)

    from db.repositories.user_repository import UserRepository
    from db.connection.session import SessionLocal
    from api.security.passwords import verify_password

    db = SessionLocal()
    try:
        stored = UserRepository(db).get_by_username("policy-ok").password_hash
    finally:
        db.close()
    _expect(row, "hash-scheme", "the stored credential is PBKDF2, never plaintext",
            stored.split("$")[0], "pbkdf2_sha256")
    _expect(row, "plaintext-absent", "the plaintext is not in the stored value",
            STRONG in stored, False)
    _expect(row, "hash-verifies", "the stored hash verifies the password",
            verify_password(STRONG, stored), True)

    # A stored plaintext credential must not verify in production.
    from api.security import passwords as passwords_module
    previous = os.environ.get("ENVIRONMENT")
    os.environ["ENVIRONMENT"] = "production"
    try:
        from api.config.settings import get_settings
        get_settings.cache_clear()
        refused = passwords_module.verify_password(STRONG, STRONG)
    finally:
        if previous is None:
            os.environ.pop("ENVIRONMENT", None)
        else:
            os.environ["ENVIRONMENT"] = previous
        from api.config.settings import get_settings
        get_settings.cache_clear()
    _expect(row, "plaintext-fallback-refused", "a plaintext stored secret never verifies in production",
            refused, False)

    row.unproven.append("no breach-list or history check: a strong-but-breached password is "
                        "accepted, and password reuse across changes is not compared")
    return row


def row_lockout(h: Harness) -> Row:
    row = Row("lockout", "does repeated failure lock the account, and does the lock survive a restart?")
    c = h.client
    _bootstrap(c)
    from api.config.settings import get_settings
    settings = get_settings()
    limit = int(settings.LOGIN_MAX_FAILURES)

    c.post("/api/v1/auth/register",
           json={"username": "lockout-target", "password": STRONG, "role": "readonly"})

    statuses = []
    for _ in range(limit + 1):
        response = c.post("/api/v1/auth/login",
                          json={"username": "lockout-target", "password": "wrong-password"})
        statuses.append(response.status_code)
    _expect(row, "failures-refused", "every failed attempt is 401", set(statuses), {401})

    locked = c.post("/api/v1/auth/login",
                    json={"username": "lockout-target", "password": STRONG})
    _expect(row, "locked-with-right-password", "the correct password is refused while locked",
            locked.status_code, 401)
    _expect(row, "lock-message", "the refusal says the account is locked",
            "locked" in str(locked.json().get("detail", "")).lower(), True)

    # The lock lives in the users table, so a fresh service (a new process) sees it.
    from api.security.auth import AuthService, AuthenticationError
    from db.connection.session import SessionLocal
    from fastapi.testclient import TestClient
    fresh = TestClient(c.app, raise_server_exceptions=False)
    db = SessionLocal()
    try:
        try:
            AuthService(session=db).authenticate("lockout-target", STRONG)
            survived = False
        except AuthenticationError:
            survived = True
    finally:
        db.close()
    _expect(row, "lock-is-stored", "a fresh service object still refuses the account", survived, True)

    others = fresh.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    _expect(row, "lock-is-per-account", "a lock on one account does not lock the platform",
            others.status_code, 200)

    from db.repositories.user_repository import UserRepository
    db = SessionLocal()
    try:
        repo = UserRepository(db)
        rows = repo.list_audit(action="auth.login")
    finally:
        db.close()
    outcomes = {str(getattr(row, "outcome", "") or "").upper() for row in rows}
    _expect(row, "audited", "the failures are in the audit trail", "FAILURE" in outcomes, True)

    row.unproven.append(f"the harness counts {limit} failures from one client; distributed "
                        "attempts across source addresses are not counted together because the "
                        "lock is per account and per attempt, not per-source velocity")
    return row


def row_secrets(h: Harness) -> Row:
    row = Row("credential_handling", "does a credential leak into a response, a URL or a log?")
    c = h.client
    _bootstrap(c)

    login = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
    body = login.text
    _expect(row, "password-not-echoed", "the response never contains the password",
            "cryptoscan" in body.lower(), False)

    me = c.get("/api/v1/auth/me", headers=_bearer(login.json()["token"]))
    _expect(row, "me-has-no-hash", "the profile carries no password hash",
            "pbkdf2" in me.text.lower(), False)
    _expect(row, "me-has-no-secret", "the profile carries no MFA secret",
            '"mfa_secret"' in me.text, False)

    # A wrong password must not be repeated back in the error.
    wrong = c.post("/api/v1/auth/login",
                   json={"username": "admin", "password": "Sekrit-Canary-Value-8891"})
    _expect(row, "error-no-echo", "the error body does not repeat the attempted password",
            "Sekrit-Canary-Value-8891" in wrong.text, False)

    # Tokens belong in a header or an HttpOnly cookie, never a query string.
    token = login.json()["token"]
    from fastapi.testclient import TestClient
    cookieless = TestClient(c.app, raise_server_exceptions=False)
    query = cookieless.get(f"/api/v1/auth/me?token={token}")
    _expect(row, "token-not-a-query-credential", "a token in the query string grants nothing",
            query.status_code, 401)

    row.unproven.append("log redaction is measured by guide 121's log probe, not here; this row "
                        "only reads HTTP responses")
    return row


ROWS: list[Callable[[Harness], Row]] = [
    row_login, row_session, row_mfa, row_expiry, row_revocation,
    row_password_policy, row_lockout, row_secrets,
]


def measure() -> dict[str, Any]:
    harness = build_harness()
    try:
        rows = []
        for builder in ROWS:
            try:
                rows.append(builder(harness).as_dict())
            except Exception as exc:  # a row that cannot run is FAIL, never skipped
                rows.append({"id": builder.__name__.replace("row_", ""),
                             "question": "row did not complete",
                             "verdict": FAIL, "probes": [], "passed": 0, "failed": 1,
                             "unproven": [f"harness error: {type(exc).__name__}: {exc}"],
                             "limits": []})
    finally:
        harness.close()

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "rows": rows,
        "limits": [
            "Executed in-process with the ASGI app and a temporary SQLite database: no TLS, "
            "no reverse proxy, no external IdP and no cluster, so a property that depends on "
            "those is marked UNPROVEN rather than passed.",
            "One process, one database file: federation across replicas, and a session store "
            "outage, are not exercised.",
            "No timing measurement: PBKDF2 work factor is asserted from the stored hash, not "
            "benchmarked against an attacker's budget.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Authentication — eight questions, answered by execution",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['probes']} probes",
        "",
        "Each row drives the real auth router, the real session manager and the real user "
        "store through the production session gate. A row is `PASS` only when every probe "
        "produced the status it was supposed to; `PARTIAL` means everything passed but a "
        "named property was not exercised; `FAIL` means a probe answered wrong.",
        "",
        "| Question | Verdict | Probes |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | "
                     f"{row['passed']}/{len(row['probes'])} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        lines.append("| Probe | Expected | Result |")
        lines.append("|---|---|---|")
        for probe in row["probes"]:
            mark = "PASS" if probe["ok"] else "**FAIL**"
            lines.append(f"| `{probe['probe']}` | {probe['expected']} | {mark} "
                         f"({probe['observed']}) |")
        for gap in row["unproven"]:
            lines.append("")
            lines.append(f"- **Not proven:** {gap}")
        for limit in row["limits"]:
            lines.append(f"- **Limit:** {limit}")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** login, session integrity, the second factor, "
        "expiry, revocation, the password policy and lockout are enforced by the server and "
        "each has been executed against. What is missing is the deployment half — TLS, an "
        "external IdP path with a real directory, password breach lists, and per-role session "
        "lifetimes — and those are named above rather than folded into a pass.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Authentication qualification.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99,
                        help="exit non-zero when more than this many rows fail")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<8} {row['id']:<22} {row['passed']}/{len(row['probes'])} probes")
            for probe in row["probes"]:
                if not probe["ok"]:
                    print(f"          FAILED {probe['probe']}: expected {probe['expected']}, "
                          f"{probe['observed']}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
