"""Every route, executed against a real uvicorn server and a real PostgreSQL.

Guide 100 §5 used to say "no live-server request was executed for every route".
The route contract compares a caller's URL with the router table; it cannot see a
handler that raises on its first line, a dependency that cannot be resolved at
call time, or a response that 500s because a column is missing. Those are exactly
the failures a bank finds first — and two of them were found this way
(`POST /api/v1/hbom/snapshot`, five compliance endpoints) that no in-process test
had ever failed on.

This file starts the application the way a deployment does — uvicorn on a socket,
the migration chain applied to a real database, the full middleware stack in
place — and then asks every operation in the schema for an answer:

* **no operation returns a 5xx** to a fully authorised operator;
* **no operation serves an unauthenticated caller**, except the ones the session
  gate declares unprotected, and that declared list is exactly what is public
  (nothing is public by accident);
* **no write operation is served to a read-only operator** (2xx is the failure;
  a 4xx is the route refusing).

Four things make this possible without weakening the product:

1. The rate limiter allots 600 requests/minute per identity, and the sweep is
   ~1250 operations. The fixture creates several equally privileged identities
   and shards the work, so the limiter keeps its production numbers and each
   identity stays inside its own window.
2. Sessions are minted directly through `SessionManager` and persisted, because
   `POST /auth/login` is itself rate limited to 5/minute per IP — a fixture that
   logged in nine times would be testing the limiter, not the routes. The env is
   populated *before* `Settings` is imported: a token minted first is signed with
   the fallback key and the server rejects it as unauthenticated.
3. Writes are sent an **empty object**. FastAPI answers 422 before the handler
   runs for any route with required fields, so the sweep exercises dependency
   resolution and validation without performing hundreds of real mutations. The
   routes that do execute (all-optional bodies) are ordered last, and the handful
   that flip a global switch are named below. A 422 proves the route is mounted —
   it says nothing about the handler, so a **second** sweep (below) sends each
   write a body synthesised from its own request schema and asserts no 5xx. That
   one really does mutate the throw-away database, which is why the session
   killers and global switches are still excluded.
4. Each test message quotes the operation, the status and the first bytes of the
   body, because "1 failed" is not a finding anyone can act on.

The suite is opt-in: it needs a PostgreSQL binary and takes about a minute. Set
`CRYPTOSCAN_LIVE_SMOKE=1` to run it.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for extra in ("scripts", "services/database", "shared/shared_models", "shared/shared_config", "shared/shared_logging", "services/api"):
    candidate = str(ROOT / extra)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

pytestmark = [
    # The sweep is thousands of real HTTP round trips. The repository's default
    # per-test timeout is sized for unit tests and killed the first attempt
    # mid-flight, before a single assertion ran; this module sets its own.
    pytest.mark.timeout(900),
    pytest.mark.skipif(
        os.environ.get("CRYPTOSCAN_LIVE_SMOKE") != "1",
        reason="live route smoke is opt-in: set CRYPTOSCAN_LIVE_SMOKE=1 (needs PostgreSQL + ~60s)",
    ),
]

pgserver = pytest.importorskip("pgserver", reason="pgserver is not installed: no PostgreSQL to run")

READ = {"GET", "HEAD"}

#: Writes that change state for the rest of the sweep. They are real operations
#: and they are exercised, but last — otherwise a maintenance window opened by
#: route 40 makes routes 41–200 answer 503 and the sweep reports a false failure.
GLOBAL_SWITCHES = (
    "/maintenance",
    "/platform/maintenance",
    "/policy/mode",
    "/execution/",
    "/airgap",
)

#: Routes that end the sweep's own credential: revoking a session, disabling a
#: user, rotating a secret. Sent last, after everything else has answered.
SESSION_KILLERS = (
    "/auth/logout",
    "/auth/me/sessions/revoke",
    "/auth/users/",
    "/auth/rotate",
    "/api-keys",
    "/secrets/rotate",
)

CONSOLE_OPERATIONS = 605


#: Operations that answer 503 on a host without an external binary — the body
#: names the missing tool, which is the honest answer, not a defect. They are
#: exempted from the body sweep only on a 503 that says so; a 500 there is still
#: a failure. Installing `pg_dump` to make a test green would hide the fact that
#: the feature degrades honestly.
UNAVAILABLE_ON_THIS_HOST = frozenset({"POST /api/v1/resilience/backup/create"})


def _operations() -> list[tuple[str, str]]:
    """(METHOD, path) for every operation the application serves."""
    import api_contract

    spec = api_contract.served_operations()
    return sorted(
        (method.upper(), path)
        for path, methods in spec.items()
        for method in methods
    )


def _concrete(path: str) -> str:
    """A path parameter needs a value; the value must not be a plausible id."""
    return "/".join("smoke-0001" if segment.startswith("{") else segment for segment in path.split("/"))


def _order(operations: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Reads first, then writes, then the two groups that end our own session."""

    def group(item: tuple[str, str]) -> int:
        method, path = item
        if any(marker in path for marker in SESSION_KILLERS):
            return 3
        if any(marker in path for marker in GLOBAL_SWITCHES):
            return 2
        return 0 if method in READ else 1

    return sorted(operations, key=lambda item: (group(item), item[0] not in READ, item[1]))


#: Server-sent-event routes never end: the connection stays open for the life of
#: the client. A sweep that reads the body of one of those blocks forever (the
#: read never times out while the stream keeps the socket alive), so the sweep
#: stops at the response headers, which is exactly what a subscriber does before
#: it starts consuming. Anything else that answers and then stalls is a finding.
STREAM_CONTENT_TYPES = ("text/event-stream", "application/x-ndjson")


def _gate_public(path: str) -> bool:
    """True for paths `AuthMiddleware` never asks for a credential.

    This mirrors the middleware rather than re-deriving the rule, because the
    point of the anonymous sweep is to prove the *gate's* surface, not this
    file's opinion of it: root and static assets, the declared unprotected
    prefixes, and every path outside ``/api/`` (liveness and readiness probes are
    served at ``/healthz`` and ``/readyz`` by the deployment).
    """
    from api.middleware.auth_middleware import _is_unprotected

    return (
        path == "/"
        or path.startswith(("/login", "/static"))
        or _is_unprotected(path)
        or not path.startswith("/api/")
    )


#: Writes a user performs on their own record. They are authorised to themselves,
#: not to a role: every signed-in operator may edit their profile and enrol a
#: second factor, so a read-only principal is *supposed* to succeed here. Excluded
#: from the read-only sweep and named rather than pattern-matched away silently.
SELF_SERVICE_WRITES = (
    "/auth/me",
    "/auth/mfa/",
)


def _role_gated_operations() -> dict[tuple[str, str], set[frozenset[str]]]:
    """(METHOD, path) → the role sets each of its dependencies requires.

    The requirement lives in a closure created by ``require_roles``, which tags
    itself with ``allowed_roles`` for exactly this purpose. Reading it from the
    route tree means the answer comes from what the app *enforces*, not from a
    second list of what the documentation says it should enforce.
    """
    import api_contract

    def role_sets(dependant) -> set[frozenset[str]]:
        found: set[frozenset[str]] = set()
        stack = [dependant]
        while stack:
            dependency = stack.pop()
            allowed = getattr(getattr(dependency, "call", None), "allowed_roles", None)
            if allowed:
                found.add(frozenset(allowed))
            stack.extend(dependency.dependencies)
        return found

    gated: dict[tuple[str, str], set[frozenset[str]]] = {}
    for route in api_contract.application().routes:
        original = getattr(route, "original_router", None)
        if original is None:
            continue  # the app shell (health probes, docs), not an API router
        context = getattr(route, "include_context", None)
        prefix = (getattr(context, "prefix", "") or "") if context is not None else ""
        router_level = set()
        for dependency in getattr(original, "dependencies", []):
            allowed = getattr(getattr(dependency, "dependency", None), "allowed_roles", None)
            if allowed:
                router_level.add(frozenset(allowed))
        for child in original.routes:
            methods = getattr(child, "methods", None)
            if not methods:
                continue
            dependant = getattr(child, "dependant", None)
            requirements = set(router_level) | (role_sets(dependant) if dependant else set())
            if not requirements:
                continue
            for method in methods:
                if method in ("HEAD", "OPTIONS"):
                    continue
                gated.setdefault((method, prefix + getattr(child, "path", "")), set()).update(requirements)
    return gated


def _grants(roles: list[str], requirement: frozenset[str]) -> bool:
    from api.security.rbac import normalize_roles

    return bool(set(normalize_roles(list(requirement))) & set(normalize_roles(roles)))


def _request(base: str, method: str, path: str, token: str | None, *, body=None,
             timeout: float = 20.0) -> tuple[int | str, bytes]:
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if method not in READ and method != "DELETE":
        data = json.dumps({} if body is None else body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_type = (response.headers.get("content-type") or "").lower()
            if any(kind in content_type for kind in STREAM_CONTENT_TYPES):
                return response.status, b"<stream opened; body not drained>"
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except Exception as error:  # transport failure: the route never answered
        return f"{type(error).__name__}: {error}", b""


def _sweep(live, operations, token_for, *, retry_429: bool = True, body_for=None):
    """Run ``operations`` sharded across identities; return {item: (status, body)}.

    ``body_for(method, path)`` supplies each request body; without it every write
    gets the empty object described in the module docstring.
    """
    results: dict[tuple[str, str], tuple[int | str, bytes]] = {}

    def run(indexed):
        index, (method, path) = indexed
        token = token_for(index)
        body = body_for(method, path) if body_for else None
        status, payload = _request(live["base"], method, _concrete(path), token, body=body)
        if status == 429 and retry_429:
            # One identity can exceed its own 60 s window during a long shard.
            # Waiting once is enough; the production limit is not relaxed.
            time.sleep(2.0)
            status, payload = _request(live["base"], method, _concrete(path), token, body=body)
        return (method, path), (status, payload)

    debug = os.environ.get("CRYPTOSCAN_SMOKE_DEBUG") == "1"
    started = time.time()
    with ThreadPoolExecutor(max_workers=24) as pool:
        for done, (item, result) in enumerate(pool.map(run, enumerate(operations)), start=1):
            results[item] = result
            if debug and done % 50 == 0:
                print(f"[smoke] {done}/{len(operations)} {item} {result[0]} {time.time() - started:.0f}s", flush=True)
    return results


def _describe(results) -> str:
    return "\n  ".join(
        f"{method} {path} -> {status} {payload[:200]!r}"
        for (method, path), (status, payload) in sorted(results.items())
    )


@pytest.fixture(scope="module")
def live():
    """uvicorn on a free port, over a real PostgreSQL at the migration tip."""
    from datetime import datetime, timedelta, timezone

    work = tempfile.mkdtemp(prefix="live-smoke-")
    server = pgserver.get_server(work)
    uri = server.get_uri()
    server.psql("CREATE DATABASE cryptoscan;")
    url = f"postgresql+psycopg2://postgres:@/cryptoscan?host={uri.split('host=')[1]}"

    # Before any settings import: get_settings() caches, and a token minted
    # against the fallback key is rejected by the server as unauthenticated.
    os.environ["DATABASE_URL"] = url
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ALLOW_SQLITE"] = "true"
    os.environ["SECRET_KEY"] = "live-smoke-secret-key-at-least-32-characters"
    os.environ["GITHUB_WEBHOOK_SECRET"] = "live-smoke-webhook-secret"
    # Machine-credential surfaces (the intel feed, ChatOps, Stripe callbacks) are
    # public by design and verify their own HMAC. Without a secret they answer 503
    # from a configuration guard, which would hide the handler behind it; with one
    # the sweep exercises the real path — and an unsigned request is refused by
    # the route itself, which is one of the things this sweep proves.
    os.environ["THREAT_INTEL_FEED_SECRET"] = "live-smoke-feed-secret"
    os.environ["ALERT_CHATOPS_SECRET"] = "live-smoke-chatops-secret"
    os.environ["STRIPE_WEBHOOK_SECRET"] = "live-smoke-stripe-secret"
    # Two registries are file-backed and default to `<cwd>/config`. The body sweep
    # deliberately performs real writes, so without these overrides it would edit
    # the checkout it is testing (it did: `contract-*` rows landed in
    # `config/group_entities.json`). Point every runtime write at the temp dir.
    os.environ["CRYPTOSCAN_HOME"] = work
    os.environ["CRYPTOSCAN_GROUP_ENTITIES"] = str(Path(work) / "group_entities.json")
    os.environ["CRYPTOSCAN_FIPS_REGISTRY"] = str(Path(work) / "fips_certificates.json")

    env = dict(os.environ)
    env["PYTHONPATH"] = ":".join(str(ROOT / extra) for extra in (
        "services/database", "services/api", "shared/shared_models",
        "shared/shared_config", "shared/shared_logging", "scripts",
    )) + ":" + env.get("PYTHONPATH", "")

    migration = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
        cwd=str(ROOT / "services/database/migrations"), env=env,
        capture_output=True, text=True,
    )
    if migration.returncode != 0:
        server.cleanup()
        pytest.fail("the migration chain does not reach head:\n" + migration.stderr[-3000:])

    from api.config.settings import get_settings
    from api.security.passwords import hash_password
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    get_settings.cache_clear()
    engine = create_engine(url, future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    manager = SessionManager()

    counter = {"n": 0}

    def mint(roles: list[str]) -> str:
        """A brand-new identity holding ``roles``, with a live session.

        Sessions are consumable: the sweep exercises ``POST /auth/logout`` and
        ``POST /auth/me/sessions/revoke`` for real, so a token reused across tests
        is a token a later test finds revoked (401 "Session revoked", which looks
        exactly like a broken role gate). Each test that needs a credential asks
        for its own.
        """
        counter["n"] += 1
        name = f"smoke-{roles[0]}-{counter['n']}"
        token = manager.create_session(name, roles=roles)
        with factory() as db:
            UserRepository(db).create_user(name, hash_password("smoke-password-1"), roles=roles)
            UserRepository(db).create_session(
                token, name, datetime.now(timezone.utc) + timedelta(hours=2), ip="127.0.0.1"
            )
            db.commit()
        return token

    identities: list[tuple[str, list[str], str]] = []
    with factory() as db:
        repository = UserRepository(db)
        for index in range(6):
            name = f"smoke-operator-{index}"
            token = manager.create_session(name, roles=["superadmin"])
            repository.create_user(name, hash_password("smoke-password-1"), roles=["superadmin"])
            repository.create_session(
                token, name, datetime.now(timezone.utc) + timedelta(hours=2), ip="127.0.0.1"
            )
            identities.append((name, ["superadmin"], token))
        readonly_token = manager.create_session("smoke-readonly", roles=["readonly"])
        repository.create_user("smoke-readonly", hash_password("smoke-password-1"), roles=["readonly"])
        repository.create_session(
            readonly_token, "smoke-readonly",
            datetime.now(timezone.utc) + timedelta(hours=2), ip="127.0.0.1",
        )
        db.commit()

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    log_path = Path(work) / "uvicorn.log"
    log = log_path.open("w")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    last_error = ""
    deadline = time.time() + 120
    while time.time() < deadline:
        if process.poll() is not None:
            break
        try:
            with urllib.request.urlopen(base + "/api/v1/healthz", timeout=3) as response:
                if response.status == 200:
                    break
        except Exception as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(0.5)
    else:
        process.terminate()
        log.close()
        server.cleanup()
        pytest.fail(f"the server never became ready at /api/v1/healthz (last error: {last_error})")

    try:
        yield {
            "base": base,
            "mint": mint,
            "tokens": [token for _name, _roles, token in identities],
            "readonly": readonly_token,
            "log": log_path,
        }
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()
        engine.dispose()
        server.cleanup()


class TestEveryOperationAnswers:
    def test_no_operation_returns_a_server_error(self, live):
        operations = _order(_operations())
        assert len(operations) >= 1100, f"only {len(operations)} operations swept"

        # Fresh identities: this sweep calls logout and revoke for real, so the
        # tokens it holds are gone by the time it returns.
        tokens = [live["mint"](["superadmin"]) for _ in range(6)]
        results = _sweep(live, operations, lambda index: tokens[index % len(tokens)])

        failures = [
            f"{method} {path} -> {status} {payload[:200]!r}"
            for (method, path), (status, payload) in sorted(results.items())
            if isinstance(status, int) and status >= 500
        ]
        unexecuted = [
            f"{method} {path} -> {status}"
            for (method, path), (status, _payload) in sorted(results.items())
            if not isinstance(status, int)
        ]
        assert failures == [], "operations that crash on a live server:\n  " + "\n  ".join(failures)
        assert unexecuted == [], "operations that never answered:\n  " + "\n  ".join(unexecuted)

    def test_the_sweep_reaches_the_read_surface(self, live):
        """A smoke test that silently 401'd everything would also report no 5xx."""
        operations = [item for item in _order(_operations()) if item[0] in READ][:80]
        tokens = [live["mint"](["superadmin"]) for _ in range(3)]
        results = _sweep(live, operations, lambda index: tokens[index % len(tokens)], retry_429=False)
        served = [1 for status, _payload in results.values() if isinstance(status, int) and 200 <= status < 300]
        assert len(served) >= 30, (
            f"only {len(served)} of {len(operations)} sampled reads returned 2xx — the identities in "
            "this fixture are not authorised, so the sweep proves nothing:\n  " + _describe(results)
        )


class TestWritesAcceptTheirOwnSchema:
    """The empty-body sweep stops at validation; this one gets past it.

    A 422 proves a route is mounted and its dependencies resolve. It does not
    prove the handler works — for a long time every write in this file was sent
    `{}`, so a handler that raised `KeyError` on its own request payload (it was
    declared `list[dict]`, so there was no schema to synthesise from) still
    answered 500 in production and 422 here. `api_payloads.request_body` builds a
    body that satisfies the operation's declared schema, which is the only way to
    reach the handler.

    This sweep performs real mutations against the throw-away database, so the
    routes that end our session or flip a global switch stay excluded, as above.
    """

    def test_no_write_operation_server_errors_on_a_schema_shaped_body(self, live):
        import api_contract
        import api_payloads

        spec = api_contract.openapi_spec()

        def body_for(method: str, path: str):
            try:
                return api_payloads.request_body(spec, path, method)
            except Exception:  # noqa: BLE001 - an unreadable schema is a finding below
                return None

        operations = [
            item
            for item in _order(_operations())
            if item[0] not in READ
            and not any(marker in item[1] for marker in SESSION_KILLERS)
            and not any(marker in item[1] for marker in GLOBAL_SWITCHES)
        ]
        assert len(operations) >= 500, f"only {len(operations)} write operations swept"
        synthesised = [1 for method, path in operations if body_for(method, path) is not None]
        assert len(synthesised) >= 400, (
            f"only {len(synthesised)} of {len(operations)} writes declared a request schema — "
            "the sweep cannot reach the handler for the rest"
        )

        tokens = [live["mint"](["superadmin"]) for _ in range(6)]
        results = _sweep(live, operations, lambda index: tokens[index % len(tokens)], body_for=body_for)

        def exempt(item, status, payload) -> bool:
            """A declared environment-dependent route, refusing for the stated reason."""
            return (
                f"{item[0]} {item[1]}" in UNAVAILABLE_ON_THIS_HOST
                and status == 503
                and b"not installed" in payload
            )

        failures = [
            f"{method} {path} -> {status} {payload[:200]!r}"
            for (method, path), (status, payload) in sorted(results.items())
            if isinstance(status, int) and status >= 500
            and not exempt((method, path), status, payload)
        ]
        unexecuted = [
            f"{method} {path} -> {status}"
            for (method, path), (status, _payload) in sorted(results.items())
            if not isinstance(status, int)
        ]
        assert failures == [], (
            "write operations that crash on a body that matches their own schema:\n  "
            + "\n  ".join(failures)
        )
        assert unexecuted == [], "operations that never answered:\n  " + "\n  ".join(unexecuted)


class TestAnonymousCallersAreRefused:
    def test_every_operation_refuses_an_unauthenticated_caller(self, live):
        operations = [item for item in _order(_operations()) if not _gate_public(_concrete(item[1]))]
        assert len(operations) >= 1000, f"only {len(operations)} protected operations found"

        results = _sweep(live, operations, lambda _index: None, retry_429=False)
        served = {
            item: result for item, result in results.items()
            if isinstance(result[0], int) and 200 <= result[0] < 300
        }
        assert served == {}, (
            "operations served to a caller with no credential:\n  " + _describe(served)
        )
        assert not [item for item, result in results.items() if not isinstance(result[0], int)], (
            "operations that never answered an anonymous caller:\n  "
            + _describe({item: result for item, result in results.items() if not isinstance(result[0], int)})
        )

    def test_nothing_is_public_outside_the_declared_list(self, live):
        # The declared list is the contract. Every path on it must behave as
        # public (not 401) and nothing else may.
        operations = _order(_operations())
        public = [item for item in operations if _gate_public(_concrete(item[1]))]
        assert public, "no unprotected operation in the schema — the list and the app disagree"
        results = _sweep(live, public, lambda _index: None, retry_429=False)
        refused = {
            item: result for item, result in results.items()
            if result[0] in (401, 403)
        }
        # A public route may still refuse on its own credentials (an HMAC the
        # sweep does not have), but it must not be refused by the session gate.
        gate = {item: result for item, result in refused.items() if b"Authentication required" in result[1]}
        assert gate == {}, "paths declared public but refused by the session gate:\n  " + _describe(gate)


class TestReadOnlyOperatorsCannotWrite:
    def test_no_write_operation_is_served_to_a_read_only_operator(self, live):
        operations = [
            item for item in _order(_operations())
            if item[0] not in READ
            and not _gate_public(_concrete(item[1]))
            and not any(marker in item[1] for marker in SESSION_KILLERS)
            and not any(marker in item[1] for marker in GLOBAL_SWITCHES)
            and not any(marker in item[1] for marker in SELF_SERVICE_WRITES)
        ]
        assert len(operations) >= 200, f"only {len(operations)} write operations found"

        readonly = live["mint"](["readonly"])
        results = _sweep(live, operations, lambda _index: readonly, retry_429=False)
        served = {
            item: result for item, result in results.items()
            if isinstance(result[0], int) and 200 <= result[0] < 300
        }
        assert served == {}, (
            "write operations a read-only operator was allowed to perform:\n  " + _describe(served)
        )


def _declared_json(spec: dict, path: str, method: str) -> dict | None:
    """The 2xx JSON schema the operation declares, if it declares one."""
    operation = spec["paths"].get(path, {}).get(method.lower())
    if not operation:
        return None
    for code, response in (operation.get("responses") or {}).items():
        if not str(code).startswith("2"):
            continue
        content = (response.get("content") or {}).get("application/json")
        if content and content.get("schema"):
            return content["schema"]
    return None


class TestResponseBodiesMatchTheDeclaredContract:
    """A 200 is not correctness. The body has to be what the schema promised.

    Guide 100 §5 limit (a): "route existence is not response correctness". This
    closes the part of it that can be closed mechanically — every operation that
    declares a 2xx JSON schema is called on the live server and the body is
    validated against that schema — and measures the part that cannot: the
    operations that declare nothing, and whose payload shape is therefore only
    as good as the console's TypeScript interface. The count is asserted so the
    typed surface can grow but not silently shrink.
    """

    def test_every_declared_response_schema_holds(self, live):
        import jsonschema
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012

        import api_contract

        spec = api_contract.openapi_spec()
        # The document is an OpenAPI 3.1 spec, not a JSON Schema, but its
        # components are JSON Schema 2020-12; registering it as a resource under
        # one urn makes every "#/components/schemas/X" pointer resolvable.
        registry = Registry().with_resource(
            "urn:cryptoscan:spec", Resource.from_contents(spec, default_specification=DRAFT202012)
        )

        def rebase(node):
            """Point every in-document ``#/...`` reference at the registered resource."""
            if isinstance(node, dict):
                return {
                    key: ("urn:cryptoscan:spec" + value if key == "$ref" and isinstance(value, str)
                          and value.startswith("#/") else rebase(value))
                    for key, value in node.items()
                }
            if isinstance(node, list):
                return [rebase(item) for item in node]
            return node

        def validate(body, schema):
            return list(
                jsonschema.Draft202012Validator(rebase(schema), registry=registry).iter_errors(body)
            )
        operations = [
            (method, path)
            for path, methods in api_contract.served_operations().items()
            for method in methods
            if _declared_json(spec, path, method)
        ]
        assert len(operations) >= 80, (
            f"only {len(operations)} operations declare a 2xx JSON schema — the typed "
            "surface shrank or the schema walk is broken"
        )

        tokens = [live["mint"](["superadmin"]) for _ in range(4)]
        results = _sweep(live, _order(operations), lambda index: tokens[index % len(tokens)])

        invalid: list[str] = []
        untyped_bodies: list[str] = []
        for (method, path), (status, payload) in sorted(results.items()):
            if not isinstance(status, int) or not 200 <= status < 300:
                continue  # the sweep above proves these answer; 404/422 has no body contract
            try:
                body = json.loads(payload)
            except Exception:
                untyped_bodies.append(f"{method} {path} -> 2xx but not JSON: {payload[:120]!r}")
                continue
            schema = _declared_json(spec, path, method)
            errors = sorted(validate(body, schema), key=lambda e: list(e.path))
            if errors:
                invalid.append(f"{method} {path} -> {errors[0].message[:200]}")
        assert untyped_bodies == [], (
            "operations that declare a JSON response and returned something else:\n  "
            + "\n  ".join(untyped_bodies)
        )
        assert invalid == [], (
            "responses that do not match the schema the route declares:\n  " + "\n  ".join(invalid)
        )

    def test_the_typed_surface_is_measured_not_assumed(self, live):
        """The honest number: how much of the API declares its own response."""
        import api_contract

        spec = api_contract.openapi_spec()
        operations = [
            (method, path)
            for path, methods in api_contract.served_operations().items()
            for method in methods
        ]
        typed = [item for item in operations if _declared_json(spec, item[1], item[0])]
        assert len(operations) >= 1200
        #: Measured 94 of 1250 (7.5%) when the cloud-account inventory, the backup
        #: family, the business process/owner family and the process/system link
        #: were given `response_model`, plus `/backup/create`, `/backup/list` and the
        #: twin path. The gap is §5's limit (a): the remaining
        #: 92.5% are validated by nothing but their console interface, and this
        #: test records that rather than hiding it. The floor only moves up —
        #: typing a route is the only way to raise it, and dropping one is the only
        #: way to trip it. `scripts/tests/test_response_typing.py` keeps the exact
        #: list, so a *new* untyped route is a build failure too.
        assert len(typed) >= 92, (
            f"{len(typed)} of {len(operations)} operations declare a response schema; this was "
            "94 — a typed route lost its model"
        )


class TestAuthorizationIsProvenPerRoute:
    """Every route that declares a role requirement is asked, with and without it.

    Checks 1–2 in guide 100 prove a route is *registered*. The auth inventory
    proves each route has an authentication seam. Neither proves the role set is
    enforced — and a gate that reads the wrong thing (the username instead of the
    role, as ``routers/compliance.py`` did) passes both. So for every operation
    whose dependency tree carries a ``require_roles`` requirement:

    * a principal holding one of the roles is admitted (never 401/403);
    * a principal holding none of them is refused.

    Operations with no role requirement are authenticated-only by design — any
    signed-in operator may call them — and are counted, not asserted.
    """

    def test_every_role_gated_operation_admits_a_principal_that_holds_the_role(self, live):
        gated = _role_gated_operations()
        assert len(gated) >= 300, f"only {len(gated)} role-gated operations found — the walk is broken"

        tokens = [live["mint"](["superadmin"]) for _ in range(6)]
        operations = _order([item for item in gated if item in set(_operations())])
        results = _sweep(live, operations, lambda index: tokens[index % len(tokens)])
        refused = {
            item: result for item, result in results.items()
            if result[0] in (401, 403)
        }
        assert refused == {}, (
            "role-gated operations that refused a superadmin — the gate is checking "
            "something other than the held roles:\n  " + _describe(refused)
        )

    def test_every_role_gated_operation_refuses_a_principal_without_the_role(self, live):
        gated = _role_gated_operations()
        operations = [
            item for item in _order(list(gated))
            if item in set(_operations())
            # a route that also accepts the read-only role is meant to serve it
            and not any(_grants(["readonly"], requirement) for requirement in gated[item])
            and not _gate_public(_concrete(item[1]))
        ]
        assert len(operations) >= 260, f"only {len(operations)} operations exclude the read-only role"

        readonly = live["mint"](["readonly"])
        results = _sweep(live, operations, lambda _index: readonly, retry_429=False)
        served = {
            item: result for item, result in results.items()
            if isinstance(result[0], int) and 200 <= result[0] < 300
        }
        assert served == {}, (
            "role-gated operations served to a principal that holds none of the "
            "required roles:\n  " + _describe(served)
        )
