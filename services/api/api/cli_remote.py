"""``cryptoscan`` as a **control-plane client** — the bank operator's command surface.

The architecture this implements, and the one it deliberately refuses:

    admin terminal  →  cryptoscan  →  HTTPS/mTLS  →  CryptoScan control plane (in-bank)
                                                          │
                                                    job manager / collectors

The CLI is **not** the scanner. It does not enumerate hosts, read `/proc`, talk to an HSM
or hold a private key. It authenticates to the bank's own control plane, submits work,
watches it, and reads evidence back. That boundary is what makes the product installable
in a bank: everything — collectors, evidence, twin, BOMs — stays inside the bank's
security boundary, and the tool an operator runs from a jump host has no collection
capability at all.

Four rules shape the code:

* **Every command names the endpoint it read.** Output carries ``source: GET /path
  (HTTP 200)``. An operator can check a number against the API, and a command whose
  endpoint does not exist cannot quietly print something invented.
* **A missing capability is reported, not faked.** Where the control plane has no
  endpoint (scope diff, per-evidence verification), the command refuses with the reason
  and the closest endpoints that *do* exist — exit code 3, the same refusal vocabulary
  the in-process commands use.
* **Failure is not success.** A non-2xx response exits non-zero with the server's own
  detail. There is no ``--ignore-errors`` that turns a 500 into a green tick.
* **Credentials are sessions, not permanent keys.** ``cryptoscan login`` stores the
  short-lived session token (``0600``) that ``/auth/login`` returns, and MFA is honoured
  (the command asks for the second factor instead of silently failing). An API key is
  supported for machine use because the platform supports it, and mTLS is supported
  because a bank will ask for it — but neither is the default.

Exit codes are shared with the in-process commands: ``0`` ok, ``1`` error, ``2``
incomplete/drifted, ``3`` refused (capability or authority missing).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import ssl
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from shared_models import release_signature

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INCOMPLETE = 2
EXIT_REFUSED = 3

DEFAULT_TIMEOUT = 20.0
DEFAULT_CONFIG_PATH = Path(
    os.environ.get("CRYPTOSCAN_CONFIG")
    or (Path.home() / ".config" / "cryptoscan" / "config.json")
)
CONFIG_MODE = 0o600

#: Test seam. ``None`` means "use urllib"; tests replace it with a fake transport that
#: answers from a path→payload map, so no test needs a socket (the suite runs with
#: ``pytest-socket``).
TRANSPORT: Callable[..., "Response"] | None = None


class Refused(Exception):
    """The control plane has no such capability, or the local side cannot supply it."""

    def __init__(self, reason: str, *, detail: str | None = None, closest: Sequence[str] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail
        self.closest = tuple(closest)


class ApiError(Exception):
    def __init__(self, status: int, method: str, path: str, body: Any, hint: str | None = None) -> None:
        super().__init__(f"{method} {path} → HTTP {status}")
        self.status = status
        self.method = method
        self.path = path
        self.body = body
        self.hint = hint

    def detail(self) -> str:
        if isinstance(self.body, Mapping):
            detail = self.body.get("detail")
            if isinstance(detail, Mapping):
                return json.dumps(detail, sort_keys=True)
            if detail is not None:
                return str(detail)
        if isinstance(self.body, (bytes, bytearray)):
            text = self.body.decode("utf-8", "replace").strip()
            return text[:400]
        return "" if self.body is None else str(self.body)[:400]


# --------------------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    """Where the control plane is, and how this process proves who it is.

    ``token`` is a session token obtained by ``login``; ``api_key`` is the machine
    credential (``x-api-key``); ``client_cert``/``client_key`` enable mTLS. Precedence on
    the wire is mTLS (transport-level) plus bearer token if present, else the API key —
    an operator who configured both is sending two proofs, and the server decides, not
    this client.
    """

    server: str | None = None
    token: str | None = None
    api_key: str | None = None
    ca: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    verify_tls: bool = True
    timeout: float = DEFAULT_TIMEOUT

    def with_env(self) -> "Config":
        """Environment wins over the file: it is how CI supplies a credential."""
        return replace(
            self,
            server=os.environ.get("CRYPTOSCAN_SERVER") or self.server,
            token=os.environ.get("CRYPTOSCAN_TOKEN") or self.token,
            api_key=os.environ.get("CRYPTOSCAN_API_KEY") or self.api_key,
            ca=os.environ.get("CRYPTOSCAN_CA") or self.ca,
            client_cert=os.environ.get("CRYPTOSCAN_CLIENT_CERT") or self.client_cert,
            client_key=os.environ.get("CRYPTOSCAN_CLIENT_KEY") or self.client_key,
        )

    def missing(self) -> list[str]:
        problems: list[str] = []
        if not self.server:
            problems.append("no server configured (--server, CRYPTOSCAN_SERVER or `cryptoscan login`)")
        if not (self.token or self.api_key):
            problems.append("no credential configured (run `cryptoscan login`, or set CRYPTOSCAN_API_KEY)")
        if bool(self.client_cert) != bool(self.client_key):
            problems.append("mTLS needs both --client-cert and --client-key")
        return problems


def load_config(path: Path | None = None) -> Config:
    target = Path(path) if path else DEFAULT_CONFIG_PATH
    try:
        raw = json.loads(target.read_text())
    except FileNotFoundError:
        return Config()
    except (OSError, ValueError):
        return Config()
    if not isinstance(raw, Mapping):
        return Config()
    return Config(
        server=_str(raw.get("server")),
        token=_str(raw.get("token")),
        api_key=_str(raw.get("api_key")),
        ca=_str(raw.get("ca")),
        client_cert=_str(raw.get("client_cert")),
        client_key=_str(raw.get("client_key")),
        verify_tls=bool(raw.get("verify_tls", True)),
        timeout=float(raw.get("timeout") or DEFAULT_TIMEOUT),
    )


def save_config(config: Config, path: Path | None = None) -> Path:
    target = Path(path) if path else DEFAULT_CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({
        "server": config.server,
        "token": config.token,
        "api_key": config.api_key,
        "ca": config.ca,
        "client_cert": config.client_cert,
        "client_key": config.client_key,
        "verify_tls": config.verify_tls,
        "timeout": config.timeout,
    }, indent=2))
    try:
        target.chmod(CONFIG_MODE)
    except OSError:  # pragma: no cover - a platform without POSIX modes
        pass
    return target


def clear_token(path: Path | None = None) -> Config:
    """Drop the session token, keep server/TLS settings (they are not secrets)."""
    config = load_config(path)
    cleared = replace(config, token=None)
    if config.server or config.api_key or config.ca:
        save_config(cleared, path)
    return cleared


def config_permissions(path: Path | None = None) -> str:
    target = Path(path) if path else DEFAULT_CONFIG_PATH
    try:
        mode = target.stat().st_mode & 0o777
    except OSError:
        return "ABSENT"
    return "PRIVATE" if mode & 0o077 == 0 else f"TOO_OPEN({oct(mode)})"


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# --------------------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------------------


@dataclass
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return self.body.decode("utf-8", "replace")


def _ssl_context(config: Config) -> ssl.SSLContext | None:
    if not (config.server or "").startswith("https"):
        return None
    if not config.verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context(cafile=config.ca) if config.ca else ssl.create_default_context()
    if config.client_cert and config.client_key:
        context.load_cert_chain(config.client_cert, config.client_key)
    return context


def _urllib_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    context: ssl.SSLContext | None,
    timeout: float,
) -> Response:
    """The only place a socket is opened. Everything else is testable without one."""
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context) if context else urllib.request.HTTPSHandler()
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return Response(response.status, dict(response.headers), response.read())
    except urllib.error.HTTPError as exc:  # a 4xx/5xx is a response, not an exception to hide
        return Response(exc.code, dict(exc.headers or {}), exc.read() or b"")
    except urllib.error.URLError as exc:
        raise Refused(
            f"cannot reach the control plane at {url.split('/api/')[0]}: {exc.reason}",
            detail="check --server, the CA bundle, and that the API is running inside the bank",
        ) from exc


class Client:
    """A thin, honest HTTP client: no retries that hide failures, no silent fallbacks."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._context = _ssl_context(config)

    # -- plumbing -----------------------------------------------------------------
    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Any = None,
    ) -> Response:
        config = self.config
        if not config.server:
            raise Refused("no server configured", detail="pass --server or run `cryptoscan login`")
        url = config.server.rstrip("/") + path
        if query:
            encoded = urllib.parse.urlencode({k: v for k, v in query.items() if v not in (None, "")})
            if encoded:
                url = f"{url}?{encoded}"
        headers: dict[str, str] = {"Accept": "application/json", "User-Agent": "cryptoscan-cli/1.0"}
        payload: bytes | None = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"
        if config.api_key:
            headers["x-api-key"] = config.api_key
        transport = TRANSPORT or _urllib_transport
        response = transport(method, url, headers, payload, self._context, config.timeout)
        if response.status >= 400:
            payload_json = response.json()
            raise ApiError(response.status, method, path, payload_json, hint=_hint_for(response.status))
        return response

    def get(self, path: str, **query: Any) -> Any:
        return self.request("GET", path, query=query or None).json()

    def post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, body=body).json()

    def put(self, path: str, body: Any = None) -> Any:
        return self.request("PUT", path, body=body).json()

    def source(self, method: str, path: str, status: int = 200, **query: Any) -> str:
        suffix = ""
        if query:
            encoded = urllib.parse.urlencode({k: v for k, v in query.items() if v not in (None, "")})
            if encoded:
                suffix = f"?{encoded}"
        return f"{method} {path}{suffix} (HTTP {status})"


def _hint_for(status: int) -> str | None:
    if status == 401:
        return "run `cryptoscan login` (or set CRYPTOSCAN_API_KEY); sessions expire"
    if status == 403:
        return "the credential is valid but not authorised for this operation or estate"
    if status == 404:
        return "the object is unknown to this estate, or the endpoint is not in this build"
    if status == 422:
        return "the control plane rejected the request body; see detail"
    if status >= 500:
        return "the control plane failed this request; do not treat it as an empty result"
    return None


# --------------------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------------------


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str, sort_keys=False))


def _emit(args: argparse.Namespace, payload: Any, *, source: str, render: Callable[[], None] | None = None) -> int:
    """One place that decides "machine output or human output", so no command forgets."""
    if getattr(args, "json", False) or render is None:
        _print_json(payload)
        return EXIT_OK
    render()
    if not getattr(args, "quiet", False):
        print(f"\nsource: {source}")
    return EXIT_OK


def _field(payload: Any, *keys: str, default: Any = None) -> Any:
    """Read a dotted path, returning ``default`` rather than raising on a shape change."""
    current: Any = payload
    for key in keys:
        if isinstance(current, Mapping) and key in current:
            current = current[key]
        elif isinstance(current, list) and key.isdigit() and int(key) < len(current):
            current = current[int(key)]
        else:
            return default
    return current


def _table(rows: Sequence[Sequence[Any]], headers: Sequence[str], *, limit: int | None = None) -> None:
    rows = list(rows[:limit] if limit else rows)
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip())
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip())


def _short(value: Any, width: int = 90) -> str:
    text = "—" if value is None else str(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def _refuse(command: str, exc: Refused) -> int:
    print(f"{command}: REFUSED — {exc.reason}", file=sys.stderr)
    if exc.detail:
        print(f"  {exc.detail}", file=sys.stderr)
    for endpoint in exc.closest:
        print(f"  closest existing endpoint: {endpoint}", file=sys.stderr)
    return EXIT_REFUSED


def _client(args: argparse.Namespace) -> Client:
    """Build a client from file + environment + flags, and refuse early when unusable."""
    config = load_config().with_env()
    overrides: dict[str, Any] = {}
    if getattr(args, "server", None):
        overrides["server"] = args.server
    if getattr(args, "token", None):
        overrides["token"] = args.token
    if getattr(args, "api_key", None):
        overrides["api_key"] = args.api_key
    if getattr(args, "ca", None):
        overrides["ca"] = args.ca
    if getattr(args, "client_cert", None):
        overrides["client_cert"] = args.client_cert
    if getattr(args, "client_key", None):
        overrides["client_key"] = args.client_key
    if getattr(args, "insecure", False):
        overrides["verify_tls"] = False
    if overrides:
        config = replace(config, **overrides)
    missing = config.missing()
    if missing:
        raise Refused(
            "the client is not usable yet",
            detail="; ".join(missing),
            closest=("cryptoscan login --server https://<control-plane>", "cryptoscan doctor"),
        )
    return Client(config)


# --------------------------------------------------------------------------------------
# commands: identity, environment, status
# --------------------------------------------------------------------------------------


def _cmd_version(args: argparse.Namespace, _session: Any = None) -> int:
    local = {"cli": "cryptoscan 1.0", "server_version": None}
    try:
        client = _client(args)
        payload = client.get("/health")
        local["server_version"] = _field(payload, "version") or _field(payload, "status")
        local["server"] = client.config.server
    except (Refused, ApiError) as exc:
        local["server_error"] = _reason(exc)
    return _emit(args, local, source="GET /health" if local.get("server_version") else "local build")


def _reason(exc: Exception) -> str:
    if isinstance(exc, ApiError):
        return f"HTTP {exc.status}: {exc.detail()}".strip()
    if isinstance(exc, Refused):
        return exc.reason
    return str(exc)


def _cmd_login(args: argparse.Namespace, _session: Any = None) -> int:
    """Obtain a session token; honour MFA instead of pretending it succeeded."""
    config = load_config().with_env()
    server = args.server or config.server
    if not server:
        return _refuse("login", Refused("no server given", detail="pass --server https://<control-plane>"))
    password = args.password or os.environ.get("CRYPTOSCAN_PASSWORD")
    if getattr(args, "password_stdin", False):
        password = sys.stdin.readline().rstrip("\n")
    body = {"username": args.username, "password": password}
    if not body["password"]:
        return _refuse("login", Refused(
            "no password supplied",
            detail="use --password-stdin to keep the password out of shell history and process args",
        ))
    client = Client(replace(config, server=server, token=None, api_key=None))
    try:
        payload = client.post("/api/v1/auth/login", body)
    except (Refused, ApiError) as exc:
        return _fail("login", exc)
    if _field(payload, "mfa_required"):
        token = _field(payload, "mfa_token")
        if not args.mfa_code:
            print("login: MFA required. Re-run with --mfa-code <code>.", file=sys.stderr)
            print(f"  challenge token expires shortly; obtained for user {args.username}", file=sys.stderr)
            return EXIT_REFUSED
        try:
            payload = client.post("/api/v1/auth/login/mfa", {"mfa_token": token, "code": args.mfa_code})
        except (Refused, ApiError) as exc:
            return _fail("login", exc)
    session = _field(payload, "token")
    if not session:
        return _fail("login", Refused("the control plane returned no session token"))
    saved = save_config(replace(config, server=server, token=session, api_key=None))
    print(f"logged in as {_field(payload, 'username', default=args.username)} "
          f"roles={','.join(_field(payload, 'roles', default=[]) or [])}")
    print(f"session expires: {_field(payload, 'session_expires_at', default='unknown')}")
    print(f"credential stored: {saved} ({config_permissions(saved).lower()})")
    print("note: this is a session token, not a permanent key — it expires and `cryptoscan logout` removes it")
    return EXIT_OK


def _cmd_logout(args: argparse.Namespace, _session: Any = None) -> int:
    config = load_config().with_env()
    revoked = "not_attempted"
    if config.server and config.token:
        try:
            Client(config).post("/api/v1/auth/logout")
            revoked = "revoked_by_server"
        except (Refused, ApiError) as exc:
            revoked = f"local_only ({_reason(exc)})"
    cleared = clear_token()
    return _emit(args, {"revoked": revoked, "token_cleared": cleared.token is None},
                 source="POST /api/v1/auth/logout")


def _cmd_status(args: argparse.Namespace, _session: Any = None) -> int:
    client = _client(args)
    report: dict[str, Any] = {"server": client.config.server}
    failures = 0
    for key, path in (
        ("health", "/api/v1/healthz"),
        ("readiness", "/api/v1/readiness/summary"),
        ("identity", "/api/v1/auth/me"),
    ):
        try:
            report[key] = client.get(path)
        except (Refused, ApiError) as exc:
            report[key] = {"error": _reason(exc)}
            failures += 1

    def render() -> None:
        health = report.get("health") or {}
        readiness = report.get("readiness") or {}
        identity = report.get("identity") or {}
        print(f"server        {report['server']}")
        print(f"health        {_short(_field(health, 'status', default=health if isinstance(health, str) else None))}")
        print(f"readiness     {_short(_field(readiness, 'status', default=_field(readiness, 'state')))}")
        print(f"identity      {_field(identity, 'username', default='—')} "
              f"roles={','.join(_field(identity, 'roles', default=[]) or []) or '—'}")
        print(f"estate        {_field(identity, 'tenant_id', default='—')}")
        if failures:
            print(f"\n{failures} probe(s) failed — see --json; nothing above is being inferred")

    return _emit(args, report, source="GET /api/v1/healthz, /readiness/summary, /auth/me", render=render)


CHECKS: tuple[tuple[str, str], ...] = (
    ("control plane dependencies", "/api/v1/healthz/dependencies"),
    ("schema", "/api/v1/healthz/schema"),
    ("worker fleet", "/api/v1/health/worker-fleet"),
    ("connectors", "/api/v1/health/connectors"),
    ("control plane", "/api/v1/control/health"),
    ("graph store", "/api/v1/graph/health"),
    ("automation", "/api/v1/automation/health/platform"),
)


def _cmd_doctor(args: argparse.Namespace, _session: Any = None) -> int:
    """Environment check. Every line is a real probe or explicitly NOT_OBSERVED."""
    config = load_config().with_env()
    rows: list[tuple[str, str, str]] = []
    blocking = 0
    warnings = 0

    perms = config_permissions()
    rows.append(("credential file", "OK" if perms in {"PRIVATE", "ABSENT"} else "WARN", perms))
    warnings += 0 if perms in {"PRIVATE", "ABSENT"} else 1

    rows.append(("tls identity", "OK" if config.client_cert else "NOT_CONFIGURED",
                 config.client_cert or "no client certificate — session token or API key will be used"))
    warnings += 0 if config.client_cert else 1

    try:
        client = _client(args)
    except Refused as exc:
        rows.append(("client configuration", "FAIL", exc.reason))
        blocking += 1
        _doctor_render(rows, blocking, warnings, args)
        return EXIT_REFUSED if not args.json else (_print_json(rows) or EXIT_REFUSED)

    try:
        me = client.get("/api/v1/auth/me")
        identity = _field(me, "username") or "unknown"
        rows.append(("authenticated identity", "OK", identity))
    except (Refused, ApiError) as exc:
        rows.append(("authenticated identity", "FAIL", _reason(exc)))
        blocking += 1

    for label, path in CHECKS:
        try:
            payload = client.get(path)
        except Refused as exc:
            rows.append((label, "FAIL", _reason(exc)))
            blocking += 1
            continue
        except ApiError as exc:
            state = "WARN" if exc.status in (403, 404, 501) else "FAIL"
            warnings += state == "WARN"
            blocking += state == "FAIL"
            rows.append((label, state, f"HTTP {exc.status}: {exc.detail()}"))
            continue
        status = _doctor_state(payload)
        if status != "OK":
            warnings += status == "WARN"
            blocking += status == "FAIL"
        rows.append((label, status, _short(_field(payload, "status", default=_field(payload, "state")), 70)))

    rows.append(("clock", "NOT_OBSERVED", "the server does not report its clock; compare with NTP on the host"))
    _doctor_render(rows, blocking, warnings, args)
    if args.json:
        _print_json({"checks": [{"check": c, "state": s, "detail": d} for c, s, d in rows],
                     "blocking": blocking, "warnings": warnings})
    if blocking:
        return EXIT_INCOMPLETE
    return EXIT_OK


def _doctor_state(payload: Any) -> str:
    text = (_field(payload, "status") or _field(payload, "state") or _field(payload, "health") or "")
    text = str(text).upper()
    if text in {"OK", "UP", "HEALTHY", "READY", "TRUE", "PASS"}:
        return "OK"
    if text in {"DEGRADED", "WARN", "WARNING", "PARTIAL"}:
        return "WARN"
    if text in {"", "UNKNOWN"}:
        # a 200 with no verdict is not a pass; the plainest honest answer is "not stated"
        return "NOT_OBSERVED"
    return "FAIL"


def _doctor_render(rows: Sequence[tuple[str, str, str]], blocking: int, warnings: int,
                   args: argparse.Namespace) -> None:
    if args.json:
        return
    for label, state, detail in rows:
        mark = {"OK": "✓", "WARN": "!", "FAIL": "✗"}.get(state, "·")
        print(f"{mark} {label:<26} {state:<13} {detail}")
    if blocking:
        print("\nResult: NOT READY")
    elif warnings:
        print("\nResult: READY WITH WARNINGS")
    else:
        print("\nResult: READY")
    print("note: READY means these probes answered. It does not mean a scan has run or that "
          "coverage is complete — use `cryptoscan status --json` and the estate coverage report.")


# --------------------------------------------------------------------------------------
# commands: targets
# --------------------------------------------------------------------------------------

TARGETS = "/api/v1/collection/targets"
COLLECTORS = "/api/v1/collection/collectors"


def _cmd_target(args: argparse.Namespace, _session: Any = None) -> int:
    client = _client(args)
    action = args.target_command
    try:
        if action == "list":
            payload = client.get(TARGETS)
            rows = _items(payload)

            def render() -> None:
                if not rows:
                    print("no registered targets — `cryptoscan target register --help`")
                    return
                _table([[t.get("target_key") or t.get("identifier") or "—",
                         t.get("system_id", "—"), t.get("environment", "—"),
                         t.get("collection_method", "—"),
                         "YES" if t.get("read_only") else "no",
                         (t.get("status") or t.get("state") or "—")] for t in rows],
                       ["target", "system", "environment", "method", "read-only", "status"])
            return _emit(args, payload, source=client.source("GET", TARGETS), render=render)

        if action == "show":
            payload = client.get(f"{TARGETS}/{urllib.parse.quote(args.identifier)}")
            return _emit(args, payload, source=client.source("GET", f"{TARGETS}/{args.identifier}"))

        if action == "register":
            body = _target_body(args)
            payload = client.post(TARGETS, body)
            return _emit(args, payload, source=client.source("POST", TARGETS, 201))

        if action == "update":
            # A revision, not a new registration: the control plane keeps the history and
            # rejects a change that would widen authorisation without an explicit new body.
            body = {key: value for key, value in {
                "address": args.address,
                "owner": args.owner,
                "environment": args.environment,
                "collection_method": args.collection_method,
                "allowed_operations": list(args.allowed_operations or []) or None,
                "not_before": args.not_before,
            }.items() if value is not None}
            if not body:
                return _refuse("target update", Refused(
                    "nothing to change",
                    detail="pass at least one of --address, --owner, --environment, "
                           "--collection-method, --allowed-operation, --not-before; a PUT with an "
                           "empty body would be a revision nobody asked for",
                ))
            path = f"{TARGETS}/{urllib.parse.quote(args.identifier)}"
            payload = client.put(path, body)
            return _emit(args, payload, source=client.source("PUT", path))

        if action in {"authorize", "revoke"}:
            path = f"{TARGETS}/{urllib.parse.quote(args.identifier)}/{action}"
            body = {"reason": args.reason} if getattr(args, "reason", None) else None
            payload = client.post(path, body)
            return _emit(args, payload, source=client.source("POST", path))
    except (Refused, ApiError) as exc:
        return _fail(f"target {action}", exc)
    raise Refused(f"unknown target action {action!r}")


def _target_body(args: argparse.Namespace) -> dict[str, Any]:
    """Build the registration body the control plane requires, refusing to invent defaults.

    ``not_before`` and ``allowed_operations`` have no safe default: a target registered
    with "everything" or "already valid" is an authorisation nobody granted.
    """
    missing = [name for name in ("target_key", "system_id", "owner", "environment",
                                 "collection_method", "address", "allowed_operations", "not_before")
               if not getattr(args, name.replace("-", "_"), None)]
    if missing:
        raise Refused("target registration needs explicit fields: " + ", ".join(missing),
                      detail="there is no default for these — a target registered without them "
                             "would be an authorisation nobody granted")
    body: dict[str, Any] = {
        "target_key": args.target_key,
        "system_id": args.system_id,
        "owner": args.owner,
        "environment": args.environment,
        "collection_method": args.collection_method,
        "address": args.address,
        "allowed_operations": list(args.allowed_operations),
        "not_before": args.not_before,
    }
    if args.read_only:
        body["read_only"] = True
    if args.credential_ref:
        body["credential_ref"] = args.credential_ref
    if args.exclusion:
        body["exclusions"] = list(args.exclusion)
    return body


def _items(payload: Any, key: str | None = None) -> list[dict[str, Any]]:
    """The list inside a listing response, whatever wrapper the endpoint chose."""
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, Mapping):
        keys = ("items", "targets", "jobs", "records", "rows", "data", "results")
        for name in ((key,) if key else ()) + keys:
            value = payload.get(name)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


# --------------------------------------------------------------------------------------
# commands: jobs
# --------------------------------------------------------------------------------------


def _cmd_jobs(args: argparse.Namespace, _session: Any = None) -> int:
    client = _client(args)
    action = args.jobs_command
    try:
        if action == "list":
            payload = client.get("/api/v1/jobs", limit=args.limit)
            rows = _items(payload)

            def render() -> None:
                if not rows:
                    print("no jobs — the control plane returned an empty list (not an error)")
                    return
                _table([[r.get("id") or r.get("job_id") or "—", r.get("status", "—"),
                         r.get("type") or r.get("kind") or "—",
                         _short(r.get("created_at") or r.get("submitted_at"), 24)]
                        for r in rows], ["job", "status", "type", "created"], limit=args.limit)
            return _emit(args, payload, source=client.source("GET", "/api/v1/jobs"), render=render)

        if action == "show":
            payload = client.get(f"/api/v1/jobs/{urllib.parse.quote(args.job_id)}")
            return _emit(args, payload, source=client.source("GET", f"/api/v1/jobs/{args.job_id}"))

        if action == "logs":
            payload = client.get(f"/api/v1/jobs/{urllib.parse.quote(args.job_id)}/logs")
            return _emit(args, payload, source=client.source("GET", f"/api/v1/jobs/{args.job_id}/logs"))

        if action == "cancel":
            # collection jobs have their own cancel endpoint; the generic job API does not.
            path = f"/api/v1/collection/jobs/{urllib.parse.quote(args.job_id)}/cancel"
            payload = client.post(path)
            print(f"cancel requested for {args.job_id} via {path}")
            return _emit(args, payload, source=client.source("POST", path))

        if action == "retry":
            path = f"/api/v1/jobs/{urllib.parse.quote(args.job_id)}/retry"
            payload = client.post(path)
            print(f"retry requested for {args.job_id} via {path}")
            print("note: the control plane refuses a retry when an execution is unsettled (409) "
                  "and for synchronous network collections, which must go back through their "
                  "original admitted route")
            return _emit(args, payload, source=client.source("POST", path))

        if action in {"evidence", "errors", "projections"}:  # collection-job artefacts
            # These read a *collection* job's artefacts. They are separate subcommands
            # because an empty evidence list and a failed job look identical if you only
            # read `status`, and only one of them means "nothing was collected".
            path = f"/api/v1/collection/jobs/{urllib.parse.quote(args.job_id)}/{action}"
            payload = client.get(path)

            def render_artefact() -> None:
                rows = _items(payload)
                print(f"job           {args.job_id}")
                print(f"{action:<13} {len(rows) if rows else 0}")
                if action == "errors":
                    for item in (rows or [])[:20]:
                        print(f"  {_short(_field(item, 'code') or _field(item, 'stage'), 24):<24} "
                              f"{_short(_field(item, 'message') or _field(item, 'detail'), 90)}")
                    if not rows:
                        print("  — no collector error was recorded for this job")
                elif action == "evidence":
                    for item in (rows or [])[:20]:
                        print(f"  {_short(_field(item, 'evidence_id') or _field(item, 'id'), 28):<28} "
                              f"{_short(_field(item, 'evidence_type') or _field(item, 'type'), 24):<24} "
                              f"{_short(_field(item, 'target'), 40)}")
                else:
                    for item in (rows or [])[:20]:
                        print(f"  {_short(_field(item, 'kind') or _field(item, 'bom'), 20):<20} "
                              f"{_short(_field(item, 'count') or _field(item, 'components'), 12)}")
                print("\nthis is what the job stored; an empty list is not proof the estate is "
                      "empty — read `cryptoscan jobs show` for its coverage state.")
            return _emit(args, payload, source=client.source("GET", path), render=render_artefact)

        if action == "watch":
            return _watch(client, args)
    except (Refused, ApiError) as exc:
        return _fail(f"jobs {action}", exc)
    return EXIT_ERROR


TERMINAL_OK = frozenset({"COMPLETED", "SUCCEEDED", "SUCCESS"})
TERMINAL_BAD = frozenset({"FAILED", "CANCELLED", "CANCELED", "ERROR", "TIMED_OUT"})


def _print_coverage(client: Client, job_id: str) -> None:
    """Per-surface collection coverage, from the platform's own report.

    This is what replaces a fabricated progress bar: the endpoint states which surfaces were
    collected, how much of each, and — in the payload's own words — that the basis is the
    authorised manifest rather than the whole estate. Printing ``None`` as a percentage
    would undo the point of the field.
    """
    path = f"/api/v1/collection/jobs/{urllib.parse.quote(str(job_id))}/coverage"
    try:
        payload = client.get(path)
    except (Refused, ApiError) as exc:
        print(f"coverage unavailable: {_reason(exc)}", file=sys.stderr)
        return
    surfaces = _field(payload, "surfaces") or {}
    basis = _field(payload, "basis")
    print("coverage")
    if isinstance(surfaces, Mapping) and surfaces:
        for name, surface in surfaces.items():
            if isinstance(surface, Mapping):
                state = surface.get("state") or surface.get("status") or "—"
                count = surface.get("count") or surface.get("items") or surface.get("observations")
                detail = f"{count}" if count is not None else ""
                print(f"  {name:<22} {state:<16} {detail}".rstrip())
            else:
                print(f"  {name:<22} {_short(surface)}")
    else:
        print("  — (the job reports no surface coverage)")
    if basis:
        print(f"  basis: {basis}")
    for limit in _field(payload, "limits", default=[]) or []:
        print(f"  limit: {_short(limit, 100)}")
    print(f"  source: {client.source('GET', path)}")


def _watch(client: Client, args: argparse.Namespace) -> int:
    """Poll a job until it reaches a terminal state, printing real transitions only."""
    deadline = time.monotonic() + args.timeout
    last = None
    path = f"/api/v1/jobs/{urllib.parse.quote(args.job_id)}"
    while True:
        try:
            payload = client.get(path)
        except (Refused, ApiError) as exc:
            return _fail("jobs watch", exc)
        state = str(_field(payload, "status") or _field(payload, "state") or "UNKNOWN").upper()
        if state != last:
            print(f"[{time.strftime('%H:%M:%S')}] {state}")
            last = state
            if getattr(args, "coverage", False) and state not in TERMINAL_OK | TERMINAL_BAD:
                _print_coverage(client, args.job_id)
        if state in TERMINAL_OK:
            if getattr(args, "coverage", False):
                _print_coverage(client, args.job_id)
            _emit(args, payload, source=client.source("GET", path))
            return EXIT_OK
        if state in TERMINAL_BAD:
            if getattr(args, "coverage", False):
                _print_coverage(client, args.job_id)
            _emit(args, payload, source=client.source("GET", path))
            return EXIT_ERROR
        if time.monotonic() >= deadline:
            print(f"jobs watch: still {state} after {args.timeout:.0f}s — not treating that as success",
                  file=sys.stderr)
            return EXIT_INCOMPLETE
        time.sleep(args.interval)


# --------------------------------------------------------------------------------------
# commands: evidence, BOMs
# --------------------------------------------------------------------------------------

RECORDS = "/api/v1/estate/evidence/evidence/records"


def _cmd_collector(args: argparse.Namespace, _session: Any = None) -> int:
    """The collector catalog, exactly as the control plane declares it.

    The interesting column is `production_execution_qualified`: most entries are
    DEVELOPMENT/OFFLINE candidates, and a bank that reads only the id would think it can
    collect Windows, cloud, HSM and vendor estates today. It cannot, and the catalog says so.
    """
    client = _client(args)
    action = args.collector_command
    try:
        payload = client.get(COLLECTORS)
        rows = _items(payload, key="collectors")
        if action == "show":
            rows = [row for row in rows if row.get("id") == args.collector_id]
            if not rows:
                return _refuse("collector show", Refused(
                    f"no collector {args.collector_id!r} in the catalog",
                    detail="the catalog is a fixed declaration served with the build; it is "
                           "not a per-collector route, so this list was filtered client-side",
                    closest=[f"GET {COLLECTORS}"],
                ))

        def render() -> None:
            if not rows:
                print("the control plane returned an empty collector catalog — that is a "
                      "server-side defect, not a clean estate")
                return
            _table([[str(row.get("id") or row.get("method") or "—"),
                     row.get("method", "—"),
                     row.get("state", "—"),
                     "YES" if row.get("production_execution_qualified") else "NO",
                     "YES" if row.get("server_execution") else "NO"]
                    for row in rows],
                   ["collector", "method", "state", "prod-qualified", "runs-on-server"])
            qualified = sum(1 for row in rows if row.get("production_execution_qualified"))
            print(f"\n{qualified} of {len(rows)} collectors are production-execution qualified. "
                  "A method that is not qualified still collects nothing, whatever its BOM "
                  "capability strings suggest.")
            if action == "show":
                print("\nfiltered from the catalog listing client-side; "
                      f"source of every field: GET {COLLECTORS}")

        return _emit(args, {"collectors": rows} if action == "show" else payload,
                     source=client.source("GET", COLLECTORS), render=render)
    except (Refused, ApiError) as exc:
        return _fail(f"collector {action}", exc)
    raise Refused(f"unknown collector action {action!r}")


def _cmd_evidence(args: argparse.Namespace, _session: Any = None) -> int:
    client = _client(args)
    action = args.evidence_command
    try:
        if action == "list":
            query = {"target": args.target, "evidence_type": args.evidence_type, "limit": args.limit}
            payload = client.get(RECORDS, **query)
            rows = _items(payload)

            def render() -> None:
                if not rows:
                    print("no evidence records in this estate yet")
                    return
                _table([[r.get("evidence_id") or r.get("id") or "—",
                         r.get("evidence_type") or r.get("type") or "—",
                         _short(r.get("target") or r.get("asset_id"), 28),
                         _short(r.get("observed_at") or r.get("created_at"), 24)]
                        for r in rows], ["evidence", "type", "target", "observed"], limit=args.limit)
            return _emit(args, payload, source=client.source("GET", RECORDS, **query), render=render)

        if action == "show":
            path = f"{RECORDS}/{urllib.parse.quote(args.evidence_id)}"
            payload = client.get(path)
            record = _field(payload, "record") or {}

            def render_show() -> None:
                print(f"evidence      {record.get('evidence_id', '—')}")
                print(f"type          {record.get('evidence_type', '—')}")
                print(f"target        {record.get('target', '—')}")
                print(f"layer         {record.get('layer', '—')}")
                print(f"collector     {record.get('collector', '—')} {record.get('collector_version') or ''}".rstrip())
                print(f"source        {record.get('source', '—')}")
                print(f"confidence    {record.get('confidence', '—')}")
                print(f"observed      {record.get('observed_at', '—')}")
                print(f"first/last    {record.get('first_seen_at', '—')} / {record.get('last_seen_at', '—')}")
                print(f"observations  {record.get('observation_count', '—')}")
                print(f"state         {record.get('lifecycle_state', '—')}")
                print(f"raw reference {record.get('raw_reference') or '— (the raw output location was not recorded)'}")
                facts = record.get("facts") or {}
                if facts:
                    print("facts")
                    for key, value in sorted(facts.items()):
                        print(f"  {key:<22} {_short(value, 80)}")
                else:
                    print("facts         — (the record carries no facts)")
            return _emit(args, payload, source=client.source("GET", path), render=render_show)

        if action == "verify":
            path = f"{RECORDS}/{urllib.parse.quote(args.evidence_id)}/verify"
            payload = client.get(path)

            def render_verify() -> None:
                print(f"evidence      {_field(payload, 'evidence_id', default='—')}")
                print(f"verdict       {_field(payload, 'verdict', default='—')}")
                print(f"recomputed    {_field(payload, 'recomputed_id', default='—')}")
                print(f"content addr  {_field(payload, 'content_addressed', default='—')}")
                for item in _field(payload, "not_checked", default=[]) or []:
                    print(f"not checked   {item}")
                print(f"\n{_field(payload, 'limits', default='')}")
            _emit(args, payload, source=client.source("GET", path), render=render_verify)
            verdict = str(_field(payload, "verdict") or "")
            if verdict == "CONTENT_ADDRESS_INTACT":
                return EXIT_OK
            if verdict == "ID_NOT_CONTENT_ADDRESSED":
                # nothing was compared: the record's id was assigned, not derived
                return EXIT_INCOMPLETE
            return EXIT_ERROR
    except (Refused, ApiError) as exc:
        return _fail(f"evidence {action}", exc)
    return EXIT_ERROR


BOM_KINDS = ("SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM")
BOMS = "/api/v1/estate/evidence/boms"


def _cmd_bom(args: argparse.Namespace, _session: Any = None) -> int:
    client = _client(args)
    kind = args.kind.upper()
    if kind not in BOM_KINDS:
        return _refuse("bom", Refused(f"unknown BOM {args.kind!r}", detail=f"expected one of {', '.join(BOM_KINDS)}"))
    try:
        payload = client.get(BOMS, bom=kind)
    except (Refused, ApiError) as exc:
        return _fail("bom", exc)

    def render() -> None:
        rows = _items(payload)
        projection = _field(payload, kind) or _field(payload, kind.lower()) or payload
        print(f"{kind} projected from the stored evidence graph")
        run_id = _field(payload, "run_id")
        print(f"run           {run_id or '— (no stored run)'}")
        if isinstance(projection, Mapping):
            for key in ("schema", "total", "count", "generated_at"):
                if key in projection:
                    print(f"{key:<13} {_short(projection[key])}")
            items = projection.get("items") or projection.get("components") or projection.get("records")
            if isinstance(items, list):
                print(f"entries       {len(items)}")
        elif isinstance(projection, list):
            print(f"entries       {len(projection)}")
        if rows:
            print(f"rows returned {len(rows)}")
        print("note: this is a projection of the evidence graph. An empty section means nothing was "
              "observed, which is not the same as nothing being present.")

    return _emit(args, payload, source=client.source("GET", BOMS, bom=kind), render=render)


# --------------------------------------------------------------------------------------
# commands: twin, pqc, scope, explain
# --------------------------------------------------------------------------------------

TWIN = "/api/v1/estate/evidence/twin"


def twin_remote(args: argparse.Namespace, _session: Any = None) -> int:
    """``twin status|snapshot|diff`` against the control plane, not the local database."""
    client = _client(args)
    action = args.twin_command
    try:
        if action in {"remediation", "remediate", "reconcile"}:
            return _twin_remediation(args, client, action)
        if action == "status":
            payload = client.get(TWIN)
            return _emit(args, payload, source=client.source("GET", TWIN))
        if action == "snapshot":
            payload = client.get(f"{TWIN}/snapshot", include_payload=bool(getattr(args, "include_payload", False)))
            return _emit(args, payload, source=client.source("GET", f"{TWIN}/snapshot"))
        if action == "diff":
            if not (args.before or args.after):
                return _refuse("twin diff", Refused(
                    "no snapshots named",
                    detail="pass --from <snapshot> --to <snapshot> (both optional server-side; "
                           "naming them makes the comparison reproducible)",
                ))
            payload = client.get(f"{TWIN}/compare", before=args.before, after=args.after)
            def render() -> None:
                changes = _items(payload) or payload
                print(f"comparing {args.before or 'previous'} → {args.after or 'current'}")
                if isinstance(changes, Mapping):
                    for key in ("added", "removed", "changed", "unchanged", "summary"):
                        value = changes.get(key)
                        if value is not None:
                            count = len(value) if isinstance(value, list) else value
                            print(f"{key:<10} {count}")
                elif isinstance(changes, list):
                    print(f"changes    {len(changes)}")
            return _emit(args, payload, source=client.source("GET", f"{TWIN}/compare"), render=render)
    except (Refused, ApiError) as exc:
        return _fail(f"twin {action}", exc)
    return EXIT_ERROR


def _twin_remediation(args: argparse.Namespace, client: Any, action: str) -> int:
    """Work the twin opened from its own findings, and what would close it.

    ``remediate`` proposes and writes nothing unless ``--persist``; ``reconcile`` closes only
    what a stored observation proves. Neither can resolve a conflict or edit an asset — the
    command reads and files work, which is the whole point of the hand-off being small.
    """
    if action == "remediation":
        path = f"{TWIN}/remediation"
        payload = client.get(path)
        source = client.source("GET", path)

        def render() -> None:
            items = _items(payload) or payload.get("items") or []
            print(f"work items    {len(items)}")
            for status, count in sorted((payload.get("by_status") or {}).items()):
                print(f"  {status:<12} {count}")
            for item in items:
                proof = item.get("proof") or {}
                print(f"\n{item.get('claim_key')}  {item.get('status')}  [{item.get('severity')}]")
                print(f"  {item.get('title')}")
                print(f"  claim     {item.get('claim')}")
                print(f"  proof     {proof.get('kind')} — {proof.get('note') or ''}".rstrip())
                if item.get("proof_evidence_id"):
                    print(f"  closed by {item.get('proof_observation_id')} "
                          f"({item.get('proof_evidence_id')})")
                for line in item.get("not_proven") or []:
                    print(f"  does not prove: {line}")
        return _emit(args, payload, source=source, render=render)

    if action == "remediate":
        path = f"{TWIN}/remediate"
        payload = client.post(path, {"persist": bool(getattr(args, "persist", False))})
        source = client.source("POST", path, 200)

        def render() -> None:
            candidates = _items(payload) or payload.get("candidates") or []
            print(f"candidates    {len(candidates)} ({payload.get('created')} new, "
                  f"{payload.get('refreshed')} refreshed)")
            for candidate in candidates:
                proof = candidate.get("proof") or {}
                print(f"\n{candidate.get('source')}  [{candidate.get('severity')}]")
                print(f"  {candidate.get('title')}")
                print(f"  claim     {candidate.get('claim')}")
                print(f"  proof     {proof.get('kind')} — {proof.get('note') or ''}".rstrip())
            if not payload.get("persisted"):
                print("\nnothing was written: this was a proposal. Re-run with --persist to "
                      "open the work.")
            for line in payload.get("limits") or []:
                print(f"limit: {line}")
        return _emit(args, payload, source=source, render=render)

    path = f"{TWIN}/remediation/reconcile"
    payload = client.post(path)
    source = client.source("POST", path, 200)

    def render() -> None:
        counts = payload.get("counts") or {}
        print(f"checked       {payload.get('checked')}")
        for name in ("PROVEN", "STILL_OPEN", "PROOF_UNAVAILABLE"):
            print(f"  {name:<17} {counts.get(name, 0)}")
        for item in payload.get("proven") or []:
            print(f"\nPROVEN  {item.get('claim_key')}")
            print(f"  {item.get('title')}")
            print(f"  closed by {item.get('proof_observation_id')} "
                  f"({item.get('proof_evidence_id')})")
        for item in payload.get("still_open") or []:
            print(f"STILL OPEN  {item.get('claim_key')}: {item.get('reason')}")
        for item in payload.get("proof_unavailable") or []:
            print(f"NO PROOF    {item.get('claim_key')}: {item.get('reason')}")
    return _emit(args, payload, source=source, render=render)


PQC = "/api/v1/estate/evidence/pqc"


def _cmd_pqc(args: argparse.Namespace, _session: Any = None) -> int:
    # impact asks a different endpoint (the twin's blast-radius walk); dispatching it after
    # the exposure read would make a 404 on /pqc look like a failure of the impact command
    if getattr(args, "pqc_command", None) == "impact":
        return _pqc_impact(args)
    client = _client(args)
    try:
        payload = client.get(PQC)
    except (Refused, ApiError) as exc:
        return _fail("pqc", exc)

    def render() -> None:
        layers = _field(payload, "layers") or _field(payload, "by_layer") or {}
        print(f"run           {_field(payload, 'run_id', default='—')}")
        if isinstance(layers, Mapping) and layers:
            for name, layer in layers.items():
                if isinstance(layer, Mapping):
                    counts = ", ".join(f"{k}={v}" for k, v in sorted(layer.items())
                                       if isinstance(v, (int, float)))
                    print(f"{name:<14} {counts or _short(layer)}")
                else:
                    print(f"{name:<14} {_short(layer)}")
        else:
            print("layers        — (the response carried no per-layer verdict)")
        print("\nthis is per-layer exposure, not a score: layers are never summed, and an "
              "algorithm that was never observed is NOT_OBSERVED, not classical.")

    if args.pqc_command == "blockers":
        blockers = _field(payload, "blockers")
        if not blockers:
            print("pqc blockers: the control plane returned no `blockers` field; "
                  "the per-layer exposure below is what it does report", file=sys.stderr)
            if not args.json:
                render()
                print("\nsource: GET " + PQC)
            return EXIT_INCOMPLETE
        return _emit(args, blockers, source=f"GET {PQC} (field blockers)")
    return _emit(args, payload, source=client.source("GET", PQC), render=render)


SCOPES = ("/api/v1/platform/scope", "/api/v1/onboarding/scope", "/api/v1/scope/envelope")


IMPACT = f"{TWIN}/impact"


def _pqc_impact(args: argparse.Namespace) -> int:
    """Blast radius for one crypto selector, framed as what it is.

    This is the twin's impact walk (`POST /twin/impact`), not a PQC score. It answers "if
    this algorithm moved, what is downstream of it" — which is the question a migration
    plan actually needs — and it reports its own blind spots. It deliberately does not
    convert reachability into a readiness number: the PQC endpoint refuses to sum layers,
    and a CLI that summed them here would undo that.
    """
    selector = {
        "algorithm": args.algorithm,
        "protocol": args.protocol,
        "asset": args.asset,
        "key_size": args.key_size,
        "depth": args.depth,
    }
    if not any(selector[key] for key in ("algorithm", "protocol", "asset", "key_size")):
        return _refuse("pqc impact", Refused(
            "no selector given",
            detail="name what would change: --algorithm, --protocol, --asset or --key-size",
        ))
    client = _client(args)
    try:
        payload = client.post(IMPACT, {k: v for k, v in selector.items() if v is not None})
    except (Refused, ApiError) as exc:
        return _fail("pqc impact", exc)

    def render() -> None:
        print(f"run           {_field(payload, 'run_id', default='—')}")
        print("selector      " + ", ".join(f"{k}={v}" for k, v in selector.items()
                                            if v is not None and k != "depth"))
        for key in ("affected", "assets", "impacted", "reachable", "depth", "truncated"):
            value = _field(payload, key)
            if value is not None:
                count = len(value) if isinstance(value, list) else value
                print(f"{key:<13} {count}")
        for limit in _field(payload, "limits", default=[]) or []:
            print(f"limit         {_short(limit, 100)}")
        print("\nthis is blast radius for a change, not a PQC readiness score: the per-layer "
              "exposure is `cryptoscan pqc status`, and layers are never summed")

    _emit(args, payload, source=client.source("POST", IMPACT), render=render)
    if _field(payload, "truncated"):
        # a truncated walk is a partial answer and must not read as the whole estate
        return EXIT_INCOMPLETE
    return EXIT_OK


def _cmd_scope(args: argparse.Namespace, _session: Any = None) -> int:
    client = _client(args)
    if args.scope_command == "diff":
        return _refuse("scope diff", Refused(
            "no scope-diff endpoint exists",
            detail="authorised scope is compared implicitly by the twin snapshot compare and by "
                   "the collection coverage endpoints; there is no scope-to-scope diff route",
            closest=(f"GET {TWIN}/compare", "GET /api/v1/collection/jobs/{id}/coverage"),
        ))
    try:
        payload = client.get(SCOPES[0])
    except ApiError as exc:
        if exc.status == 404:
            return _refuse("scope show", Refused(
                "this build does not expose /platform/scope",
                closest=tuple(f"GET {path}" for path in SCOPES),
            ))
        return _fail("scope show", exc)
    except Refused as exc:
        return _fail("scope show", exc)

    def render() -> None:
        targets = _field(payload, "targets") or _field(payload, "entries") or []
        print(f"organisation  {_field(payload, 'organisation', default=_field(payload, 'tenant_id', default='—'))}")
        print(f"environment   {_field(payload, 'environment', default='—')}")
        print(f"targets       {len(targets) if isinstance(targets, list) else _short(targets)}")
        print(f"status        {_field(payload, 'status', default=_field(payload, 'state', default='—'))}")

    return _emit(args, payload, source=client.source("GET", SCOPES[0]), render=render)


def _explain_finding(args: argparse.Namespace, client: Client) -> int:
    """Explain a scan finding, and say where the explanation has to stop.

    A finding is a scan record: what was detected, in which file, at which line, with what
    confidence and chain hash. Two things it is **not**:

    * it is not an estate asset. The twin explains assets, and a finding carries a file
      path, not an asset id — joining them by guessing would explain a different object, so
      this command reports ``NOT_JOINABLE`` and names the asset route instead;
    * it is not a verified observation. ``/findings/{id}/verify`` recomputes the record's
      own chain commitment, which proves the row has not been altered — not that the
      detector was right.

    Both halves are read from the platform, and each prints its own source line.
    """
    finding_id = urllib.parse.quote(str(args.identifier))
    finding_path = f"/api/v1/findings/{finding_id}"
    try:
        finding = client.get(finding_path)
    except (Refused, ApiError) as exc:
        return _fail("explain finding", exc)

    verify: Any = None
    verify_error: str | None = None
    try:
        verify = client.get(f"{finding_path}/verify")
    except (Refused, ApiError) as exc:
        verify_error = _reason(exc)

    result = {
        "finding": finding,
        "chain_verification": verify,
        "chain_verification_error": verify_error,
        "estate_join": "NOT_JOINABLE",
        "estate_join_reason": (
            "a finding is a scan record (file path, line, algorithm); the twin explains "
            "assets, and nothing in the finding names the asset id an estate answer would "
            "need — see `cryptoscan explain asset <id> --fact-type crypto:algorithm`"
        ),
        "limits": [
            "this explains the finding record and its chain commitment; it does not explain "
            "why the estate holds the algorithm, because the two are keyed differently",
            "a verified chain commitment proves the stored row was not altered, not that the "
            "detection was correct",
        ],
    }

    def render() -> None:
        print(f"finding       {_field(finding, 'evidence_id', default=args.identifier)}")
        print(f"scan          {_field(finding, 'scan_id', default='—')}")
        print(f"algorithm     {_field(finding, 'algorithm', default='—')}"
              f" {_field(finding, 'key_size', default='')}"
              f" {_field(finding, 'mode', default='')}".rstrip())
        print(f"location      {_field(finding, 'file_path', default='—')}"
              f":{_field(finding, 'line_number', default='—')}")
        print(f"confidence    {_field(finding, 'confidence', default='—')}")
        print(f"compliance    {_field(finding, 'compliance_status', default='—')}")
        print(f"content hash  {_field(finding, 'content_hash', default='—')}")
        print(f"chain hash    {_field(finding, 'chain_hash', default='—')}")
        if verify is not None:
            print(f"chain check   {_field(verify, 'verdict', default=_field(verify, 'status', default='—'))}")
        else:
            print(f"chain check   UNAVAILABLE — {verify_error}")
        print("\nestate join   NOT_JOINABLE")
        print(f"  {result['estate_join_reason']}")
        for limit in result["limits"]:
            print(f"limit: {limit}")

    return _emit(args, result, source=client.source("GET", finding_path), render=render)


def _cmd_explain(args: argparse.Namespace, _session: Any = None) -> int:
    """Why did the platform say that? Every answer names the endpoint that answered."""
    client = _client(args)
    kind = args.subject
    try:
        if kind == "asset":
            payload = client.get(f"/api/v1/estate/evidence/why/{urllib.parse.quote(args.identifier)}",
                                 fact_type=args.fact_type)
            source = client.source("GET", f"/api/v1/estate/evidence/why/{args.identifier}")
        elif kind == "system":
            payload = client.get(f"/api/v1/risk/systems/{urllib.parse.quote(args.identifier)}/explain")
            source = client.source("GET", f"/api/v1/risk/systems/{args.identifier}/explain")
        elif kind == "node":
            payload = client.get("/api/v1/graph/explain", node_id=args.identifier)
            source = client.source("GET", "/api/v1/graph/explain")
        elif kind == "finding":
            return _explain_finding(args, client)
        else:
            return _refuse("explain", Refused(
                f"unknown subject {kind!r}",
                detail="explain answers for an asset, a system, a graph node or a finding",
                closest=(
                    "GET /api/v1/estate/evidence/why/{identifier}?fact_type=...",
                    "GET /api/v1/risk/systems/{system_id}/explain",
                    "GET /api/v1/graph/explain?node_id=...",
                    "GET /api/v1/findings/{evidence_id}",
                ),
            ))
    except (Refused, ApiError) as exc:
        return _fail(f"explain {kind}", exc)

    def render() -> None:
        for label, path in (("subject", ("subject", "asset", "id", "node_id")),
                            ("evidence", ("evidence", "evidence_ids", "citations")),
                            ("reason", ("reason", "explanation", "why")),
                            ("policy", ("policy", "policy_id", "rule")),
                            ("confidence", ("confidence",))):
            value = None
            for key in path:
                value = _field(payload, key)
                if value is not None:
                    break
            print(f"{label:<11} {_short(value)}")

    return _emit(args, payload, source=source, render=render)


# --------------------------------------------------------------------------------------
# commands: reports
# --------------------------------------------------------------------------------------


def _cmd_report(args: argparse.Namespace, _session: Any = None) -> int:
    """Generate a report by streaming it to disk — never by printing bytes into a terminal."""
    client = _client(args)
    fmt = args.format.lower()
    paths = {
        "json": f"/api/v1/scans/{urllib.parse.quote(args.scan)}/report",
        "html": f"/api/v1/scans/{urllib.parse.quote(args.scan)}/report.html",
        "pdf": f"/api/v1/scans/{urllib.parse.quote(args.scan)}/report.pdf",
    }
    if fmt not in paths:
        return _refuse("report", Refused(f"unknown format {args.format!r}", detail="json, html or pdf"))
    path = paths[fmt]
    destination = Path(args.output or f"cryptoscan-report-{args.scan}.{fmt}")
    try:
        response = client.request("GET", path)
    except (Refused, ApiError) as exc:
        return _fail("report", exc)
    destination.write_bytes(response.body)
    digest = _sha256(response.body)
    print(f"wrote {destination} ({len(response.body)} bytes, {fmt})")
    print(f"sha256 {digest}")
    print(f"source: GET {path} (HTTP {response.status})")
    print("note: the report is a rendering of stored evidence; its integrity is the evidence "
          "chain's, and `cryptoscan verify-installation --manifest` does not check report contents")
    return EXIT_OK


def _sha256(data: bytes) -> str:

    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------
# commands: CI gate
# --------------------------------------------------------------------------------------

GATE = "/api/v1/scans/{scan}/gate"
CI_GATE = "/api/v1/ci/gate"
SBOM_SCAN = "/api/v1/devsecops/sbom/scan"


def _ci_scan(args: argparse.Namespace, client: Client) -> int:
    """Scan a source tree, on the control plane, and hand the result to the gate.

    The honest constraint first: ``--path`` is resolved **on the control plane**, not on the
    operator's machine. A CLI cannot ship a checkout to the server in this build, so the
    path must be one the platform can already see — a mounted volume, a build agent's
    workspace. Naming that here costs one line and prevents the most likely
    misunderstanding, which is that this scanned your laptop.
    """
    body = {
        "kind": "source",
        "target": args.path,
        "format": args.format,
        "include_vendored": bool(getattr(args, "include_vendored", False)),
        "use_lockfiles": not bool(getattr(args, "no_lockfiles", False)),
    }
    try:
        payload = client.post(SBOM_SCAN, body)
    except (Refused, ApiError) as exc:
        return _fail("ci scan", exc)

    def render() -> None:
        artifact = _field(payload, "artifact_id") or _field(payload, "id")
        print(f"path          {args.path} (resolved on the control plane)")
        print(f"format        {_field(payload, 'format', default=args.format)}")
        print(f"artifact      {artifact or '— (the response named no artifact)'}")
        summary = _field(payload, "summary") or {}
        if isinstance(summary, Mapping) and summary:
            for key, value in sorted(summary.items()):
                if isinstance(value, (int, float, str)):
                    print(f"  {key:<18} {value}")
        components = _field(payload, "components") or payload.get("packages") or []
        if isinstance(components, list):
            print(f"components    {len(components)}")
        print("\nthis scanned a path the control plane can see, not the directory you are "
              "standing in; the SBOM it produced is the artefact to keep.")

    _emit(args, payload, source=client.source("POST", SBOM_SCAN, 201), render=render)

    if getattr(args, "gate", False):
        print("ci scan: --gate needs a scan id, and an SBOM scan does not produce one here; "
              "run `cryptoscan ci gate --scan <id>` against a stored scan", file=sys.stderr)
        return EXIT_INCOMPLETE
    return EXIT_OK


def _cmd_ci(args: argparse.Namespace, _session: Any = None) -> int:
    """The build gate: PASS / WARN / FAIL from the platform's own decision.

    The decision is never recomputed here. `drift.core.gate` evaluates it against a policy
    profile and records the evaluation server-side; a CLI that re-derived PASS/FAIL from the
    finding list would be a second policy engine that can disagree with the one the bank
    audited.
    """
    client = _client(args)
    action = args.ci_command
    if action == "scan":
        return _ci_scan(args, client)
    if action != "gate":
        return _refuse("ci", Refused(
            f"unknown ci action {action!r}",
            detail="the gate evaluates a completed scan; there is no source-tree scan mode here",
            closest=("cryptoscan bom cbom", "cryptoscan scan --manifest", "GET /api/v1/scans/{id}/gate"),
        ))

    path = GATE.format(scan=urllib.parse.quote(args.scan))
    try:
        if args.record:
            # recording is the audited path: it stores the evaluation and the actor
            payload = client.post(CI_GATE, {
                "scan_id": args.scan,
                "profile": args.profile,
                "require_baseline": bool(args.require_baseline),
            })
            source = client.source("POST", CI_GATE)
        else:
            payload = client.get(path)
            source = client.source("GET", path)
    except (Refused, ApiError) as exc:
        return _fail("ci gate", exc)

    decision = str(_field(payload, "decision") or "UNKNOWN").upper()
    blocking = _field(payload, "blocking", default=[]) or []
    warnings_ = _field(payload, "warnings", default=[]) or []

    def render() -> None:
        print(f"decision      {decision}")
        print(f"profile       {_field(payload, 'profile', default=args.profile or 'standard')}")
        print(f"blocking      {len(blocking)}")
        for item in blocking[:20]:
            print(f"  ✗ {_short(_field(item, 'code'), 28):<28} {_short(_field(item, 'message'), 80)}")
        print(f"warnings      {len(warnings_)}")
        for item in warnings_[:20]:
            print(f"  ⚠ {_short(_field(item, 'code'), 28):<28} {_short(_field(item, 'message'), 80)}")
        if args.record:
            print(f"recorded      {_field(payload, 'recorded', default='—')}")
        print("\nthis decision comes from the platform's policy profile, not from this client")

    _emit(args, payload, source=source, render=render)

    if getattr(args, "sarif", None):
        try:
            sarif = client.get(f"{path}.sarif")
        except (Refused, ApiError) as exc:
            print(f"ci gate: SARIF unavailable — {_reason(exc)}", file=sys.stderr)
            return EXIT_INCOMPLETE
        out = Path(args.sarif)
        out.write_text(json.dumps(sarif, indent=2))
        print(f"wrote {out} (SARIF)")

    fail_on = (args.fail_on or "fail").lower()
    if decision == "PASS":
        return EXIT_OK
    if decision == "WARN":
        return EXIT_OK if fail_on != "warn" else EXIT_INCOMPLETE
    if decision == "FAIL":
        return EXIT_ERROR
    # an unrecognised decision is not a pass
    print(f"ci gate: the platform returned decision {decision!r}, which this client does not "
          f"treat as success", file=sys.stderr)
    return EXIT_INCOMPLETE


# --------------------------------------------------------------------------------------
# commands: air-gap bundles
# --------------------------------------------------------------------------------------

BUNDLE_SCHEMA = "cryptoscan.bundle/1"
BUNDLE_LIMITS = [
    "the bundle carries stored evidence, projections and the twin snapshot — not the "
    "collectors, their raw output, or the database",
    "the manifest hashes prove the files are unmodified relative to the manifest; who "
    "produced them is proven only if the bundle was signed and you check it against a key "
    "you already trust",
    "encryption (if used) is confidentiality only: one shared passphrase, no forward secrecy, "
    "and no protection against someone who has the passphrase",
    "importing a bundle into another installation does not make its evidence yours; the "
    "records keep the estate they were observed under",
]


def _bundle_sources(client: Client) -> dict[str, Any]:
    """Everything a bundle carries, each with the endpoint that answered it."""
    wanted: list[tuple[str, str]] = [
        ("evidence.json", RECORDS + "?limit=1000"),
        ("twin.json", f"{TWIN}/snapshot"),
        ("pqc.json", PQC),
        ("boms.json", BOMS),
    ]
    for kind in BOM_KINDS:
        wanted.append((f"boms/{kind}.json", f"{BOMS}?bom={kind}"))
    documents: dict[str, Any] = {}
    sources: dict[str, str] = {}
    failures: dict[str, str] = {}
    for name, path in wanted:
        try:
            documents[name] = client.get(path)
            sources[name] = client.source("GET", path.split("?")[0], **dict(
                urllib.parse.parse_qsl(path.split("?", 1)[1])) if "?" in path else {})
        except (Refused, ApiError) as exc:
            # A missing projection is recorded as missing. An export that quietly omitted a
            # BOM would produce a bundle a reader could mistake for a complete estate.
            failures[name] = _reason(exc)
    return {"documents": documents, "sources": sources, "failures": failures}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_bundle(
    destination: Path, payload: dict[str, Any], *, signing_key: Any = None
) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}
    for name, document in payload["documents"].items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps(document, indent=2, default=str).encode()
        target.write_bytes(body)
        files[name] = _sha256_bytes(body)
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "created_at": datetime_now(),
        "server": payload.get("server"),
        "files": files,
        "sources": payload["sources"],
        "unavailable": payload["failures"],
        "signature": None,
        "limits": BUNDLE_LIMITS,
    }
    if signing_key is not None:
        # the signature covers every other member, so a rewritten hash list is detectable
        manifest["signature"] = release_signature.sign_document(manifest, signing_key)
    body = json.dumps(manifest, indent=2).encode()
    (destination / "bundle.json").write_bytes(body)
    files["bundle.json"] = _sha256_bytes(body)
    return manifest


def datetime_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _read_passphrase(args: argparse.Namespace) -> str:
    from os import environ

    if getattr(args, "passphrase_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    value = environ.get("CRYPTOSCAN_BUNDLE_PASSPHRASE")
    if not value:
        raise Refused(
            "no bundle passphrase",
            detail="set CRYPTOSCAN_BUNDLE_PASSPHRASE or pass --passphrase-stdin; a bundle "
                   "encrypted with a passphrase on the command line would leak it to ps(1)",
        )
    return value


def _encrypt_bundle(directory: Path, passphrase: str) -> Path:
    """Tar the directory, then AES-256-GCM it under a scrypt-derived key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                archive.add(path, arcname=str(path.relative_to(directory)))
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1).derive(passphrase.encode())
    ciphertext = AESGCM(key).encrypt(nonce, buffer.getvalue(), BUNDLE_SCHEMA.encode())
    header = {
        "schema": "cryptoscan.bundle-envelope/1",
        "kdf": {"name": "scrypt", "n": 2 ** 14, "r": 8, "p": 1, "salt": salt.hex()},
        "cipher": {"name": "AES-256-GCM", "nonce": nonce.hex()},
        "plaintext": "tar.gz of the bundle directory",
    }
    header_bytes = json.dumps(header, sort_keys=True).encode()
    target = directory.with_suffix(".cse")
    target.write_bytes(len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext)
    return target


def _decrypt_bundle(path: Path, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    raw = path.read_bytes()
    length = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4:4 + length])
    body = raw[4 + length:]
    salt = bytes.fromhex(header["kdf"]["salt"])
    nonce = bytes.fromhex(header["cipher"]["nonce"])
    key = Scrypt(
        salt=salt, length=32,
        n=header["kdf"]["n"], r=header["kdf"]["r"], p=header["kdf"]["p"],
    ).derive(passphrase.encode())
    try:
        return AESGCM(key).decrypt(nonce, body, BUNDLE_SCHEMA.encode())
    except Exception as exc:  # noqa: BLE001 — a wrong passphrase and a tampered file look alike
        raise Refused(
            "the bundle could not be decrypted",
            detail="wrong passphrase, or the file was modified after export (AES-GCM cannot "
                   "tell these apart)",
        ) from exc


def _cmd_bundle(args: argparse.Namespace, _session: Any = None) -> int:
    action = args.bundle_command
    if action == "export":
        client = _client(args)
        payload = {**_bundle_sources(client), "server": client.config.server}
        destination = Path(args.out or f"cryptoscan-bundle-{time.strftime('%Y%m%dT%H%M%S')}")
        signing_key = None
        if getattr(args, "sign_key", None):
            try:
                signing_key = release_signature.load_private_key(args.sign_key)
            except Exception as exc:  # noqa: BLE001 — an unreadable key is a refusal
                return _fail("bundle export", Refused(f"cannot read signing key: {exc}"))
        manifest = _write_bundle(destination, payload, signing_key=signing_key)
        written = {
            "bundle": str(destination),
            "files": len(manifest["files"]),
            "unavailable": manifest["unavailable"],
            "encrypted": None,
            "signature": (manifest["signature"] or {}).get("key_id"),
        }
        if args.encrypt:
            encrypted = _encrypt_bundle(destination, _read_passphrase(args))
            written["encrypted"] = str(encrypted)
        if args.json:
            _print_json({**written, "manifest": manifest})
        else:
            print(f"bundle      {destination} ({len(manifest['files'])} files)")
            for name in manifest["unavailable"]:
                print(f"  unavailable {name}: {manifest['unavailable'][name]}")
            if written["encrypted"]:
                print(f"encrypted   {written['encrypted']}")
            print(f"signature   {written['signature'] or 'UNSIGNED'}")
            print("\nsource of each file is recorded in bundle.json under `sources`")
            print("limits (also in bundle.json):")
            for limit in BUNDLE_LIMITS:
                print(f"  - {limit}")
        return EXIT_OK if not manifest["unavailable"] else EXIT_INCOMPLETE

    if action == "verify":
        directory = Path(args.bundle)
        manifest_path = directory / "bundle.json"
        if not manifest_path.exists():
            return _refuse("bundle verify", Refused(
                f"no bundle.json in {directory}",
                detail="a bundle is a directory with a bundle.json manifest; decrypt a .cse "
                       "envelope first with `bundle import`",
            ))
        manifest = json.loads(manifest_path.read_text())
        mismatched, missing = [], []
        for name, expected in sorted((manifest.get("files") or {}).items()):
            candidate = directory / name
            if not candidate.exists():
                missing.append(name)
            elif _sha256_bytes(candidate.read_bytes()) != str(expected):
                mismatched.append(name)
        signature = _check_manifest_signature(manifest, getattr(args, "public_key", None))
        result = {
            "bundle": str(directory),
            "files": len(manifest.get("files") or {}),
            "missing": missing,
            "mismatched": mismatched,
            "signature": signature["status"],
            "signature_detail": signature,
            "unsigned": manifest.get("signature") is None,
            "verdict": "INTACT" if not missing and not mismatched else "MODIFIED",
        }
        if args.json:
            _print_json(result)
        else:
            print(f"bundle      {directory}")
            print(f"files       {result['files']} ({len(missing)} missing, {len(mismatched)} modified)")
            for name in missing:
                print(f"  missing   {name}")
            for name in mismatched:
                print(f"  modified  {name}")
            print(f"signature   {result['signature']}")
            if result["signature_detail"].get("key_id"):
                print(f"  key       {result['signature_detail']['key_id']}")
            print(f"verdict     {result['verdict']}")
            print("\nthe files match the manifest. Who made the bundle is proven only by a "
                  "signature checked against a key you already trust — an embedded public key "
                  "proves nothing on its own.")
        if signature["status"] in {release_signature.INVALID, release_signature.KEY_MISMATCH,
                                   release_signature.MALFORMED}:
            return EXIT_ERROR
        return EXIT_OK if result["verdict"] == "INTACT" else EXIT_INCOMPLETE

    if action == "import":
        source = Path(args.bundle)
        into = Path(args.into or "cryptoscan-bundle")
        if source.suffix == ".cse" or (source.is_file() and source.name.endswith(".cse")):
            plaintext = _decrypt_bundle(source, _read_passphrase(args))
            into.mkdir(parents=True, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
                for member in archive.getmembers():
                    if member.name.startswith("/") or ".." in Path(member.name).parts:
                        raise Refused(
                            f"refusing bundle member {member.name!r}",
                            detail="absolute paths and parent traversal are not accepted from an "
                                   "imported bundle",
                        )
                archive.extractall(into)
            print(f"decrypted into {into}")
        else:
            print("bundle import: the source is not an encrypted envelope; verifying it in place")
            args.bundle = str(source)
            args.json = args.json
            return _cmd_bundle(argparse.Namespace(**{**vars(args), "bundle_command": "verify"}),
                               _session)
        # verify what was just extracted, rather than trusting the archive
        return _cmd_bundle(argparse.Namespace(**{**vars(args), "bundle_command": "verify",
                                                "bundle": str(into)}), _session)

    return _refuse("bundle", Refused(f"unknown bundle action {action!r}"))


# --------------------------------------------------------------------------------------
# commands: installation integrity
# --------------------------------------------------------------------------------------


def _cmd_verify_installation(args: argparse.Namespace, _session: Any = None) -> int:
    """Verify the installed files against a release manifest.

    What this can honestly claim: the files on disk hash to what the manifest says. What it
    cannot: that the manifest is authentic. Signing is a release-process capability, and a
    command that printed "VERIFIED" from an unsigned manifest would be exactly the kind of
    over-claim this product exists to avoid — so a manifest without a signature is reported
    as ``MANIFEST_UNSIGNED`` and the exit code says so.
    """
    manifest_path = Path(args.manifest)
    try:
        manifest = json.loads(manifest_path.read_text())
    except FileNotFoundError:
        return _refuse("verify-installation", Refused(
            f"no manifest at {manifest_path}",
            detail="the release ships a manifest with sha256 per file; without it there is nothing to compare",
        ))
    except ValueError as exc:
        return _fail("verify-installation", Refused(f"manifest is not JSON: {exc}"))

    files = manifest.get("files") if isinstance(manifest, Mapping) else None
    if not isinstance(files, Mapping) or not files:
        return _refuse("verify-installation", Refused(
            "manifest has no `files` map",
            detail="expected {\"files\": {\"api/cli.py\": \"<sha256>\", ...}}",
        ))

    root = Path(args.root or manifest_path.parent)
    mismatched: list[str] = []
    missing: list[str] = []
    for relative, expected in sorted(files.items()):
        candidate = root / relative
        if not candidate.exists():
            missing.append(relative)
            continue
        if _sha256(candidate.read_bytes()) != str(expected):
            mismatched.append(relative)

    # The signature is checked against a key the caller names. Without one the document's own
    # public key is not evidence: whoever edited the manifest could have replaced it.
    signature = _check_manifest_signature(manifest, getattr(args, "public_key", None))

    result = {
        "manifest": str(manifest_path),
        "root": str(root),
        "files": len(files),
        "mismatched": mismatched,
        "missing": missing,
        # the historical name for "no signature at all" is kept: documents and tests use it
        "manifest_signature": ("MANIFEST_UNSIGNED"
                               if signature["status"] == release_signature.UNSIGNED
                               else signature["status"]),
        "signature_detail": signature,
        "verdict": "MATCH" if not mismatched and not missing else "MISMATCH",
    }
    if args.json:
        _print_json(result)
    else:
        print(f"manifest   {manifest_path}")
        print(f"root       {root}")
        print(f"files      {len(files)} ({len(missing)} missing, {len(mismatched)} mismatched)")
        for name in missing:
            print(f"  missing    {name}")
        for name in mismatched:
            print(f"  mismatch   {name}")
        print(f"signature  {result['manifest_signature']}")
        detail = result["signature_detail"]
        if detail.get("key_id"):
            print(f"  key      {detail['key_id']}")
        if detail.get("reason"):
            print(f"  reason   {detail['reason']}")
        print(f"verdict    {result['verdict']}")
        print("\nfile contents are checked against the manifest. The manifest itself is "
              "authentic only if the key you passed with --public-key is the one you meant to "
              "trust — a signature proves who signed these bytes, not who they should be.")
        if result["manifest_signature"] == release_signature.SIGNED_UNVERIFIED:
            print("this manifest is signed, but no --public-key was given, so the signature "
                  "was not checked against anything an attacker could not also have written.")
    # Two questions, two answers. The exit code tracks the one this command is named for —
    # do the files match the manifest — and a bad signature is always a hard failure. An
    # unsigned (or unchecked) manifest is reported in the output and does not pretend the
    # files were not verified, because they were.
    if signature["status"] in {release_signature.INVALID, release_signature.KEY_MISMATCH,
                              release_signature.MALFORMED}:
        return EXIT_ERROR
    if mismatched or missing:
        return EXIT_INCOMPLETE
    return EXIT_OK


def _check_manifest_signature(manifest: Mapping[str, Any], public_key_path: str | None) -> dict[str, Any]:
    """Reuse one verifier for the manifest and the bundle, so they cannot disagree."""
    trusted = None
    if public_key_path:
        try:
            trusted = release_signature.load_public_key(public_key_path)
        except Exception as exc:  # noqa: BLE001 — an unreadable key is a verdict, not a crash
            return {"status": release_signature.MALFORMED,
                    "reason": f"cannot read --public-key: {exc}"}
    return release_signature.verify_document(manifest, trusted_key=trusted)


# --------------------------------------------------------------------------------------
# commands: scan (remote mode)
# --------------------------------------------------------------------------------------


def scan_remote(args: argparse.Namespace, _session: Any = None) -> int:
    """Submit collection work to the control plane instead of running it here.

    The CLI never collects. ``scan`` in remote mode either asks for the **plan** (dry-run),
    submits a **target job** (``--target``), triggers a **system scan** (``--system``), or
    starts an **estate discovery run** — whichever the operator asked for, with the
    endpoint named in the output.
    """
    client = _client(args)
    manifest = _load_manifest(getattr(args, "manifest", None))

    if getattr(args, "dry_run", False):
        try:
            plan = client.get("/api/v1/estate/evidence/plan")
        except (Refused, ApiError) as exc:
            return _fail("scan --dry-run", exc)

        def render_plan() -> None:
            print("DRY RUN — nothing was collected and nothing was written")
            payload = plan if isinstance(plan, Mapping) else {}
            for key in ("planes", "collectors", "targets", "scope", "estate", "coverage"):
                value = payload.get(key)
                if value is None:
                    continue
                if isinstance(value, list):
                    print(f"{key:<12} {len(value)}")
                    for entry in value[:20]:
                        label = entry.get("plane") or entry.get("collector") or entry.get("name") if isinstance(entry, Mapping) else entry
                        status = entry.get("status") or entry.get("state") if isinstance(entry, Mapping) else None
                        print(f"  {label}"
                              + (f"  [{status}]" if status else "")
                              + ("  ← would run" if (isinstance(entry, Mapping) and entry.get("enabled") is False) else ""))
                elif isinstance(value, Mapping):
                    print(f"{key:<12} {len(value)} entries")
                else:
                    print(f"{key:<12} {_short(value)}")
            print("\nthe plan states what the platform is configured to collect; it is not a "
                  "prediction of what a run will observe.")

        return _emit(args, plan, source=client.source("GET", "/api/v1/estate/evidence/plan"), render=render_plan)

    try:
        if getattr(args, "target", None):
            submit = {
                "target_id": args.target,
                "expected_target_revision": args.target_revision,
            }
            if args.target_revision is None:
                return _refuse("scan --target", Refused(
                    "expected target revision is required",
                    detail="the control plane refuses a job whose target changed since the operator "
                           "read it; pass --target-revision (see `cryptoscan target show <id>`)",
                ))
            response = client.post("/api/v1/collection/jobs", submit)
            source = client.source("POST", "/api/v1/collection/jobs", 202)
            submitted = {"target": args.target, "job": response}
        elif getattr(args, "system", None):
            path = f"/api/v1/systems/{urllib.parse.quote(args.system)}/scan"
            response = client.post(path)
            source = client.source("POST", path, 202)
            submitted = {"system": args.system, "scan": response}
        else:
            body, ignored = _scan_body(args, manifest)
            for key in ignored:
                print(f"scan: manifest key {key!r} has no field in the estate scan request and was "
                      f"NOT sent — the run will not honour it", file=sys.stderr)
            response = client.post("/api/v1/estate/evidence/scan", body)
            source = client.source("POST", "/api/v1/estate/evidence/scan", 202)
            submitted = {"estate": body["estate"], "scan": response}
    except (Refused, ApiError) as exc:
        return _fail("scan", exc)

    job_id = (_field(response, "job_id") or _field(response, "id") or _field(response, "scan_id")
              or _field(response, "identifier"))

    def render_submitted() -> None:
        print("submitted — the CLI does not wait for collection unless asked")
        print(f"job           {job_id or '— (the control plane returned no id)'}")
        print(f"status        {_field(response, 'status', default='—')}")
        if job_id:
            print(f"\nwatch it with: cryptoscan jobs watch {job_id}")
        print("collectors run inside the bank; this command only submitted the work")

    if getattr(args, "wait", False) and job_id:
        print(f"submitted job {job_id}; waiting")
        args.job_id = str(job_id)
        return _watch(client, args)
    return _emit(args, submitted, source=source, render=render_submitted)


def _load_manifest(path: str | None) -> dict[str, Any] | None:
    """Read a scan manifest. YAML needs PyYAML; without it the command says so."""
    if not path:
        return None
    candidate = Path(path)
    try:
        text = candidate.read_text()
    except OSError as exc:
        raise Refused(f"cannot read manifest {path}: {exc}") from exc
    if candidate.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # noqa: PLC0415 - optional dependency, only for manifests
        except ImportError as exc:  # pragma: no cover - PyYAML is installed here
            raise Refused(
                "YAML manifests need PyYAML, which is not installed",
                detail="re-write the manifest as JSON, or install pyyaml",
            ) from exc
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise Refused(f"manifest is not JSON: {exc}") from exc
    if not isinstance(data, Mapping):
        raise Refused("manifest must be an object with scope/planes")
    return dict(data)


def _scan_body(args: argparse.Namespace, manifest: Mapping[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """Compose the estate scan request, naming anything the manifest asked for that we drop.

    Dropping silently would be the worst outcome: an operator would believe a policy or a
    collector selection from their manifest applied to the run. Anything the API cannot
    express is returned so the caller can print it.
    """
    planes = list(getattr(args, "planes", None) or [])
    for flag, plane in (("remote_static", "STATIC"), ("remote_runtime", "RUNTIME"),
                        ("remote_network", "NETWORK")):
        if getattr(args, flag, False) and plane not in planes:
            planes.append(plane)
    body: dict[str, Any] = {
        "estate": getattr(args, "estate", "default") or "default",
        "scope": getattr(args, "scope", "production"),
        "planes": planes or None,
        "include_boms": not getattr(args, "no_boms", False),
        "persist": not getattr(args, "no_persist", False),
    }
    ignored: list[str] = []
    if manifest:
        scope_block = manifest.get("scope")
        if isinstance(scope_block, Mapping):
            if scope_block.get("name"):
                body["scope"] = str(scope_block["name"])
            for key in scope_block:
                if key != "name":
                    ignored.append(f"scope.{key}")
        elif isinstance(scope_block, str):
            body["scope"] = scope_block
        collectors = manifest.get("collectors")
        if isinstance(collectors, Mapping):
            chosen = [str(name).upper() for name, enabled in collectors.items() if enabled]
            if chosen:
                body["planes"] = chosen if not body.get("planes") else sorted(set(body["planes"]) & set(chosen))
        for key in manifest:
            if key not in {"scope", "collectors"}:
                ignored.append(str(key))
    return body, ignored


def collect_remote(args: argparse.Namespace, _session: Any = None) -> int:
    """``collect --submit``: hand collection to the control plane, collect nothing here.

    The in-process ``collect`` negotiates TLS from the operator's terminal. This mode does
    not: it submits, prints the id, and — with ``--wait`` — follows the job and its real
    per-surface coverage. The plane list is *requested*, and the response is what decides
    what actually ran.
    """
    client = _client(args)
    try:
        if getattr(args, "target", None):
            if args.target_revision is None:
                return _refuse("collect --submit --target", Refused(
                    "expected target revision is required",
                    detail="pass --target-revision (see `cryptoscan target show <id>`)",
                ))
            payload = client.post("/api/v1/collection/jobs", {
                "target_id": args.target,
                "expected_target_revision": args.target_revision,
            })
            source = client.source("POST", "/api/v1/collection/jobs", 202)
        elif getattr(args, "system", None):
            path = f"/api/v1/systems/{urllib.parse.quote(args.system)}/scan"
            payload = client.post(path)
            source = client.source("POST", path, 202)
        else:
            body = {
                "estate": getattr(args, "estate", "default") or "default",
                "scope": getattr(args, "scope", "production"),
                "include_boms": True,
                "persist": True,
            }
            payload = client.post("/api/v1/estate/evidence/scan", body)
            source = client.source("POST", "/api/v1/estate/evidence/scan", 202)
    except (Refused, ApiError) as exc:
        return _fail("collect --submit", exc)

    job_id = (_field(payload, "job_id") or _field(payload, "id")
              or _field(payload, "scan_id") or _field(payload, "identifier"))
    print("submitted — no collection happened in this process")
    print(f"job           {job_id or '— (the control plane returned no id)'}")
    print(f"status        {_field(payload, 'status', default='—')}")
    if job_id:
        print(f"\nwatch: cryptoscan jobs watch {job_id} --coverage")
    print(f"source: {source}")
    if getattr(args, "wait", False) and job_id:
        args.job_id = str(job_id)
        args.coverage = True
        args.interval = getattr(args, "interval", 5.0)
        args.timeout = getattr(args, "timeout", 1800.0)
        return _watch(client, args)
    return EXIT_OK


# --------------------------------------------------------------------------------------
# parser registration
# --------------------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser, *, credential_flags: bool = True) -> None:
    parser.add_argument("--server", default=None, help="control-plane base URL (default: stored config)")
    parser.add_argument("--json", action="store_true", help="emit the raw response document")
    parser.add_argument("--quiet", action="store_true", help="suppress the source footer")
    if credential_flags:
        parser.add_argument("--token", default=None, help="session token (default: stored, or CRYPTOSCAN_TOKEN)")
        parser.add_argument("--api-key", dest="api_key", default=None,
                            help="machine credential sent as x-api-key (default: CRYPTOSCAN_API_KEY)")
        parser.add_argument("--ca", default=None, help="CA bundle for the control plane's TLS certificate")
        parser.add_argument("--client-cert", dest="client_cert", default=None, help="mTLS client certificate")
        parser.add_argument("--client-key", dest="client_key", default=None, help="mTLS client key")
        parser.add_argument("--insecure", action="store_true",
                            help="skip TLS verification — for a lab only; the command says so in its output")


def register_remote_commands(sub: argparse._SubParsersAction, twin_sub: argparse._SubParsersAction) -> None:
    """Attach the control-plane commands to the existing ``cryptoscan`` parser."""
    version = sub.add_parser("version", help="CLI and control-plane version")
    _add_common(version, credential_flags=False)

    status = sub.add_parser("status", help="is the control plane reachable, ready and who am I")
    _add_common(status)

    doctor = sub.add_parser("doctor", help="check this installation, the control plane and its dependencies")
    _add_common(doctor)

    login = sub.add_parser("login", help="obtain a short-lived session from the control plane")
    login.add_argument("--server", default=None)
    login.add_argument("--username", required=True)
    login.add_argument("--password", default=None, help="prefer --password-stdin or CRYPTOSCAN_PASSWORD")
    login.add_argument("--password-stdin", dest="password_stdin", action="store_true")
    login.add_argument("--mfa-code", dest="mfa_code", default=None, help="second factor when the account requires it")
    login.add_argument("--json", action="store_true")

    logout = sub.add_parser("logout", help="revoke the session and remove the stored token")
    _add_common(logout)

    target = sub.add_parser("target", help="register and authorise collection targets")
    target_sub = target.add_subparsers(dest="target_command", required=True)
    target_list = target_sub.add_parser("list", help="targets registered in this estate")
    _add_common(target_list)
    target_show = target_sub.add_parser("show", help="one target, exactly as the control plane holds it")
    target_show.add_argument("identifier")
    _add_common(target_show)
    target_update = target_sub.add_parser("update", help="revise a registered target")
    target_update.add_argument("identifier")
    target_update.add_argument("--address", default=None)
    target_update.add_argument("--owner", default=None)
    target_update.add_argument("--environment", default=None)
    target_update.add_argument("--collection-method", dest="collection_method", default=None)
    target_update.add_argument("--allowed-operation", dest="allowed_operations", action="append",
                               default=[], help="repeatable; replaces the allowlist when given")
    target_update.add_argument("--not-before", dest="not_before", default=None)
    _add_common(target_update)

    target_register = target_sub.add_parser("register", help="register a target (no defaults are invented)")
    for flag, help_text in (
        ("--target-key", "stable key for this target"),
        ("--system-id", "system the target belongs to"),
        ("--owner", "accountable owner"),
        ("--environment", "production | staging | ..."),
        ("--collection-method", "how collectors reach it (agent, ssh-readonly, api, ...)"),
        ("--address", "host or endpoint"),
        ("--not-before", "authorisation start (ISO-8601)"),
    ):
        # Deliberately not argparse-required: the refusal below explains *why* there is no
        # default for these, and an argparse usage line does not.
        target_register.add_argument(flag, dest=flag[2:].replace("-", "_"), default=None, help=help_text)
    target_register.add_argument("--allowed-operation", dest="allowed_operations", action="append",
                                 default=[], help="repeatable, explicit operation allowlist")
    target_register.add_argument("--credential-ref", dest="credential_ref", default=None,
                                 help="vault:// reference; never a secret")
    target_register.add_argument("--read-only", action="store_true", default=True)
    target_register.add_argument("--exclusion", action="append", default=[], help="repeatable exclusion")
    _add_common(target_register)
    for action, help_text in (("authorize", "authorise a registered target"),
                              ("revoke", "revoke a target's authorisation")):
        node = target_sub.add_parser(action, help=help_text)
        node.add_argument("identifier")
        node.add_argument("--reason", default=None)
        _add_common(node)

    jobs = sub.add_parser("jobs", help="submit-watch-cancel: the job queue")
    jobs_sub = jobs.add_subparsers(dest="jobs_command", required=True)
    jobs_list = jobs_sub.add_parser("list", help="recent jobs")
    jobs_list.add_argument("--limit", type=int, default=25)
    _add_common(jobs_list)
    jobs_show = jobs_sub.add_parser("show", help="one job")
    jobs_show.add_argument("job_id")
    _add_common(jobs_show)
    jobs_logs = jobs_sub.add_parser("logs", help="a job's logs")
    jobs_logs.add_argument("job_id")
    _add_common(jobs_logs)
    jobs_cancel = jobs_sub.add_parser("cancel", help="cancel a collection job")
    jobs_cancel.add_argument("job_id")
    _add_common(jobs_cancel)
    jobs_retry = jobs_sub.add_parser("retry", help="re-run a failed job through its own route")
    jobs_retry.add_argument("job_id")
    _add_common(jobs_retry)
    for name, help_text in (
        ("evidence", "evidence records a collection job stored"),
        ("errors", "collector errors recorded for a collection job"),
        ("projections", "BOM projections produced by a collection job"),
    ):
        parser = jobs_sub.add_parser(name, help=help_text)
        parser.add_argument("job_id")
        _add_common(parser)
    jobs_watch = jobs_sub.add_parser("watch", help="follow a job until it reaches a terminal state")
    jobs_watch.add_argument("job_id")
    jobs_watch.add_argument("--coverage", action="store_true",
                            help="also print per-surface collection coverage when the job settles")
    jobs_watch.add_argument("--timeout", type=float, default=1800.0)
    jobs_watch.add_argument("--interval", type=float, default=5.0)
    _add_common(jobs_watch)

    collector = sub.add_parser("collector", help="what this build can actually collect")
    collector_sub = collector.add_subparsers(dest="collector_command", required=True)
    collector_list = collector_sub.add_parser("list", help="the collector catalog served with the build")
    _add_common(collector_list)
    collector_show = collector_sub.add_parser("show", help="one catalog entry, with its capability limits")
    collector_show.add_argument("collector_id")
    _add_common(collector_show)

    evidence = sub.add_parser("evidence", help="read collected evidence")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_list = evidence_sub.add_parser("list", help="evidence records in this estate")
    evidence_list.add_argument("--target", default=None)
    evidence_list.add_argument("--evidence-type", dest="evidence_type", default=None)
    evidence_list.add_argument("--limit", type=int, default=50)
    _add_common(evidence_list)
    evidence_show = evidence_sub.add_parser("show", help="one stored evidence record, with its provenance")
    evidence_show.add_argument("evidence_id")
    _add_common(evidence_show)
    evidence_verify = evidence_sub.add_parser(
        "verify", help="recompute a record's content address and check it against its id")
    evidence_verify.add_argument("evidence_id")
    _add_common(evidence_verify)

    bom = sub.add_parser("bom", help="print one BOM projection (sbom|cbom|hbom|nbom|vbom|techbom)")
    bom.add_argument("kind", help="SBOM, CBOM, HBOM, NBOM, VBOM or TECHBOM")
    _add_common(bom)

    pqc = sub.add_parser("pqc", help="post-quantum exposure, per layer")
    pqc_sub = pqc.add_subparsers(dest="pqc_command", required=True)
    for action, help_text in (("status", "per-layer PQC exposure"),
                              ("blockers", "the blockers field, if the platform reports one")):
        node = pqc_sub.add_parser(action, help=help_text)
        _add_common(node)
    pqc_impact = pqc_sub.add_parser(
        "impact", help="blast radius for one algorithm/protocol/asset (not a PQC score)")
    pqc_impact.add_argument("--algorithm", default=None)
    pqc_impact.add_argument("--protocol", default=None)
    pqc_impact.add_argument("--asset", default=None)
    pqc_impact.add_argument("--key-size", dest="key_size", default=None)
    pqc_impact.add_argument("--depth", type=int, default=3)
    _add_common(pqc_impact)

    scope = sub.add_parser("scope", help="the authorised scope this installation may touch")
    scope_sub = scope.add_subparsers(dest="scope_command", required=True)
    scope_show = scope_sub.add_parser("show", help="authorised scope")
    _add_common(scope_show)
    scope_diff = scope_sub.add_parser("diff", help="diff two scopes (refuses: no such route)")
    scope_diff.add_argument("--from", dest="before", default=None)
    scope_diff.add_argument("--to", dest="after", default=None)
    _add_common(scope_diff)

    explain = sub.add_parser("explain", help="why the platform said that — asset, system or graph node")
    explain_sub = explain.add_subparsers(dest="subject", required=True)
    explain_asset = explain_sub.add_parser("asset", help="evidence behind one asset's facts")
    explain_asset.add_argument("identifier")
    explain_asset.add_argument("--fact-type", dest="fact_type", default="CRYPTO_ALGORITHM")
    _add_common(explain_asset)
    explain_system = explain_sub.add_parser("system", help="unified risk explanation for a system")
    explain_system.add_argument("identifier")
    _add_common(explain_system)
    explain_node = explain_sub.add_parser("node", help="graph explanation for a node")
    explain_node.add_argument("identifier")
    _add_common(explain_node)
    explain_finding = explain_sub.add_parser(
        "finding", help="the finding record, its chain check, and where the explanation stops")
    explain_finding.add_argument("identifier")
    _add_common(explain_finding)

    report = sub.add_parser("report", help="generate a report for a completed scan")
    report_sub = report.add_subparsers(dest="report_command", required=True)
    generate = report_sub.add_parser("generate", help="write a report file")
    generate.add_argument("--scan", required=True)
    generate.add_argument("--format", default="json", choices=["json", "html", "pdf"])
    generate.add_argument("--output", "-o", default=None)
    _add_common(generate)

    ci = sub.add_parser("ci", help="build gate: PASS / WARN / FAIL for a completed scan")
    ci_sub = ci.add_subparsers(dest="ci_command", required=True)
    ci_scan = ci_sub.add_parser("scan", help="scan a source tree the control plane can see")
    ci_scan.add_argument("--path", required=True,
                         help="source tree path, resolved on the control plane (not this host)")
    ci_scan.add_argument("--format", default="cyclonedx", choices=["cyclonedx", "spdx"])
    ci_scan.add_argument("--include-vendored", dest="include_vendored", action="store_true")
    ci_scan.add_argument("--no-lockfiles", dest="no_lockfiles", action="store_true",
                         help="ignore resolved lockfiles; manifests only")
    ci_scan.add_argument("--gate", action="store_true",
                         help="also try to evaluate the policy gate (needs a scan id)")
    _add_common(ci_scan)

    ci_gate = ci_sub.add_parser("gate", help="evaluate (and optionally record) the policy gate")
    ci_gate.add_argument("--scan", required=True)
    ci_gate.add_argument("--profile", default=None, help="standard | strict | lenient")
    ci_gate.add_argument("--record", action="store_true",
                         help="record the evaluation server-side (audited, with the actor)")
    ci_gate.add_argument("--require-baseline", dest="require_baseline", action="store_true")
    ci_gate.add_argument("--fail-on", dest="fail_on", default="fail", choices=["fail", "warn"],
                         help="exit non-zero on FAIL (default) or also on WARN")
    ci_gate.add_argument("--sarif", default=None, help="also write the SARIF report to this path")
    _add_common(ci_gate)

    bundle = sub.add_parser("bundle", help="air-gap bundles: export, verify, import")
    bundle_sub = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_export = bundle_sub.add_parser("export", help="write a bundle directory from this estate")
    bundle_export.add_argument("--out", default=None, help="destination directory")
    bundle_export.add_argument("--encrypt", action="store_true",
                               help="also write an AES-256-GCM envelope (.cse) beside it")
    bundle_export.add_argument("--passphrase-stdin", dest="passphrase_stdin", action="store_true")
    bundle_export.add_argument("--sign-key", dest="sign_key", default=None,
                               help="Ed25519 private key (PEM) to sign the bundle manifest")
    _add_common(bundle_export)
    bundle_verify = bundle_sub.add_parser("verify", help="recompute a bundle's manifest hashes")
    bundle_verify.add_argument("bundle", help="bundle directory")
    bundle_verify.add_argument("--public-key", dest="public_key", default=None,
                               help="Ed25519 public key to check the bundle signature with")
    _add_common(bundle_verify, credential_flags=False)
    bundle_import = bundle_sub.add_parser("import", help="decrypt and extract a bundle envelope")
    bundle_import.add_argument("bundle", help="path to a .cse envelope (or a bundle directory)")
    bundle_import.add_argument("--into", default=None, help="destination directory")
    bundle_import.add_argument("--passphrase-stdin", dest="passphrase_stdin", action="store_true")
    bundle_import.add_argument("--public-key", dest="public_key", default=None,
                               help="Ed25519 public key to check the bundle signature with")
    _add_common(bundle_import, credential_flags=False)

    verify = sub.add_parser("verify-installation", help="hash installed files against a release manifest")
    verify.add_argument("--manifest", required=True, help="path to the release manifest (JSON)")
    verify.add_argument("--root", default=None, help="directory the manifest paths are relative to")
    verify.add_argument("--public-key", dest="public_key", default=None,
                        help="Ed25519 public key (PEM or base64 .pub) to check the signature with")
    _add_common(verify, credential_flags=False)

    twin_status = twin_sub.add_parser("status", help="the twin as the control plane serves it")
    _add_common(twin_status)
    twin_snapshot = twin_sub.add_parser("snapshot", help="current twin snapshot")
    twin_snapshot.add_argument("--include-payload", action="store_true", dest="include_payload")
    _add_common(twin_snapshot)
    twin_remediation = twin_sub.add_parser("remediation", help="work the twin has opened")
    _add_common(twin_remediation)
    twin_remediate = twin_sub.add_parser("remediate", help="propose work from what the twin holds")
    twin_remediate.add_argument("--persist", action="store_true",
                                help="open the work instead of only proposing it")
    _add_common(twin_remediate)
    twin_reconcile = twin_sub.add_parser("reconcile", help="close what an observation proved")
    _add_common(twin_reconcile)
    twin_diff = twin_sub.add_parser("diff", help="compare two twin snapshots")
    twin_diff.add_argument("--from", dest="before", default=None)
    twin_diff.add_argument("--to", dest="after", default=None)
    _add_common(twin_diff)


def _guarded(command: str, handler: Callable[[argparse.Namespace, Any], int]
             ) -> Callable[[argparse.Namespace, Any], int]:
    """Turn a refusal or an API failure into an exit code, never a traceback.

    Every remote command starts by building a client, and building a client can refuse
    (no server, no credential, half an mTLS pair). Without this wrapper that refusal
    escaped as a generic exception and exited 1 — indistinguishable from a crash, which is
    exactly the wrong signal for "you have not configured this yet".
    """

    def wrapper(args: argparse.Namespace, session: Any = None) -> int:
        try:
            return handler(args, session)
        except Refused as exc:
            return _refuse(command, exc)
        except ApiError as exc:
            return _fail(command, exc)

    wrapper.__name__ = getattr(handler, "__name__", command)
    return wrapper


#: Handlers keyed by the top-level command name; ``cli.COMMANDS`` merges this in.
COMMANDS: dict[str, Callable[[argparse.Namespace, Any], int]] = {
    name: _guarded(name, handler)
    for name, handler in (
        ("version", _cmd_version),
        ("status", _cmd_status),
        ("doctor", _cmd_doctor),
        ("login", _cmd_login),
        ("logout", _cmd_logout),
        ("target", _cmd_target),
        ("jobs", _cmd_jobs),
        ("collector", _cmd_collector),
        ("evidence", _cmd_evidence),
        ("bom", _cmd_bom),
        ("pqc", _cmd_pqc),
        ("scope", _cmd_scope),
        ("explain", _cmd_explain),
        ("report", _cmd_report),
        ("ci", _cmd_ci),
        ("bundle", _cmd_bundle),
        ("verify-installation", _cmd_verify_installation),
    )
}


def _fail(command: str, exc: Exception) -> int:
    if isinstance(exc, Refused):
        return _refuse(command, exc)
    if isinstance(exc, ApiError):
        detail = exc.detail()
        print(f"{command}: FAILED — {exc}", file=sys.stderr)
        if detail:
            print(f"  {detail}", file=sys.stderr)
        if exc.hint:
            print(f"  hint: {exc.hint}", file=sys.stderr)
        return EXIT_ERROR if exc.status < 500 else EXIT_INCOMPLETE
    print(f"{command}: FAILED — {type(exc).__name__}: {exc}", file=sys.stderr)
    return EXIT_ERROR
