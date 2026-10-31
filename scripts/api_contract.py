"""Extract the API paths this repository calls, and match them to what it serves.

A page existing does not prove its backend path works. Neither does a CLI flag,
or a drill script that has been in the tree since before the route was renamed.
Those are the failures this module exists to make visible, because they are
silent by construction: a caller that asks for a path nobody registered gets a
404 at the worst possible moment — during a burn-in, a drill, or a bank's
evaluation — and nothing in CI notices.

The contract is read from the application's own OpenAPI schema (the same one
served at ``GET /api/openapi.json``), so there is no second list to maintain.
Callers are found in three places:

* ``frontend/src/**/*.ts(x)`` — absolute ``/api/...`` literals, template
  literals, and ``const BASE = "/api/v1/x"`` prefixes;
* ``scripts/**/*.py`` — string literals and f-strings that contain ``/api/v1/``;
* ``integrations/**`` and the shell scripts, for the same reason.

A caller is *known* when its path matches a served path, with a ``{param}``
matching any single path segment (one segment only: ``/a/{x}`` must not match
``/a/b/c``). Anything else is reported.
"""

from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Paths that exist on the app but not in the OpenAPI schema, or that are not
#: part of this API at all. Each entry needs a reason, because the whole point of
#: the exercise is that "it is probably fine" is how a broken path survives.
ALLOWED = {
    "/api/docs": "FastAPI's own Swagger UI, mounted at /api/docs (not in the schema)",
    "/api/openapi.json": "the schema document itself",
    "/api/redoc": "FastAPI's ReDoc UI",
}


@dataclass(frozen=True)
class Call:
    path: str
    source: str
    line: int

    def where(self) -> str:
        return f"{self.source}:{self.line}"


_SPEC: dict | None = None
_APP = None


def application():
    """The application object, built once per process.

    Building a second app in the same process is not guaranteed to produce the
    same tree (routers register modules at import time), so the schema and the
    route objects — including the role each route requires — must come from one
    instance.
    """
    global _APP
    if _APP is None:
        import sys

        for extra in ("shared/shared_models", "services/api"):
            candidate = str(ROOT / extra)
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
        from api.main import create_app  # noqa: PLC0415

        _APP = create_app()
    return _APP


def openapi_spec() -> dict:
    """The application schema, built once per process.

    Building a second app in the same process is not guaranteed to produce the
    same tree (routers register modules at import time), so everything reads the
    one document: the routes, the verbs and the response models.
    """
    global _SPEC
    if _SPEC is None:
        _SPEC = application().openapi()
    return _SPEC


def _schema_operations() -> dict[str, set[str]]:
    """Served path -> the verbs it accepts, from the live application."""
    import sys

    for extra in ("shared/shared_models", "services/api"):
        candidate = str(ROOT / extra)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)

    operations: dict[str, set[str]] = {}
    for path, item in openapi_spec()["paths"].items():
        verbs = {method.upper() for method in item if method.lower() in
                 {"get", "post", "put", "patch", "delete", "head", "options"}}
        operations[path] = verbs
    return operations


_OPERATIONS: dict[str, set[str]] | None = None


def served_operations() -> dict[str, set[str]]:
    global _OPERATIONS
    if _OPERATIONS is None:
        _OPERATIONS = _schema_operations()
    return _OPERATIONS


def _schema_paths() -> list[str]:
    return sorted(served_operations())


_PATH_CACHE: list[str] | None = None
_MATCHERS: list[re.Pattern[str]] | None = None


def served_paths() -> list[str]:
    global _PATH_CACHE
    if _PATH_CACHE is None:
        _PATH_CACHE = _schema_paths()
    return _PATH_CACHE


def _matcher(path: str) -> re.Pattern[str]:
    segments = []
    for segment in path.split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            segments.append("[^/]+")
        else:
            segments.append(re.escape(segment))
    return re.compile("^" + "/".join(segments) + "$")


def matchers() -> list[re.Pattern[str]]:
    global _MATCHERS
    if _MATCHERS is None:
        _MATCHERS = [_matcher(path) for path in served_paths()]
    return _MATCHERS


#: Call sites whose last segment is chosen at runtime from a closed set the
#: extractor cannot see. Listed rather than matched, so the reader knows exactly
#: which suffix each one is allowed to pick.
ALLOWED_DYNAMIC = {
    "/api/v1/exceptions/{param}/{param}": (
        "frontend/src/lib/api.ts sends approve | reject | revoke as the last segment "
        "(apiExceptionDecision); all three are registered under /exceptions/{id}/"
    ),
    "/api/v1/drift/{param}/{param}": (
        "frontend/src/pages/Drift.tsx sends the action name as the last segment; "
        "the set is {acknowledge, resolve, false-positive, remediation-tasks}"
    ),
}

#: Strings that look like API paths but are filesystem paths, module names or
#: prose. Excluding them here is better than an allowlist that grows forever.
_NOT_A_PATH = re.compile(r"\.(py|ts|tsx|js|jsx|java|md|json|ya?ml|sh|go|rs)$")
_NON_HTTP_ROOTS = {"api", "src", "tests", "Dockerfile", "..."}


def _looks_like_http(path: str) -> bool:
    # Every served path lives under /api/v1/. Other /api/... strings in this tree
    # are filesystem paths ("/api/api/routers"), GitLab's own API ("/api/v4") or
    # FastAPI's documentation mounts, which are in ALLOWED above.
    if not path.startswith("/api/v1/"):
        return False
    for segment in path.split("/")[2:]:
        if not segment:
            continue
        if _NOT_A_PATH.search(segment):
            return False
        if segment in _NON_HTTP_ROOTS:
            return False
    return True


def is_served(path: str) -> bool:
    if path in ALLOWED or path in ALLOWED_DYNAMIC:
        return True
    if not _looks_like_http(path):
        return True
    return any(match.match(path) for match in matchers())


def is_prefix_only(path: str) -> bool:
    """True when the literal is a prefix of a served path (a base, not a call).

    ``const BASE = "/api/v1/resource-monitoring"`` is not a request; the request
    is ``BASE + "/plans"``. Treating prefixes as satisfied keeps the check on the
    composed paths, which is where a typo actually lands.
    """
    if any(match.match(path) for match in matchers()):
        return False
    return any(served.startswith(path.rstrip("/") + "/") for served in served_paths())


def normalise(raw: str) -> str:
    """Strip a query string, collapse interpolations, drop a trailing wildcard."""
    out: list[str] = []
    index = 0
    while index < len(raw):
        if raw.startswith("${", index):
            depth, cursor = 1, index + 2
            while cursor < len(raw) and depth:
                if raw[cursor] == "{":
                    depth += 1
                elif raw[cursor] == "}":
                    depth -= 1
                cursor += 1
            body = raw[index + 2 : cursor - 1]
            # `${qs ? "?limit=50" : ""}` is a query string, not a path segment:
            # counting it as one turned "/api/v1/findings" into "findings{param}".
            if "?" not in body:
                out.append("{param}")
            index = cursor
        elif raw[index] == "{":
            depth, cursor = 1, index + 1
            while cursor < len(raw) and depth:
                if raw[cursor] == "{":
                    depth += 1
                elif raw[cursor] == "}":
                    depth -= 1
                cursor += 1
            out.append("{param}")
            index = cursor
        else:
            out.append(raw[index])
            index += 1
    path = "".join(out).split("?")[0].split("#")[0].strip().rstrip(".,;:")
    if path.endswith("*"):
        path = path[:-1]
    return path.rstrip("/") or "/"


def candidates(path: str) -> list[str]:
    """The path as written, plus the same path without a trailing interpolation.

    ``/api/v1/marketplace/plugins${q}`` normalises to ``plugins{param}`` because
    the extractor cannot see that ``q`` is a query string; the truncated variant
    is the real path. Routes whose last segment is genuinely chosen at runtime
    are listed in ``ALLOWED_DYNAMIC`` instead, so this fallback cannot be used to
    excuse one of those.
    """
    out = [path]
    if path.endswith("{param}"):
        out.append(path[: -len("{param}")].rstrip("/") or "/")
    return out


def _python_calls(path: Path) -> list[Call]:
    source = path.read_text(encoding="utf-8", errors="replace")
    calls: list[Call] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError):
        return calls
    for token in tokens:
        if token.type != tokenize.STRING:
            continue
        raw = token.string
        prefix = raw[:2].lower()
        body = raw[2:] if prefix in {"f\"", "f'", "rf", "fr"} or raw[0] in "fF" else raw
        if "/api/" not in body:
            continue
        if raw[0] in "fF" or raw[:2].lower() in {"rf", "fr"}:
            text = body
        else:
            try:
                text = ast.literal_eval(raw)
            except (ValueError, SyntaxError):
                text = body
        for match in re.finditer(r"/api/[A-Za-z0-9_\-/{}$.:<>]*", text):
            literal = match.group(0)
            if literal.count("{") and "}" not in literal and "$" not in literal:
                continue
            calls.append(Call(normalise(literal), _rel(path), token.start[0]))
    return calls


def _ts_calls(path: Path) -> list[Call]:
    source = path.read_text(encoding="utf-8", errors="replace")
    calls: list[Call] = []
    # `const BASE = "/api/v1/resource-monitoring"` and friends.
    bases = {
        name: value
        for name, value in re.findall(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[\"'`](/api/[^\"'`]*)[\"'`]", source
        )
    }

    def resolve(text: str) -> str:
        for name, value in bases.items():
            text = text.replace("${" + name + "}", value)
        return text

    pattern = re.compile(r"[\"'`](/api/[^\"'`\n]*)[\"'`]")
    for match in pattern.finditer(resolve(source)):
        literal = match.group(1)
        line = source[: match.start()].count("\n") + 1
        calls.append(Call(normalise(literal), _rel(path), line))
    # `${BASE}/plans` never appears as a standalone literal: the base is inline.
    for name, value in bases.items():
        for match in re.finditer(r"`\$\{" + re.escape(name) + r"\}([^`]*)`", source):
            literal = value + match.group(1)
            line = source[: match.start()].count("\n") + 1
            calls.append(Call(normalise(literal), _rel(path), line))
    return calls


def _rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


#: The frontend's request helpers, and the verb each one sends. A helper name is
#: the most reliable statement of intent in `api.ts`; `call`/`tenantFetch` carry
#: the verb in their options object and are read from there.
_HELPER_VERB = {
    "_rsGet": "GET",
    "_rsPost": "POST",
    "_rsPut": "PUT",
    "_ds": "POST",
    "_ca": "POST",
    "_postAction": "POST",
    "_simPost": "POST",
    "_simPreview": "POST",
}

_HELPER_CALL = re.compile(
    r"\b(_rsGet|_rsPost|_rsPut|_ds|_ca|_postAction|_simPost|_simPreview|call|tenantFetch)"
    r"(?:<[^<>()]*>)?\("
)


def _closing_paren(source: str, open_at: int) -> int:
    """Index just past the parenthesis matching the one at ``open_at``."""
    depth = 0
    index = open_at
    quote: str | None = None
    while index < len(source):
        char = source[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(source)


@dataclass(frozen=True)
class VerbCall:
    method: str
    path: str
    source: str
    line: int

    def where(self) -> str:
        return f"{self.source}:{self.line}"


def frontend_verb_calls() -> list[VerbCall]:
    """(verb, path) pairs for the calls whose verb the source makes explicit.

    Only the arguments of the one call are read, so a ``method: "POST"`` in the
    next statement cannot lend its verb to this path.
    """
    calls: list[VerbCall] = []
    for path in sorted((ROOT / "frontend" / "src").rglob("*.ts*")):
        text_path = str(path)
        if ".test." in text_path or ".spec." in text_path:
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        for match in _HELPER_CALL.finditer(source):
            helper = match.group(1)
            end = _closing_paren(source, match.end() - 1)
            arguments = source[match.end(): end]
            literal = re.search(r"[\"'`](/api/v1/[^\"'`]+)[\"'`]", arguments)
            if literal is None:
                continue
            verb = _HELPER_VERB.get(helper)
            if verb is None:
                found = re.search(r"method:\s*[\"']([A-Za-z]+)[\"']", arguments)
                verb = found.group(1).upper() if found else "GET"
            calls.append(
                VerbCall(
                    method=verb,
                    path=normalise(literal.group(1)),
                    source=_rel(path),
                    line=source[: match.start()].count("\n") + 1,
                )
            )
    return calls


def wrong_verbs() -> list[dict]:
    """Calls whose path is served but whose verb the route does not accept."""
    operations = served_operations()
    by_pattern = sorted(
        ((_matcher(served), served) for served in operations),
        key=lambda pair: pair[1].count("{"),  # concrete routes win over {param} ones
    )
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for call in frontend_verb_calls():
        path = call.path
        if path in ALLOWED or path in ALLOWED_DYNAMIC:
            continue
        for candidate in candidates(path):
            # An exact path always beats a parameterised one: "compliance-map" is
            # not "the sector_id is 'compliance-map'".
            served = candidate if candidate in operations else next(
                (served for matcher, served in by_pattern if matcher.match(candidate)), None
            )
            if served is None:
                continue
            if call.method in operations[served]:
                break
            key = (call.method, served)
            if key in seen:
                break
            seen.add(key)
            out.append(
                {
                    "method": call.method,
                    "path": served,
                    "accepts": sorted(operations[served]),
                    "at": call.where(),
                }
            )
            break
    return out


def frontend_calls() -> list[Call]:
    calls: list[Call] = []
    for path in sorted((ROOT / "frontend" / "src").rglob("*.ts*")):
        text = str(path)
        if ".test." in text or ".spec." in text or ".stories." in text:
            continue
        calls.extend(_ts_calls(path))
    return calls


#: The two shipped command-line entry points. They were outside every caller scan
#: until now: `scripts/` and `integrations/` were walked, and the CLIs that an
#: operator actually runs were not. ``cli.py`` is the in-process operator path and
#: builds no URLs; ``cli_remote.py`` is the bank-facing HTTP client and is exactly
#: the kind of caller this scan exists for.
CLI_SOURCES: tuple[str, ...] = (
    "services/api/api/cli_remote.py",
    "services/api/api/cli.py",
)


def script_calls() -> list[Call]:
    calls: list[Call] = []
    for name in CLI_SOURCES:
        path = ROOT / name
        if path.exists():
            calls.extend(_python_calls(path))
    for directory in ("scripts", "integrations"):
        base = ROOT / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if "tests" in path.parts or "__pycache__" in path.parts:
                continue
            if path.name == "api_contract.py":
                # this module's own docstring contains example paths
                continue
            calls.extend(_python_calls(path))
    return calls


def _extends(prefix: str) -> bool:
    """True when a served path exists one segment below ``prefix``.

    ``/api/v1/collection/qualification/campaigns/{id}/${action}`` normalises to
    ``.../{param}/{param}``; dropping the last segment only proves the call is
    real if the collection below it exists (``.../freeze``, ``.../withdraw``).
    Without this check the truncated fallback would excuse a misspelled action.
    """
    matcher = _matcher(prefix + "/{param}")
    return any(matcher.match(served) for served in served_paths())


def _resolves(call: Call) -> bool:
    if is_served(call.path) or is_prefix_only(call.path):
        return True
    if call.path.endswith("{param}"):
        truncated = call.path[: -len("{param}")].rstrip("/") or "/"
        if is_served(truncated) or is_prefix_only(truncated):
            return True
        if _extends(truncated):
            return True
    return False


def unknown(calls: list[Call]) -> list[Call]:
    out: list[Call] = []
    seen: set[tuple[str, str]] = set()
    for call in calls:
        if _resolves(call):
            continue
        key = (call.path, call.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(call)
    return sorted(out, key=lambda call: (call.source, call.line))


def console_operation_typing() -> dict:
    """How many console-called operations declare a response model.

    This is the structural half of "the page exists, so the endpoint must work".
    An operation that returns ``dict`` gives the console nothing to check
    against: the TypeScript interface in ``lib/api.ts`` is a hand-written claim,
    and a field the server stops sending renders as ``undefined``.
    """
    spec = openapi_spec()["paths"]
    resolved: set[str] = set()
    for call in frontend_calls():
        for candidate in candidates(call.path):
            if candidate in spec:
                resolved.add(candidate)
                break
            found = [path for path in spec if _matcher(candidate).match(path)]
            if found:
                resolved.update(found)
                break
    typed: list[str] = []
    untyped: list[str] = []
    for path in sorted(resolved):
        for method, operation in spec[path].items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            response = (operation.get("responses") or {}).get("200") or {}
            schema = (response.get("content", {}).get("application/json", {}) or {}).get("schema")
            (typed if schema else untyped).append(f"{method.upper()} {path}")
    return {
        "operations": len(typed) + len(untyped),
        "typed": sorted(typed),
        "untyped": sorted(untyped),
        "untyped_share": round(len(untyped) / max(1, len(typed) + len(untyped)), 3),
    }


def report() -> dict:
    front = frontend_calls()
    scripts = script_calls()
    return {
        "schema": "cryptoscan.api-route-contract/1",
        "served_paths": len(served_paths()),
        "frontend_calls": len(front),
        "script_calls": len(scripts),
        "frontend_unknown": [
            {"path": call.path, "at": call.where()} for call in unknown(front)
        ],
        "script_unknown": [
            {"path": call.path, "at": call.where()} for call in unknown(scripts)
        ],
        "wrong_verbs": wrong_verbs(),
        "console_typing": {
            keys: value for keys, value in console_operation_typing().items() if keys != "untyped"
        },
    }


def main() -> int:
    document = report()
    print(json.dumps(document, indent=2))
    broken = (
        document["frontend_unknown"]
        or document["script_unknown"]
        or document["wrong_verbs"]
    )
    return 0 if not broken else 1


if __name__ == "__main__":
    raise SystemExit(main())


# --------------------------------------------------------------------------- #
# The console's own types
#
# The API declares no response model for 93% of the operations the console calls
# (they return `dict`), so the TypeScript interface in `lib/api.ts` *is* the
# contract — written by hand, on the other side of the wire, from the same
# payload. That is where "the page exists, so the endpoint must be fine" breaks:
# the console renders `data.measured.by_asset_class` and the server stops sending
# `measured`. Nothing fails until a bank opens the page.
#
# These helpers read those interfaces out of the source so a test can compare
# them with a real response.
# --------------------------------------------------------------------------- #

_INTERFACE = re.compile(r"(?:export\s+)?interface\s+([A-Za-z_]\w*)\s*(?:extends\s[\w,\s]+)?\{")

#: One top-level member of an interface body. The lookbehind is applied against
#: the *whole* source (`.match(source, index)`), not a slice — a slice would make
#: the anchor fail at position 0 and every interface would parse as empty.
_MEMBER = re.compile(
    r"(?<=[{\n;])\s*"
    r"(?:(?:/\*.*?\*/|//[^\n]*(?:\n|$))\s*)*"
    r"([A-Za-z_]\w*)(\??)\s*:",
    re.DOTALL,
)


def ts_interfaces(path: Path) -> dict[str, dict[str, bool]]:
    """``{interface name: {field: is_optional}}`` for the top-level fields only.

    Nested object literals are skipped: the check is about which keys a page can
    rely on, and a nested mismatch shows up as a missing parent key anyway.
    """
    source = path.read_text(encoding="utf-8", errors="replace")
    out: dict[str, dict[str, bool]] = {}
    for match in _INTERFACE.finditer(source):
        name = match.group(1)
        index = match.end() - 1
        depth = 0
        fields: dict[str, bool] = {}
        # walk the body, tracking braces and comments
        while index < len(source):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            elif depth == 1:
                # A member starts a line (or follows ``{`` / ``;``), which is what
                # keeps prose out of the field set: an unanchored version turned
                # ``// Always served: …`` into a field named ``served`` and
                # ``// comment with colon: here`` into one named ``colon``.
                field = _MEMBER.match(source, index)
                if field and (index == 0 or source[index - 1] in "{\n;," or source[index - 1].isspace()):
                    fields[field.group(1)] = field.group(2) == "?"
                    # absolute, because the regex matched against the whole source
                    index = field.end()
                    continue
            index += 1
        out[name] = fields
    return out
