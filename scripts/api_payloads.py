"""Synthesise a minimal *valid* request body from the API's own schema.

The live route sweep sent `{}` to every write. FastAPI answers `422` before the
handler runs whenever a route declares required fields, so most handlers were
never executed — the sweep proved the dependency graph resolved, not that the
operation works. That is the limit guide 100 §5 records as "the sweep sends an
empty body".

This module closes it from the other side: read the request schema out of the
OpenAPI document (the same one served at `/api/openapi.json`), resolve `$ref`,
and fill every required field with a value of the declared type — enumerations
take their first member, `const` takes its value, formats get format-appropriate
strings, numbers respect `minimum`, strings respect `minLength`/`maxLength` and
`pattern` where it is simple enough to satisfy.

What it is not: a fixture generator for a specific bank. The values are
deliberately unremarkable and obviously synthetic (`contract-…`, `127.0.0.1`,
`2026-01-01T00:00:00Z`), so a handler that accepts them is exercising its real
code path while a handler that rejects them is telling us something about its
schema.
"""

from __future__ import annotations

import re

#: A fixed instant. Deterministic values keep a sweep reproducible: the same
#: operation with the same body fails in the same place on any machine.
TIMESTAMP = "2026-01-01T00:00:00Z"
DATE = "2026-01-01"


def _first_enum(schema: dict):
    values = schema.get("enum") or []
    return values[0] if values else None


def _string(schema: dict, field: str) -> str:
    if "const" in schema:
        return str(schema["const"])
    enum = _first_enum(schema)
    if enum is not None:
        return str(enum)
    fmt = (schema.get("format") or "").lower()
    if fmt == "date-time":
        return TIMESTAMP
    if fmt == "date":
        return DATE
    if fmt == "email":
        return "contract@example.invalid"
    if fmt == "uri" or fmt == "url":
        return "https://example.invalid/contract"
    if fmt == "ipv4":
        return "127.0.0.1"
    if fmt == "ipv6":
        return "::1"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    if fmt == "binary":
        return "contract"
    minimum = schema.get("minLength") or 0
    value = f"contract-{field}"
    # `pattern` is only honoured when the requirement is a character class the
    # placeholder already satisfies; guessing at an arbitrary regex would produce
    # bodies the schema rejects, which is the thing this module exists to avoid.
    pattern = schema.get("pattern")
    if pattern:
        simple = re.fullmatch(r"\^?\[([A-Za-z0-9_\-]+)\]\+?\$?", pattern)
        if simple:
            value = "contract" + (simple.group(1)[0] if simple.group(1) else "x")
    if len(value) < minimum:
        value = value + "x" * (minimum - len(value))
    maximum = schema.get("maxLength")
    if isinstance(maximum, int):
        value = value[:maximum]
    return value


def _number(schema: dict, integer: bool):
    if "const" in schema:
        return schema["const"]
    enum = _first_enum(schema)
    if enum is not None:
        return enum[0] if isinstance(enum, list) else enum
    minimum = schema.get("minimum")
    value = 1 if minimum is None else max(1, int(minimum) if integer else minimum)
    if schema.get("exclusiveMinimum") is True:
        value = (value if integer else float(value)) + 1
    maximum = schema.get("maximum")
    if maximum is not None and value > maximum:
        value = maximum
    return int(value) if integer else float(value)


def synthesize_value(schema: dict, field: str = "value", *, spec: dict | None = None, depth: int = 0):
    """One value satisfying ``schema``, of the type it declares."""
    if not isinstance(schema, dict) or depth > 6:
        return None
    if "$ref" in schema and spec is not None:
        resolved = resolve_ref(spec, schema["$ref"])
        return synthesize_value(resolved, field, spec=spec, depth=depth + 1)
    for combinator in ("allOf", "anyOf", "oneOf"):
        options = schema.get(combinator)
        if options:
            if combinator == "allOf":
                merged: dict = {"type": "object", "properties": {}, "required": []}
                for part in options:
                    part = resolve_ref(spec, part["$ref"]) if "$ref" in part and spec else part
                    merged["properties"].update(part.get("properties") or {})
                    merged["required"].extend(part.get("required") or [])
                return synthesize_value(merged, field, spec=spec, depth=depth + 1)
            return synthesize_value(options[0], field, spec=spec, depth=depth + 1)
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((item for item in kind if item != "null"), "string")
    if kind == "object" or "properties" in schema:
        return synthesize_object(schema, spec=spec, depth=depth + 1)
    if kind == "array":
        items = schema.get("items") or {"type": "string"}
        count = max(1, int(schema.get("minItems") or 1))
        return [synthesize_value(items, field, spec=spec, depth=depth + 1) for _ in range(count)]
    if kind == "integer":
        return _number(schema, True)
    if kind == "number":
        return _number(schema, False)
    if kind == "boolean":
        return bool(schema.get("const", True))
    if kind == "null":
        return None
    return _string(schema, field)


def synthesize_object(schema: dict, *, spec: dict | None = None, depth: int = 0,
                      required_only: bool = True) -> dict:
    """An object carrying every required property, and optional ones only if asked."""
    properties = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    if not required_only:
        required = list(properties)
    body: dict = {}
    for name in required:
        field_schema = properties.get(name) or {}
        value = synthesize_value(field_schema, name, spec=spec, depth=depth + 1)
        if value is not None or field_schema.get("type") == "null":
            body[name] = value
    if "additionalProperties" in schema and isinstance(schema["additionalProperties"], dict):
        # A free-form map: one entry so a handler that iterates it has something.
        body.setdefault("contract", synthesize_value(schema["additionalProperties"], "contract", spec=spec, depth=depth + 1))
    return body


def resolve_ref(spec: dict, ref: str) -> dict:
    """Follow a local ``#/...`` pointer inside the OpenAPI document."""
    if not ref.startswith("#/"):
        return {}
    node = spec
    for segment in ref[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or segment not in node:
            return {}
        node = node[segment]
    return node if isinstance(node, dict) else {}


def request_body(spec: dict, path: str, method: str) -> dict | None:
    """A valid body for the operation, or None when it declares none."""
    operation = (spec.get("paths") or {}).get(path, {}).get(method.lower()) or {}
    body = operation.get("requestBody") or {}
    content = body.get("content") or {}
    for media_type in ("application/json", "application/*+json", "*/*"):
        if media_type in content:
            schema = content[media_type].get("schema") or {}
            if "$ref" in schema:
                schema = resolve_ref(spec, schema["$ref"])
            if schema.get("type") == "array":
                return synthesize_value(schema, "body", spec=spec)
            return synthesize_object(schema, spec=spec)
    return None
