"""Classify every served operation by the authority it demands, and write it down.

Guide 100 §5 limit (c) says the audit proves enforcement of what a route
*declares*, and does not assert that any particular session-only route should have
declared a role — "deciding that is a policy question per route". 1212 of the 1248
operations are behind the session gate with no role requirement. This module is the
first half of deciding: it reads the route tree and says, for each operation, which
kind of authority guard is actually in its dependency closure —

* ``role``         — ``require_roles`` / ``require_any_role`` / ``require_admin``
* ``permission``   — ``require_permission`` (RBAC action, e.g. ``hardware.ingest``)
* ``tenant-role``  — ``require_tenant_roles`` (owner/admin *within a tenant*)
* ``session``      — nothing but ``get_current_user``

Written as a register (``--write``) it becomes the list a reviewer signs off, and
``scripts/tests/test_authorization_register.py`` pins the counts so the surface can
only move in the declared direction.

Guards are detected by walking the FastAPI dependency tree and matching the
qualname of the dependency callable: a factory's inner ``dependency`` carries its
enclosing function's name (``require_roles.<locals>.dependency``), which is what
the app actually executes — not what a docstring claims.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path

#: Enclosing-factory name → the kind of authority it demands. The inner function a
#: guard factory returns has qualname ``<factory>.<locals>.dependency``, so this
#: table is read off the running app.
GUARD_KINDS: dict[str, str] = {
    "require_roles": "role",
    "require_any_role": "role",
    "require_permission": "permission",
    "require_tenant_roles": "tenant-role",
}

#: Methods that change state. Session-only *reads* are a deliberate design choice
#: for most of this API; session-only writes are the ones a reviewer should see.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _guard_kind(dependant) -> tuple[str | None, tuple[str, ...]]:
    """(kind, allowed roles) for one dependency node, or (None, ()) if it is not a guard."""
    call = getattr(dependant, "call", None)
    if call is None:
        return None, ()
    qualname = getattr(call, "__qualname__", "") or ""
    factory = qualname.split(".<locals>", 1)[0]
    kind = GUARD_KINDS.get(factory)
    if kind is None:
        return None, ()
    return kind, tuple(getattr(call, "allowed_roles", ()) or ())


def route_guards(route) -> dict[str, set[tuple[str, ...]]]:
    """{kind: {allowed-role tuples}} demanded anywhere in this route's dependencies."""
    found: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    stack = [getattr(route, "dependant", None)]
    while stack:
        dependant = stack.pop()
        if dependant is None:
            continue
        kind, allowed = _guard_kind(dependant)
        if kind is not None:
            found[kind].add(allowed)
        stack.extend(getattr(dependant, "dependencies", []) or [])
    return dict(found)


def register() -> list[dict]:
    """One row per served operation: what it is, and what authority it demands."""
    import api_contract

    rows: list[dict] = []
    for route in api_contract.application().routes:
        original = getattr(route, "original_router", None)
        if original is None:
            continue  # app shell: health probes, docs — not an API router
        context = getattr(route, "include_context", None)
        prefix = (getattr(context, "prefix", "") or "") if context is not None else ""
        router_guards: dict[str, set[tuple[str, ...]]] = defaultdict(set)
        for dependency in getattr(original, "dependencies", []) or []:
            kind, allowed = _guard_kind(dependency)
            if kind is not None:
                router_guards[kind].add(allowed)
        for child in original.routes:
            methods = getattr(child, "methods", None)
            if not methods:
                continue
            guards: dict[str, set[tuple[str, ...]]] = defaultdict(set)
            for kind, sets in router_guards.items():
                guards[kind] |= sets
            for kind, sets in route_guards(child).items():
                guards[kind] |= sets
            for method in sorted(methods):
                if method in ("HEAD", "OPTIONS"):
                    continue
                rows.append(
                    {
                        "method": method,
                        "path": prefix + getattr(child, "path", ""),
                        "guards": {kind: sorted(sets) for kind, sets in guards.items()},
                        "handler": f"{getattr(child, 'endpoint', None).__module__}."
                        f"{getattr(getattr(child, 'endpoint', None), '__qualname__', '')}",
                    }
                )
    rows.sort(key=lambda row: (row["path"], row["method"]))
    return rows


def summary(rows: list[dict]) -> dict:
    # The session-only *write* list has one owner: `auth_write_inventory`, which
    # also records the policy reason and excludes public paths. Deriving it twice
    # gave two numbers for the same fact (290 here, 347 there), and a register that
    # contradicts the inventory is worse than no register.
    import auth_write_inventory

    kinds = Counter()
    unwritten = Counter()
    for row in rows:
        label = "+".join(sorted(row["guards"])) or "session"
        kinds[label] += 1
    for entry in auth_write_inventory.inventory():
        unwritten[_area(entry["path"])] += 1
    return {
        "operations": len(rows),
        "by_authority": dict(sorted(kinds.items(), key=lambda item: -item[1])),
        "session_only_writes": sum(unwritten.values()),
        "session_only_writes_by_area": dict(sorted(unwritten.items(), key=lambda item: -item[1])),
    }


def _area(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    return parts[2] if len(parts) > 2 else path


def markdown(rows: list[dict]) -> str:
    """The register as a document a reviewer can sign."""
    counts = summary(rows)
    lines = [
        "# Authorization register",
        "",
        "Generated by `scripts/authorization_register.py --write`. Do not edit by hand;",
        "regenerate and review the diff.",
        "",
        "Every served operation, with the authority its dependency closure demands. The",
        "guards are read from the callables the application executes, so this is what the",
        "API enforces, not what a document claims.",
        "",
        "## Totals",
        "",
        "| Authority demanded | Operations |",
        "|---|---|",
    ]
    for label, count in counts["by_authority"].items():
        lines.append(f"| {label} | {count} |")
    lines += [
        "",
        f"**{counts['operations']}** operations; **{counts['session_only_writes']}** of them "
        "change state with nothing but the session gate — the exact list, with the policy",
        "reason for each, is `102-authenticated-only-writes.json`.",
        "",
        "## Session-only writes, by area",
        "",
        "These are the routes that hold no role requirement. Each one is recorded with",
        "the reason it holds none in `102-authenticated-only-writes.json`; the count is",
        "pinned by `scripts/tests/test_auth_write_inventory.py` and may only go down.",
        "",
        "| Area | Session-only writes |",
        "|---|---|",
    ]
    for area, count in counts["session_only_writes_by_area"].items():
        lines.append(f"| `{area}` | {count} |")
    lines += [
        "",
        "## Every session-only write",
        "",
        "| Method | Path | Handler |",
        "|---|---|---|",
    ]
    for row in rows:
        if row["guards"] or row["method"] not in WRITE_METHODS:
            continue
        lines.append(f"| {row['method']} | `{row['path']}` | `{row['handler']}` |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", metavar="PATH", help="write the markdown register here")
    parser.add_argument("--summary", action="store_true", help="print the totals only")
    args = parser.parse_args(argv)

    rows = register()
    if args.summary or not args.write:
        import json

        print(json.dumps(summary(rows), indent=2))
    if args.write:
        target = Path(args.write)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(markdown(rows))
        print(f"wrote {target} ({len(rows)} operations)")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
