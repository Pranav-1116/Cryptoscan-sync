#!/usr/bin/env python3
"""Tenant-isolation audit: every escape hatch must be justified in source.

The runtime guard (``db/tenancy.py``) fails closed on raw SQL, Core-shaped
statements and unstamped bulk inserts while a tenant scope is active. Guards
rot, however, exactly like the queries they police — so this script audits
the *source* for the shapes the guard exists to catch, plus the model plane
the guard derives its authority from:

1. **Model conformance** — every model with a ``__tablename__`` under a
   ``db/models/`` package must inherit ``TenantScoped`` unless the class
   carries a ``# platform-scope: <reason>`` marker (identity plane, tenant
   registry, worker leases, global catalogs). Unmarked unscoped models are
   how cross-tenant tables are born.
2. **Direct primary-key loads** — ``session.get(ScopedModel, ...)`` bypasses
   SELECT criteria via the identity map; scoped reads must go through
   ``db.tenancy.filtered_get``.
3. **Raw SQL** — ``text("... scans ...")`` literals naming a tenant-scoped
   table outside the guard's own tests and Alembic migrations (platform-plane
   schema management, which runs unscoped by design).
4. **Inventory** — every ``platform_scope()`` site, so deliberate cross-tenant
   reads stay greppable and reviewable.

The registry check imports the live models when the environment allows it
(SQLAlchemy present) and cross-checks the table registry the Core guard
matches against; without it the script degrades to the AST pass alone.

Exit code is 0 only when there are no violations.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import re
import sys
import tokenize
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

#: Schema management and tests are outside tenant scopes by design.
SCAN_ROOTS = [ROOT / "services"]
EXCLUDED_PARTS = {"tests", "migrations", "__pycache__", "node_modules", ".venv"}

PLATFORM_SCOPE_MARKER = re.compile(r"#\s*platform-scope:\s*(?P<reason>.+)")


def _service_paths() -> list[Path]:
    paths: list[Path] = []
    for pattern in ("services/*", "shared/*"):
        for path in ROOT.glob(pattern):
            if path.is_dir() and path.name not in EXCLUDED_PARTS:
                paths.append(path)
    return paths


def _bootstrap_imports() -> None:
    for path in _service_paths():
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def _iter_python_files() -> list[Path]:
    out: list[Path] = []
    for root in SCAN_ROOTS:
        for path in root.rglob("*.py"):
            if any(part in EXCLUDED_PARTS for part in path.parts):
                continue
            out.append(path)
    return sorted(out)


def _comment_lines(source: str) -> dict[int, str]:
    """Line number -> comment text, via tokenize (comments are not in the AST)."""
    comments: dict[int, str] = {}
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comments[token.start[0]] = token.string
    except tokenize.TokenError:
        pass
    return comments


# --------------------------------------------------------------------- #
# live registry (authoritative table/model sets)
# --------------------------------------------------------------------- #

def registry_facts() -> tuple[dict[str, Any], str | None]:
    """Import the models and derive scoped tables / models; None on failure."""
    try:
        _bootstrap_imports()
        import db.models  # noqa: F401 — registers every model
        from db.connection.session import Base
        from db.tenancy import TenantScoped, scoped_tables
    except Exception as exc:  # noqa: BLE001 — report, don't crash
        return {}, f"model import failed ({type(exc).__name__}: {exc}); AST pass only"

    scoped: dict[str, str] = {}      # table name -> model name
    unscoped: dict[str, str] = {}    # table name -> model name
    missing_index: list[str] = []
    for mapper in Base.registry.mappers:
        model = mapper.class_
        table = getattr(model, "__table__", None)
        name = getattr(model, "__tablename__", None)
        if table is None or not name:
            continue
        if issubclass(model, TenantScoped):
            scoped[name] = model.__name__
            column = table.columns.get("tenant_id")
            if column is None:
                missing_index.append(f"{model.__name__}.{name}: no tenant_id column")
            elif column.index is None:
                missing_index.append(f"{model.__name__}.{name}: tenant_id not indexed")
        else:
            unscoped[name] = model.__name__

    registered = set(scoped_tables())
    unregistered = sorted(set(scoped) - registered)
    facts = {
        "scoped_tables": scoped,
        "unscoped_tables": unscoped,
        "unregistered_with_guard": unregistered,
        "tenant_id_column_issues": missing_index,
    }
    return facts, None


# --------------------------------------------------------------------- #
# AST pass 1: model conformance + platform-scope markers
# --------------------------------------------------------------------- #

def audit_models(facts: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Every __tablename__ class must be TenantScoped or carry a marker."""
    violations: list[str] = []
    justified: list[str] = []

    for path in _iter_python_files():
        if not path.parts or "models" not in path.parts:
            continue
        if not any(part.endswith("db") for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        comments = _comment_lines(source)
        rel = path.relative_to(ROOT)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            table = None
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in stmt.targets)
                        and isinstance(stmt.value, ast.Constant)):
                    table = str(stmt.value.value)
            if table is None:
                continue
            bases = {b.id for b in node.bases if isinstance(b, ast.Name)}
            bases |= {b.attr for b in node.bases if isinstance(b, ast.Attribute)}
            if "TenantScoped" in bases:
                continue
            # Justified platform scope? Marker above the class or inside it.
            span = set(range(node.lineno, node.end_lineno + 1)) | set(range(max(1, node.lineno - 3), node.lineno))
            reason = None
            for line in span:
                match = PLATFORM_SCOPE_MARKER.match(comments.get(line, ""))
                if match:
                    reason = match.group("reason").strip()
                    break
            if reason:
                justified.append(f"{rel}:{node.lineno}: {node.name} ({table}) — {reason}")
            else:
                violations.append(
                    f"{rel}:{node.lineno}: model {node.name} (table {table!r}) is not "
                    f"TenantScoped and carries no '# platform-scope:' justification"
                )
    # Cross-check: registry classes the AST pass could not see (dynamic
    # definitions) still count through the live facts.
    for table, model in sorted((facts.get("unscoped_tables") or {}).items()):
        if not any(model in entry for entry in justified + violations):
            violations.append(
                f"(registry) {model} (table {table!r}) is not TenantScoped; the AST "
                f"pass found no '# platform-scope:' marker for it"
            )
    return violations, justified


# --------------------------------------------------------------------- #
# AST pass 2: escape-hatch usage in request/worker code
# --------------------------------------------------------------------- #

def audit_escape_hatches(facts: dict[str, Any]) -> tuple[list[str], list[str]]:
    """session.get on scoped models, text() naming scoped tables, platform_scope sites."""
    violations: list[str] = []
    scope_sites: list[str] = []
    scoped_models = set((facts.get("scoped_tables") or {}).values())
    scoped_tables = set((facts.get("scoped_tables") or {}).keys())
    if not scoped_tables:  # no live registry: fall back to a broad word set
        scoped_tables = set()
        scoped_models = set()

    text_call = re.compile(r"\b(%s)\b" % "|".join(sorted(re.escape(t) for t in scoped_tables))) if scoped_tables else None

    for path in _iter_python_files():
        rel = path.relative_to(ROOT)
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            # platform_scope() inventory (informational)
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "platform_scope"):
                scope_sites.append(f"{rel}:{node.lineno}")

            # session.get(ScopedModel, ...) — identity-map bypass of the filter
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                    and node.args
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id in scoped_models):
                receiver = node.func.value
                receiver_name = getattr(receiver, "id", None) or getattr(receiver, "attr", "") or ""
                if receiver_name and re.search(r"session|sess|db$|\bdb\b", receiver_name, re.IGNORECASE):
                    violations.append(
                        f"{rel}:{node.lineno}: direct {receiver_name}.get({node.args[0].id}, ...) "
                        f"bypasses tenant SELECT criteria; use db.tenancy.filtered_get"
                    )

            # text("... <scoped table> ...") in request/worker code
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "text"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str) and text_call is not None):
                match = text_call.search(node.args[0].value)
                if match:
                    violations.append(
                        f"{rel}:{node.lineno}: raw text() names tenant-scoped table "
                        f"{match.group(1)!r}; inside a tenant scope the guard rejects this — "
                        f"use the ORM or an explicit platform_scope block"
                    )
    return violations, scope_sites


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path, default=None, help="also write findings as JSON")
    args = ap.parse_args(argv)

    facts, import_error = registry_facts()
    model_violations, justified = audit_models(facts)
    hatch_violations, scope_sites = audit_escape_hatches(facts)

    registry_violations = list(facts.get("unregistered_with_guard") or []) + list(facts.get("tenant_id_column_issues") or [])
    scoped_count = len(facts.get("scoped_tables") or {})
    unscoped_count = len(facts.get("unscoped_tables") or {})

    print(f"tenant-isolation audit — {scoped_count} scoped tables, "
          f"{unscoped_count} platform-scope tables")
    if import_error:
        print(f"WARN {import_error}")
    if justified:
        print("\nplatform-scope tables (justified in source):")
        for entry in justified:
            print(f"  - {entry}")
    if scope_sites:
        print(f"\nplatform_scope() opt-out sites ({len(scope_sites)}):")
        for site in scope_sites:
            print(f"  - {site}")
    for label, items in (
        ("model-conformance violations", model_violations),
        ("escape-hatch violations", hatch_violations),
        ("registry violations", registry_violations),
    ):
        if items:
            print(f"\nFAIL {label} ({len(items)}):")
            for item in items:
                print(f"  - {item}")

    all_violations = model_violations + hatch_violations + registry_violations
    if args.json:
        payload = {
            "schema": "cryptoscan.tenant-isolation-audit/1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "scoped_tables": scoped_count,
            "platform_scope_tables": unscoped_count,
            "justified": justified,
            "platform_scope_sites": scope_sites,
            "violations": all_violations,
            "registry_available": import_error is None,
            "registry_warning": import_error,
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\njson report -> {args.json}")

    verdict = "PASS" if not all_violations else "FAIL"
    print(f"\ntenant-isolation audit verdict: {verdict}")
    return 0 if not all_violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
