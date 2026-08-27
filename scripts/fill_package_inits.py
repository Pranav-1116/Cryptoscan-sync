"""One-shot generator: fill empty package __init__.py files with real docstrings.

Writes a package docstring (purpose + accurate module inventory with each
module's first docstring line). Idempotent: only touches zero-byte files.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PURPOSES: dict[str, str] = {
    "services/api/api": "CryptoScan API service — FastAPI application package (app, routers, middleware, security).",
    "services/api/api/config": "API configuration: settings loaded from environment (.env via shared_config).",
    "services/api/api/github": "GitHub integration clients (status poster, app auth) for scan feedback.",
    "services/api/api/middleware": "ASGI middleware (request IDs, auth, rate limiting, metrics).",
    "services/api/api/routers": "HTTP route handlers exposing scans, findings, policies, evidence, stats.",
    "services/api/api/schemas": "Pydantic request/response schemas for the API surface.",
    "services/api/api/security": "Authentication and authorization (token auth, RBAC guards).",
    "services/api/tests": "API test suite (unit + integration).",
    "services/database/tests": "Database service test suite (unit).",
    "services/drift/drift/alerts": "Drift alerting: notifications when drift between scans is detected.",
    "services/drift/drift/classifiers": "Classifiers that categorize drift events by severity and kind.",
    "services/drift/drift/core": "Drift service core engine and orchestration.",
    "services/drift/drift/fingerprinting": "Finding fingerprinting for cross-scan comparison.",
    "services/drift/drift/models": "Drift domain models (events, comparisons, snapshots).",
    "services/drift/tests": "Drift service test suite.",
    "services/evidence/evidence/core": "Evidence service core: recording and lifecycle of tamper-evident records.",
    "services/evidence/evidence/hashing": "Hashing utilities (canonical JSON digests) for evidence integrity.",
    "services/evidence/evidence/models": "Evidence domain models (records, chains, batches).",
    "services/evidence/evidence/storage": "Evidence persistence backends.",
    "services/evidence/evidence/verification": "Evidence chain verification (hash-chain audit).",
    "services/evidence/tests": "Evidence service test suite.",
    "services/normalization/normalization/core": "Normalization core engine: raw findings to normalized findings.",
    "services/normalization/normalization/enrichers": "Post-normalization enrichers (context, vendor intel).",
    "services/normalization/normalization/matchers": "Pattern matchers binding raw findings to rule catalog entries.",
    "services/normalization/normalization/models": "Normalization domain models (rules, normalized findings).",
    "services/normalization/normalization/rules": "Rule loading, validation, and registry for the YAML catalog.",
    "services/normalization/tests": "Normalization service test suite.",
    "services/policy/policy": "Policy service: evaluates normalized findings against policy packs.",
    "services/policy/policy/conditions": "Condition evaluators for policy rules.",
    "services/policy/policy/core": "Policy engine core (evaluation, violations, decisions).",
    "services/policy/policy/models": "Policy domain models (packs, rules, violations).",
    "services/policy/policy/rules": "Built-in policy rules and pack loading.",
    "services/policy/tests": "Policy service test suite.",
    "services/scanner/scanner/config": "Scanner configuration (paths, exclusions, thresholds).",
    "services/scanner/scanner/core": "Scanner core: orchestration, file discovery, language detection.",
    "services/scanner/scanner/extractors": "Extraction helpers (algorithms, snippets, confidence).",
    "services/scanner/scanner/git": "Git metadata client for scan targets.",
    "services/scanner/scanner/models": "Scanner domain models (RawFinding, ScanResult, enums).",
    "services/scanner/scanner/output": "Scan output writers and the JSON Schema result contract.",
    "services/scanner/scanner/parsers": "Per-language parsers turning source into RawFindings.",
    "services/scanner/tests": "Scanner test suite (unit + integration + fixtures).",
    "services/worker/tests": "Worker test suite (unit).",
    "services/worker/worker/core": "Worker core: job consumption from Redis, lifecycle management.",
    "services/worker/worker/pipeline": "Scan processing pipeline stages executed by the worker.",
    "services/worker/worker/workspace": "Workspace management for checked-out scan targets.",
}

TEST_PURPOSE = "Test-suite package marker: keeps tests importable under their service namespace."


def module_summary(path: Path) -> str:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return ""
    doc = ast.get_docstring(tree)
    if doc:
        return doc.strip().splitlines()[0].rstrip(".")
    return ""


def subpackages(pkg_dir: Path) -> list[str]:
    return sorted(
        d.name for d in pkg_dir.iterdir() if d.is_dir() and (d / "__init__.py").exists()
    )


def build_doc(pkg_dir: Path, rel: str) -> str:
    purpose = PURPOSES.get(rel)
    if purpose is None:
        if pkg_dir.name == "tests":
            purpose = TEST_PURPOSE
        else:
            purpose = f"{rel.split('/', 1)[1].replace('/', '.')} package."
    lines = [f'"""{purpose}', ""]

    modules = sorted(
        p for p in pkg_dir.glob("*.py") if p.name != "__init__.py" and not p.name.startswith("conftest")
    )
    subpkgs = subpackages(pkg_dir)
    if modules:
        lines.append("Modules:")
        for mod in modules:
            summary = module_summary(mod)
            lines.append(f"- {mod.stem}: {summary}" if summary else f"- {mod.stem}")
    if subpkgs:
        if modules:
            lines.append("")
        lines.append("Subpackages: " + ", ".join(subpkgs) + ".")
    lines.append('"""')
    return "\n".join(lines) + "\n"


def main() -> None:
    filled = 0
    for init in sorted(ROOT.rglob("__init__.py")):
        if ".venv" in init.parts or ".git" in init.parts:
            continue
        if init.stat().st_size != 0:
            continue
        rel = str(init.parent.relative_to(ROOT))
        if rel not in PURPOSES and init.parent.name != "tests":
            print(f"SKIP (no purpose mapped): {rel}")
            continue
        init.write_text(build_doc(init.parent, rel), encoding="utf-8")
        filled += 1
    print(f"filled {filled} __init__.py files")


if __name__ == "__main__":
    main()
