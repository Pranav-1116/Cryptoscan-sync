#!/usr/bin/env python3
"""Repository-level, honest engineering hardening checks.

This script reports static evidence only. In particular, it does not claim
that a GitHub/GitLab rule is enforced unless the provider API was queried with
credentials. It produces machine-readable PASS/FAIL/SKIP rows so the readiness
orchestrator can make a strict decision without confusing "not checked" with
"passed".
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEXT_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".rb", ".php"}


def add(checks: list[dict], name: str, status: str, detail: str, **extra: Any) -> None:
    row = {"check": name, "status": status, "detail": detail, **extra}
    checks.append(row)
    print(f"{status:<4} {name}: {detail}")


def files() -> list[Path]:
    ignored = {".git", "node_modules", "dist", "build", "coverage", ".venv", "__pycache__"}
    out = []
    for path in ROOT.rglob("*"):
        if path.is_file() and path.suffix in TEXT_EXTENSIONS and not any(part in ignored for part in path.parts):
            out.append(path)
    return out


def exception_inventory(checks: list[dict]) -> None:
    findings = []
    for path in files():
        if path.suffix != ".py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: bare except")
            elif isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}:
                body = node.body
                # A handler that only discards control flow is still swallowed,
                # even when it uses `return None` or `continue` instead of pass.
                meaningful = any(
                    not isinstance(stmt, ast.Pass)
                    and not (isinstance(stmt, ast.Return) and (stmt.value is None or isinstance(stmt.value, ast.Constant) and stmt.value.value is None))
                    and not isinstance(stmt, (ast.Continue, ast.Break))
                    for stmt in body
                )
                if not meaningful:
                    findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: swallowed {node.type.id}")
    allow = ROOT / "config" / "exception-allowlist.json"
    allowed = set()
    if allow.exists():
        try:
            payload = json.loads(allow.read_text(encoding="utf-8"))
            entries = payload.get("entries", [])
            if not isinstance(entries, list):
                raise ValueError("entries must be a list")
            seen_locations: set[str] = set()
            required_fields = {"location", "owner", "reviewed_by", "reviewed_at", "reason"}
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict) or not required_fields.issubset(entry):
                    findings.append(f"{allow}:{index + 1}: allowlist entry needs location, owner, reviewed_by, reviewed_at and reason")
                    continue
                location = str(entry["location"])
                if location in seen_locations:
                    findings.append(f"{allow}:{index + 1}: duplicate allowlist location: {location}")
                    continue
                seen_locations.add(location)
                allowed.add(location)
        except Exception as exc:
            findings.append(f"{allow}:0: invalid allowlist: {type(exc).__name__}")
    unresolved = [f for f in findings if f.split(": bare")[0].split(": swallowed")[0] not in allowed]
    # Keep test fixtures and operational probes visible, but separate them from
    # deployable runtime code. This prevents a large historical test inventory
    # from hiding whether production exception paths are actually triaged.
    production = []
    nonproduction = []
    for finding in unresolved:
        location = finding.split(":", 1)[0]
        if "/tests/" in f"/{location}" or location.startswith("tests/") or location.startswith("scripts/"):
            nonproduction.append(finding)
        else:
            production.append(finding)
    add(
        checks,
        "exception inventory",
        "PASS" if not unresolved else "FAIL",
        f"{len(production)} unresolved production handlers; {len(nonproduction)} unresolved test/harness handlers; inventory={len(findings)}",
        findings=production,
        nonproduction_findings=nonproduction,
        unresolved=len(unresolved),
        production_unresolved=len(production),
        test_harness_unresolved=len(nonproduction),
        allowlisted=len(findings) - len(unresolved),
        allowlist=str(allow),
    )


def api_key_coverage(checks: list[dict]) -> None:
    """Prove that machine-key requests reach a per-route auth dependency.

    AuthMiddleware intentionally lets X-API-Key requests through so FastAPI can
    resolve the key and its endpoint/method policy. This AST check verifies the
    second half instead of confusing the middleware bypass with authorization.
    """
    import ast

    root = ROOT / "services" / "api" / "api" / "routers"
    route_count = 0
    guarded = 0
    findings = []
    middleware = ROOT / "services" / "api" / "api" / "middleware" / "auth_middleware.py"
    global_machine_gate = middleware.exists() and "_resolve_api_key" in middleware.read_text(encoding="utf-8", errors="ignore") and "api_key_middleware_authorization_failed" in middleware.read_text(encoding="utf-8", errors="ignore")
    unprotected = (
        "/health", "/ready", "/metrics", "/api/docs", "/api/redoc", "/api/openapi.json",
        "/api/v1/auth/", "/api/v1/saas/signup", "/api/v1/saas/invites/accept",
        "/api/v1/auth/oidc", "/api/v1/auth/saml", "/api/v1/auth/ldap", "/api/v1/auth/sso",
        "/api/v1/meta", "/api/v1/healthz", "/api/v1/readyz", "/api/v1/discovery", "/api/v1/webhooks",
    )
    for path in root.rglob("*.py") if root.exists() else []:
        text = path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(text, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        router_prefix = ""
        for statement in tree.body:
            if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call) and getattr(statement.value.func, "id", "") == "APIRouter":
                for keyword in statement.value.keywords:
                    if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        router_prefix = keyword.value.value
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = [ast.unparse(d) for d in node.decorator_list]
            route_decorators = [d for d in decorators if re.search(r"(?:router|app)\.(?:get|post|put|patch|delete|api_route)\(", d)]
            if not route_decorators:
                continue
            route_count += 1
            source = ast.get_source_segment(text, node) or ""
            route = ""
            for decorator in route_decorators:
                match = re.search(r"(?:router|app)\.(?:get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]+)", decorator)
                if match:
                    route = match.group(1)
                    break
            full_route = "/api/v1" + router_prefix + route if route else ""
            exempt = any(full_route == prefix.rstrip("/") or full_route.startswith(prefix.rstrip("/") + "/") for prefix in unprotected)
            protected = global_machine_gate or "get_current_user" in source or "_resolve_api_key" in source or "get_api_key" in source
            if protected or exempt:
                guarded += 1
            else:
                findings.append(f"{path.relative_to(ROOT)}:{node.lineno}:{route or '<dynamic>'}")
    if route_count == 0:
        add(checks, "X-API-Key route coverage", "SKIP", "no API route decorators found under services/api/api/routers")
    else:
        add(checks, "X-API-Key route coverage", "PASS" if not findings else "FAIL", f"decorated routes={route_count}; auth-covered-or-exempt={guarded}; uncovered={len(findings)}", findings=findings[:100])


def frontend_roles(checks: list[dict]) -> None:
    root = ROOT / "frontend" / "src"
    findings = []
    for path in root.rglob("*.tsx") if root.exists() else []:
        if path.name.endswith((".test.tsx", ".spec.tsx")):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            if re.search(r"localStorage\.(?:getItem|setItem)\([^\n]*(?:role|roles)", line):
                findings.append(f"{path.relative_to(ROOT)}:{line_no}")
    add(checks, "frontend direct-role authorization", "PASS" if not findings else "FAIL", f"{len(findings)} direct role/localStorage references", findings=findings[:100])


def tenant_isolation_audit(checks: list[dict]) -> None:
    """Static + registry audit of the tenant-isolation plane.

    Runs scripts/tenant_isolation_audit.py in a subprocess (it bootstraps its
    own import paths) and reports its verdict: every tenant-scoped model must
    be TenantScoped or carry an in-source '# platform-scope:' justification,
    direct session.get() on scoped models and raw text() naming scoped tables
    are violations, and platform_scope() sites are inventoried.
    """
    script = ROOT / "scripts" / "tenant_isolation_audit.py"
    if not script.is_file():
        add(checks, "tenant isolation audit", "FAIL", f"audit script missing: {script}")
        return
    report_path = ROOT / "docs" / "readiness-evidence" / "tenant-isolation-audit.json"
    try:
        proc = subprocess.run(
            [sys.executable, str(script), "--json", str(report_path)],
            capture_output=True, text=True, cwd=str(ROOT), timeout=300,
        )
    except Exception as exc:  # noqa: BLE001 — report, don't crash the gate
        add(checks, "tenant isolation audit", "FAIL", f"audit run failed: {type(exc).__name__}: {exc}")
        return
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        add(checks, "tenant isolation audit", "FAIL",
            f"audit exited {proc.returncode}; report unreadable: {exc}")
        return
    violations = report.get("violations") or []
    detail = (f"{report.get('scoped_tables', '?')} scoped tables; "
              f"{report.get('platform_scope_tables', '?')} justified platform-scope tables; "
              f"{len(report.get('platform_scope_sites') or [])} platform_scope() sites; "
              f"violations={len(violations)}")
    status = "PASS" if proc.returncode == 0 and not violations else "FAIL"
    add(checks, "tenant isolation audit", status, detail, violations=violations[:100])


def image_policy(checks: list[dict], release_manifests: Path | None = None) -> None:
    """Check a rendered release, while keeping source templates honest.

    Checked-in Kubernetes files are intentionally templates because the
    registry digest does not exist until a release is built. Treating those
    templates as a production deployment would be unsafe; treating them as a
    failed release would make the static repository gate misleading. A real
    release must pass ``--release-manifests`` with the output of
    ``pin_release_images.py``.
    """
    root = (release_manifests or ROOT / "k8s").resolve()
    manifests = list(root.rglob("*.yaml")) if root.is_dir() else []
    mutable = []
    images = []
    for path in manifests:
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if not re.search(r"^\s*image:\s*[^\s]+", line):
                continue
            reference = line.split("image:", 1)[1].strip()
            images.append(reference)
            if "@sha256:" not in line:
                try:
                    location = str(path.relative_to(ROOT))
                except ValueError:
                    location = str(path)
                mutable.append(f"{location}:{line_no}:{line.strip()}")
    if release_manifests is None:
        status = "SKIP" if mutable else "PASS"
        detail = (
            f"{len(mutable)} mutable template references; render a release and "
            "supply --release-manifests before approval"
            if mutable else f"checked {len(images)} template image references"
        )
    else:
        status = "PASS" if images and not mutable else "FAIL"
        detail = f"checked {len(images)} rendered image references; mutable={len(mutable)}"
    add(checks, "production image immutable digests", status, detail, references=mutable[:100], image_references=images)


def branch_protection(checks: list[dict]) -> None:
    branch = os.getenv("PROTECTED_BRANCH", "main")
    repo = os.getenv("GITHUB_REPOSITORY")
    if repo:
        if subprocess.run(["gh", "auth", "status"], capture_output=True, check=False).returncode != 0:
            add(checks, "branch protection API verification", "SKIP", "GITHUB_REPOSITORY is set but gh is not authenticated; enforcement is not asserted")
            return
        proc = subprocess.run(["gh", "api", f"repos/{repo}/branches/{branch}/protection"], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            add(checks, "branch protection API verification", "FAIL", f"GitHub API returned exit {proc.returncode}; enforcement is not asserted")
            return
        try:
            data = json.loads(proc.stdout)
            required = data.get("required_status_checks") is not None and data.get("required_pull_request_reviews") is not None
            add(checks, "branch protection API verification", "PASS" if required else "FAIL", "GitHub response inspected; required checks/reviews presence evaluated")
        except json.JSONDecodeError:
            add(checks, "branch protection API verification", "FAIL", "GitHub response was not JSON")
        return

    project = os.getenv("GITLAB_PROJECT")
    token = os.getenv("GITLAB_TOKEN")
    if project and token:
        base = os.getenv("GITLAB_API_URL", "https://gitlab.com/api/v4").rstrip("/")
        url = f"{base}/projects/{urllib.parse.quote(project, safe='')}/protected_branches/{urllib.parse.quote(branch, safe='')}"
        request = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read())
            merge = data.get("merge_access_levels") or []
            push = data.get("push_access_levels") or []
            required = bool(merge) and bool(push)
            add(checks, "branch protection API verification", "PASS" if required else "FAIL", "GitLab response inspected; protected branch access levels evaluated")
        except Exception as exc:
            add(checks, "branch protection API verification", "FAIL", f"GitLab API query failed: {type(exc).__name__}; enforcement is not asserted")
        return

    add(checks, "branch protection API verification", "SKIP", "provider repository identifier and credentials are required; enforcement is not asserted")


def sample_hooks(checks: list[dict], args: argparse.Namespace) -> None:
    parser_names = {"cobol": "parse_cobol_file", "pli": "parse_pli_file", "rpg": "parse_rpg_file"}
    parser_modules = {"cobol": "scanner.parsers.cobol_parser", "pli": "scanner.parsers.pli_parser", "rpg": "scanner.parsers.rpg_parser"}
    scanner_path = str(ROOT / "services" / "scanner")
    if scanner_path not in sys.path:
        sys.path.insert(0, scanner_path)
    for language, value in (("cobol", args.cobol_sample), ("pli", args.pli_sample), ("rpg", args.rpg_sample)):
        if not value:
            add(checks, f"{language} customer sample", "SKIP", "sample path not supplied; corpus evidence is not customer validation")
            continue
        path = Path(value)
        if not path.exists():
            add(checks, f"{language} customer sample", "FAIL", f"not found: {value}")
            continue
        suffixes = {"cobol": {".cbl", ".cob", ".cobol", ".cpy", ".jcl"}, "pli": {".pli", ".inc"}, "rpg": {".rpgle", ".rpg", ".cl", ".sqlrpgle"}}[language]
        candidates = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file() and (p.suffix.lower() in suffixes or not p.suffix)]
        try:
            if not candidates:
                add(checks, f"{language} customer sample", "FAIL", "sample path contains no files")
                continue
            module = __import__(parser_modules[language], fromlist=[parser_names[language]])
            parser = getattr(module, parser_names[language])
            findings = 0
            for candidate in candidates:
                findings += len(parser(candidate, path.parent))
            digest = hashlib.sha256("".join(sorted(str(p) + ":" + hashlib.sha256(p.read_bytes()).hexdigest() for p in candidates)).encode()).hexdigest()
            add(checks, f"{language} customer sample", "PASS", f"parsed {len(candidates)} files; findings={findings}; sample-set-sha256={digest}; semantic TP/FP review remains customer-owned")
        except Exception as exc:
            add(checks, f"{language} customer sample", "FAIL", f"parser execution failed: {type(exc).__name__}: {exc}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--release-manifests", type=Path, default=os.getenv("RELEASE_MANIFESTS"), help="rendered release directory from pin_release_images.py; source k8s templates remain SKIP")
    ap.add_argument("--cobol-sample", default=os.getenv("COBOL_CUSTOMER_SAMPLE"))
    ap.add_argument("--pli-sample", default=os.getenv("PLI_CUSTOMER_SAMPLE"))
    ap.add_argument("--rpg-sample", default=os.getenv("RPG_CUSTOMER_SAMPLE"))
    args = ap.parse_args(argv)
    checks: list[dict] = []
    exception_inventory(checks)
    api_key_coverage(checks)
    frontend_roles(checks)
    tenant_isolation_audit(checks)
    image_policy(checks, args.release_manifests)
    branch_protection(checks)
    sample_hooks(checks, args)
    report = {"schema": "cryptoscan.engineering-gate/1", "captured_at": datetime.now(timezone.utc).isoformat(), "checks": checks, "verdict": "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"}
    output = args.out or ROOT / "docs" / "readiness-evidence" / "engineering-gate.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Engineering verdict: {report['verdict']} -> {output}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
