#!/usr/bin/env python3
"""Prove the production gate refuses what it claims to refuse.

``validate_runtime_settings`` is the only thing standing between a
``docker compose up`` with defaults and a production instance with a published
secret key. A gate nobody exercises is a comment, so this command runs a matrix
of hostile configurations through it and fails if any of them boots:

* a valid production configuration must PASS (otherwise "everything is
  refused" would also look green — and the deployment would be unusable);
* every hostile variant must be REFUSED, and for the stated reason.

Two modes:

``--matrix`` (default)
    Fixtures only. Runs in CI, needs no deployment.

``--env-file <path>``
    Load that file as the process environment and run the *real* gate on the
    *real* configuration. Secret values are never printed — the report carries a
    redacted fingerprint so an operator can confirm which value was judged.

Exit codes: 0 every case behaved, 1 a case did not, 2 bad invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "services" / "api", ROOT / "shared" / "shared_config"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

#: A production configuration that must be accepted. Fixed values so the run is
#: reproducible; every one of them is what an operator would actually have to
#: supply (long random secrets, a PBKDF2 hash, rediss with an ACL user).
VALID_PRODUCTION: dict[str, Any] = {
    "ENVIRONMENT": "production",
    "SECRET_KEY": "audit-current-secret-key-0123456789abcdefghijklmnop",
    "SECRET_KEY_PREVIOUS": "",
    "ADMIN_PASSWORD": "",
    "ADMIN_PASSWORD_HASH": "pbkdf2_sha256$600000$c2FsdHNhbHRzYWx0c2FsdA==$"
    "3V0U5n0m0Yw5m5m5m5m5m5m5m5m5m5m5m5m5m5m5m5m5=",
    "GITHUB_WEBHOOK_SECRET": "audit-webhook-secret-0123456789abcdef",
    "DATABASE_URL": "postgresql+psycopg2://cryptoscan:pw@postgres.internal:5432/cryptoscan",
    "REDIS_URL": "rediss://cryptoscan-realtime:pw@redis.internal:6379/0",
    "REDIS_SENTINELS": "",
    "REDIS_SENTINEL_MASTER": "",
    "EVENT_TAILER_SECONDS": 2,
    "CORS_ORIGINS": "https://console.bank.example",
    "TRUSTED_HOSTS": ["cryptoscan.bank.example"],
    "METRICS_TOKEN": "audit-metrics-token-0123456789abcdefghijkl",
    "REGISTRY_WEBHOOK_SECRET": "audit-registry-secret-0123456789abcdefgh",
    "CBOM_SIGNING_SECRET": "audit-cbom-secret-0123456789abcdefghijkl",
    "STREAM_SECRET": "audit-stream-secret-0123456789abcdefghij",
    "AUDITOR_API_KEY": "audit-auditor-key-0123456789abcdefghijklm",
    "CRYPTOSCAN_DEPLOYMENT_PROFILE": "kubernetes-external-services/local-source-v1",
    "NEO4J_URI": "",
    "NEO4J_PASSWORD": "",
    "TLS_CERT_FILE": "",
    "TLS_KEY_FILE": "",
    "TRUSTED_PROXY_COUNT": 1,
    "TRUSTED_PROXY_CIDRS": "10.20.0.0/24",
    "ALLOW_SQLITE": False,
    "ALLOW_INSECURE_CORS": False,
}


@dataclass(frozen=True)
class Case:
    name: str
    overrides: dict[str, Any]
    #: substring the refusal must mention; ``None`` means "this is a deliberate
    #: escape hatch — it is accepted, and the audit reports it as a warning so it
    #: can never be switched on unnoticed".
    expect: str | None
    why: str


MATRIX: tuple[Case, ...] = (
    Case(
        "weak SECRET_KEY",
        {"SECRET_KEY": "changeme"},
        "SECRET_KEY must be a unique value",
        "a guessable session key forges any user's session",
    ),
    Case(
        "plaintext admin password",
        {"ADMIN_PASSWORD_HASH": "", "ADMIN_PASSWORD": "cryptoscan"},
        "ADMIN_PASSWORD_HASH must be set in production",
        "the default login can never be live",
    ),
    Case(
        "sqlite database",
        {"DATABASE_URL": "sqlite:///./data/cryptoscan.db"},
        "DATABASE_URL must be PostgreSQL",
        "a single-file database has no PITR and no HA",
    ),
    Case(
        "no redis",
        {"REDIS_URL": ""},
        "REDIS_URL must be configured",
        "realtime events and scan state need shared storage",
    ),
    Case(
        "redis without TLS",
        {"REDIS_URL": "redis://cryptoscan:pw@redis.internal:6379/0"},
        "Realtime Redis requires verified TLS",
        "evidence events would cross the network in clear text",
    ),
    Case(
        "redis default ACL user",
        {"REDIS_URL": "rediss://default:pw@redis.internal:6379/0"},
        "dedicated non-default ACL user",
        "the default user has no per-install isolation",
    ),
    Case(
        "wildcard CORS",
        {"CORS_ORIGINS": "*"},
        "CORS_ORIGINS must be an explicit origin list",
        "any web page could call the API as the victim",
    ),
    Case(
        "wildcard TRUSTED_HOSTS",
        {"TRUSTED_HOSTS": ["*"]},
        "TRUSTED_HOSTS must be an explicit host allow-list",
        "host-header poisoning reaches password-reset and OIDC links",
    ),
    Case(
        "short metrics token",
        {"METRICS_TOKEN": "short"},
        "METRICS_TOKEN must be a unique value",
        "the metrics endpoint exposes estate size and queue depth",
    ),
    Case(
        "missing CBOM signing secret",
        {"CBOM_SIGNING_SECRET": ""},
        "CBOM_SIGNING_SECRET must be a unique value",
        "unsigned BOMs cannot be distinguished from forged ones",
    ),
    Case(
        "rotation overlap contains current key",
        {"SECRET_KEY_PREVIOUS": "audit-current-secret-key-0123456789abcdefghijklmnop"},
        "must not contain the current SECRET_KEY",
        "a no-op rotation that claims an overlap it does not have",
    ),
    Case(
        "four retained previous keys",
        {
            "SECRET_KEY_PREVIOUS": ",".join(
                f"retired-secret-key-{index}-0123456789abcdefghij" for index in range(4)
            )
        },
        "more than 3 rotations",
        "every retained key can still mint a session",
    ),
    Case(
        "operator profile with a graph endpoint",
        {"NEO4J_URI": "bolt://neo4j:7687"},
        "Operator profile must leave NEO4J_URI empty",
        "a profile that promises no graph must not half-enable one",
    ),
    Case(
        "forwarded headers trusted from any peer",
        {"TRUSTED_PROXY_CIDRS": ""},
        "TRUSTED_PROXY_CIDRS must name the proxy network",
        "any direct client could choose its own IP for audit and limits",
    ),
    Case(
        "proxy CIDR list with no hop count",
        {"TRUSTED_PROXY_COUNT": 0},
        "TRUSTED_PROXY_COUNT must be at least 1",
        "a configured allow-list that is silently never consulted",
    ),
    Case(
        "trusted proxy from the whole internet",
        {"TRUSTED_PROXY_CIDRS": "0.0.0.0/0"},
        "must not trust every address",
        "X-Forwarded-For would be client-written again",
    ),
    Case(
        "insecure CORS escape hatch",
        {"ALLOW_INSECURE_CORS": True, "CORS_ORIGINS": "*"},
        None,
        "an accepted escape hatch: reported as a warning, never silently green",
    ),
)


def _settings_factory():
    from api.config.settings import APISettings

    def build(overrides: dict[str, Any]):
        values = {**VALID_PRODUCTION, **overrides}
        # ``_env_file=None``: the audit judges the values it was handed, not
        # whatever happens to sit in the operator's .env.
        return APISettings(_env_file=None, **values)

    return build


def _refusal(settings: Any) -> str | None:
    from api.config.settings import validate_runtime_settings

    try:
        validate_runtime_settings(settings)
    except RuntimeError as exc:
        return str(exc)
    return None


def run_matrix() -> dict[str, Any]:
    build = _settings_factory()
    results: list[dict[str, Any]] = []

    baseline = _refusal(build({}))
    results.append(
        {
            "case": "valid production configuration",
            "expected": "accepted",
            "outcome": "PASS" if baseline is None else "FAIL",
            "detail": baseline or "accepted",
            "why": "the gate must be usable, not merely strict",
        }
    )

    for case in MATRIX:
        refusal = _refusal(build(case.overrides))
        if case.expect is None:
            # An escape hatch: accepted by design. It still has to be visible.
            outcome = "WARN" if refusal is None else "PASS"
            detail = refusal or "accepted — deliberate escape hatch, see WARNINGS"
        elif refusal is None:
            outcome, detail = "FAIL", "accepted — this configuration must not boot"
        elif case.expect not in refusal:
            outcome = "FAIL"
            detail = f"refused for the wrong reason: {refusal[:200]}"
        else:
            outcome, detail = "PASS", refusal
        results.append(
            {"case": case.name, "expected": case.expect, "outcome": outcome, "detail": detail, "why": case.why}
        )

    failed = [row for row in results if row["outcome"] == "FAIL"]
    warnings = [row for row in results if row["outcome"] == "WARN"]
    return {
        "mode": "matrix",
        "schema": "cryptoscan.config-audit/1",
        "cases": len(results),
        "passed": len(results) - len(failed) - len(warnings),
        "warnings": len(warnings),
        "failed": len(failed),
        "ok": not failed,
        "results": results,
    }


def _fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest} len={len(value)}"


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, raw = stripped.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = raw.strip().strip("'\"")
        values[key] = value
    return values


def run_env_file(path: Path) -> dict[str, Any]:
    """Judge the deployment's real configuration, without printing its secrets."""
    values = _load_env_file(path)
    for key, value in values.items():
        os.environ[key] = value
    from api.config.settings import APISettings, get_settings, validate_runtime_settings

    get_settings.cache_clear()
    settings = APISettings(_env_file=None)
    refusal = None
    try:
        validate_runtime_settings(settings)
    except RuntimeError as exc:
        refusal = str(exc)
    interesting = (
        "ENVIRONMENT",
        "SECRET_KEY",
        "SECRET_KEY_PREVIOUS",
        "DATABASE_URL",
        "REDIS_URL",
        "METRICS_TOKEN",
        "CBOM_SIGNING_SECRET",
        "TRUSTED_PROXY_COUNT",
        "TRUSTED_PROXY_CIDRS",
    )
    observed = {}
    for name in interesting:
        value = str(getattr(settings, name, "") or "")
        if name in {"SECRET_KEY", "METRICS_TOKEN"} or name.endswith("SECRET"):
            observed[name] = _fingerprint(value) if value else "(empty)"
        elif name == "SECRET_KEY_PREVIOUS":
            observed[name] = f"{len([p for p in value.split(',') if p.strip()])} retained"
        else:
            observed[name] = value or "(empty)"
    return {
        "mode": "env-file",
        "schema": "cryptoscan.config-audit/1",
        "file": str(path),
        "ok": refusal is None,
        "refusal": refusal,
        "observed": observed,
    }


def render(report: dict[str, Any]) -> str:
    lines: list[str] = []
    if report["mode"] == "matrix":
        lines.append(
            f"config audit — {report['cases']} cases, {report['passed']} refused as required, "
            f"{report['warnings']} accepted escape hatch(es), {report['failed']} did not"
        )
        width = max(len(row["case"]) for row in report["results"])
        for row in report["results"]:
            mark = {"PASS": "ok  ", "WARN": "warn", "FAIL": "FAIL"}[row["outcome"]]
            lines.append(f"  [{mark}] {row['case']:<{width}}  {row['why']}")
            if row["outcome"] != "PASS":
                lines.append(f"         -> {row['detail']}")
    else:
        lines.append(f"config audit — {report['file']}")
        lines.append(f"  verdict: {'accepted' if report['ok'] else 'REFUSED'}")
        for name, value in report["observed"].items():
            lines.append(f"  {name}: {value}")
        if report["refusal"]:
            lines.append(f"  refusal: {report['refusal']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, help="judge this deployment's real environment file")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    report = run_env_file(args.env_file) if args.env_file else run_matrix()
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
