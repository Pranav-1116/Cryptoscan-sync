#!/usr/bin/env python3
"""Verify production Compose exposes only the nginx edge."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDERS = {
    "POSTGRES_PASSWORD": "compose-check-only",
    "NEO4J_PASSWORD": "compose-check-only",
    "CORS_ORIGINS": "https://example.invalid",
    "METRICS_TOKEN": "compose-check-only",
    "TRUSTED_HOSTS": '["example.invalid"]',
    "SECRET_KEY": "compose-check-only",
    "ADMIN_PASSWORD_HASH": "compose-check-only",
    "GITHUB_WEBHOOK_SECRET": "compose-check-only",
    "CBOM_SIGNING_SECRET": "compose-check-only",
    "REGISTRY_WEBHOOK_SECRET": "compose-check-only",
    "STREAM_SECRET": "compose-check-only",
    "AUDITOR_API_KEY": "compose-check-only",
    "NGINX_PORT": "80",
    "TLS_PORT": "443",
    "API_PORT": "8010",
    "FRONTEND_PORT": "3003",
}


def render(*overlays: str) -> dict:
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    env.update(PLACEHOLDERS)
    command = ["docker", "compose", "--env-file", os.devnull]
    for filename in ("docker-compose.yml", *overlays):
        command.extend(("-f", filename))
    command.extend(("config", "--format", "json"))
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "docker compose config failed")
    return json.loads(result.stdout)["services"]


def published_ports(service: dict) -> set[tuple[int, int]]:
    return {(int(port["target"]), int(port["published"])) for port in service.get("ports", [])}


def check() -> None:
    for label, overlays, expected_edge in (
        ("production", ("docker-compose.prod.yml",), {(80, 80)}),
        ("production TLS", ("docker-compose.prod.yml", "docker-compose.tls.yml"), {(80, 80), (443, 443)}),
    ):
        services = render(*overlays)
        for name, service in services.items():
            if name != "nginx" and published_ports(service):
                raise RuntimeError(f"{label}: {name} publishes host ports outside the nginx edge")
        if published_ports(services["nginx"]) != expected_edge:
            raise RuntimeError(f"{label}: nginx host ports differ from {sorted(expected_edge)}")

    development = render()
    if published_ports(development["api"]) != {(8010, 8010)}:
        raise RuntimeError("development API port changed unexpectedly")
    if published_ports(development["frontend"]) != {(3003, 3003)}:
        raise RuntimeError("development frontend port changed unexpectedly")


def main() -> int:
    if shutil.which("docker") is None:
        print("prod-compose: docker compose is required to validate overlays", file=sys.stderr)
        return 2
    try:
        check()
    except (RuntimeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"prod-compose: FAIL — {exc}", file=sys.stderr)
        return 1
    print("prod-compose: OK — only nginx publishes production host ports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
