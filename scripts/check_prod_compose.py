#!/usr/bin/env python3
"""Verify production Compose exposes only the nginx edge."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDERS = {
    "POSTGRES_PASSWORD": "compose-check-only",
    "CRYPTOSCAN_APP_DATABASE_URL": "postgresql://ci_runtime:compose-check-only@postgres:5432/cryptoscan",
    "REDIS_URL": "rediss://ci_acl:compose-check-only@redis.internal:6379/0",
    "REDIS_CA_HOST_PATH": "/tmp/cryptoscan-compose-check-ca.pem",
    "BACKUP_STORAGE_HOST_PATH": "/tmp/cryptoscan-compose-check-governance-backups",
    "SBOM_S3_ENDPOINT": "https://s3.example.invalid",
    "SBOM_S3_BUCKET": "cryptoscan-ci-artifacts",
    "SBOM_S3_ACCESS_KEY_HOST_PATH": "/tmp/cryptoscan-compose-check-s3-access",
    "SBOM_S3_SECRET_KEY_HOST_PATH": "/tmp/cryptoscan-compose-check-s3-secret",
    "SBOM_S3_CA_HOST_PATH": "/tmp/cryptoscan-compose-check-s3-ca.pem",
    "SBOM_STORAGE_BACKUP_DIR": "/tmp/cryptoscan-compose-check-backup-declaration",
    "SBOM_RETENTION_DAYS": "365",
    "NEO4J_PASSWORD": "compose-check-only",
    "CORS_ORIGINS": "https://example.invalid",
    "METRICS_TOKEN": "compose-check-only",
    "ALERTMANAGER_WEBHOOK_TOKEN": "compose-check-only-alertmanager-0123456789abcdef",
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


def render(*overlays: str, profiles: tuple[str, ...] = ()) -> dict:
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    env.update(PLACEHOLDERS)
    command = ["docker", "compose", "--env-file", os.devnull]
    for profile in profiles:
        command.extend(("--profile", profile))
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
        ("production S3", ("docker-compose.prod.yml", "docker-compose.s3.yml"), {(80, 80)}),
    ):
        services = render(*overlays, profiles=("notifications",))
        for name, service in services.items():
            if name != "nginx" and published_ports(service):
                raise RuntimeError(f"{label}: {name} publishes host ports outside the nginx edge")
        if published_ports(services["nginx"]) != expected_edge:
            raise RuntimeError(f"{label}: nginx host ports differ from {sorted(expected_edge)}")
        backup_dir = services["api"]["environment"].get("BACKUP_STORAGE_DIR")
        if not backup_dir or not any(
            mount.get("target") == backup_dir and not mount.get("read_only", False)
            and mount.get("bind", {}).get("create_host_path") is not True
            for mount in services["api"].get("volumes", []) if isinstance(mount, dict)
        ):
            raise RuntimeError(f"{label}: production backup store has no writable bank-managed mount")
        migrator = urlsplit(services["migrate"]["environment"]["DATABASE_URL"])
        runtime = ("api", "worker", "estate-daemon", "monitor", "notifications")
        urls = [services[name]["environment"]["DATABASE_URL"] for name in runtime]
        if (not migrator.username or len(set(urls)) != 1 or any(
            not urlsplit(url).username or urlsplit(url).username == migrator.username
            for url in urls
        )):
            raise RuntimeError(f"{label}: runtime database identity must differ from the migration superuser")
        for name in ("api", "worker", "estate-daemon", "monitor"):
            service = services[name]
            if not service["environment"].get("REDIS_URL", "").startswith("rediss://"):
                raise RuntimeError(f"{label}: {name} must use bank-owned TLS Redis")
            if not any(
                mount.get("target") == "/run/secrets/redis-ca.pem" and mount.get("read_only") is True
                for mount in service.get("volumes", []) if isinstance(mount, dict)
            ):
                raise RuntimeError(f"{label}: {name} has no read-only Redis CA bundle")
        if label == "production S3":
            s3_names = ("SBOM_S3_ENDPOINT", "SBOM_S3_BUCKET", "SBOM_S3_REGION",
                        "SBOM_S3_ACCESS_KEY_FILE", "SBOM_S3_SECRET_KEY_FILE", "SBOM_S3_CA_BUNDLE")
            api = services["api"]
            worker = services["worker"]
            if any(api["environment"].get(key) != worker["environment"].get(key) for key in s3_names):
                raise RuntimeError("production S3: API and worker artifact backends differ")
            evidence_fields = ("ENDPOINT", "BUCKET", "REGION", "ACCESS_KEY_FILE",
                               "SECRET_KEY_FILE", "CA_BUNDLE")
            for name in ("api", "worker"):
                env = services[name]["environment"]
                if any(env.get(f"EVIDENCE_OBJECT_S3_{field}") != env.get(f"SBOM_S3_{field}")
                       for field in evidence_fields) or env.get("EVIDENCE_OBJECT_S3_PREFIX") != "tenants":
                    raise RuntimeError(f"production S3: {name} twin evidence tier differs from BOM storage")
            for name in ("api", "worker"):
                service = services[name]
                for key in ("SBOM_S3_ACCESS_KEY_FILE", "SBOM_S3_SECRET_KEY_FILE", "SBOM_S3_CA_BUNDLE"):
                    path = service["environment"][key]
                    if not any(mount.get("target") == path and mount.get("read_only") is True
                               for mount in service.get("volumes", []) if isinstance(mount, dict)):
                        raise RuntimeError(f"production S3: {name} has no read-only {key} mount")
            if "SBOM_S3_SECRET_KEY_FILE" in services["migrate"]["environment"]:
                raise RuntimeError("production S3: migration role must not receive the S3 credential")

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
