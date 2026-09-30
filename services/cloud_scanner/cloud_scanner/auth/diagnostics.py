"""Credential-chain diagnostics for cloud deployments.

Answers the deployment question "why did the cloud scan find nothing?"
without shell access to the pod: which credential source each provider's
SDK would use, whether the SDK is installed, and hygiene warnings.

Rules of engagement:

* NO network probes — IMDS/metadata availability is reported as a
  fallback the SDK *would* try; presence of markers (env vars, config
  files) is all we report.
* NO secret values ever leave this module — only presence booleans and
  file paths, with a redaction guard as defense in depth.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import importlib.util
from pathlib import Path
from typing import Any, Mapping

_REDACT_KEYS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "client_secret",
    "private_key",
    "token",
}

_FALLBACK_SOURCES = {"instance-metadata-imds", "metadata-server", "imds-managed-identity"}


def _sdk_installed(module: str) -> str | None:
    try:
        spec = importlib.util.find_spec(module)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    return module if spec is not None else None


def _scrub(status: dict[str, Any]) -> dict[str, Any]:
    """Defense in depth: never emit credential-looking values."""
    cleaned: dict[str, Any] = {}
    for key, value in status.items():
        if str(key).lower() in _REDACT_KEYS and not isinstance(value, bool):
            cleaned[key] = "[redacted]"
        elif isinstance(value, dict):
            cleaned[key] = _scrub(value)
        elif isinstance(value, list):
            cleaned[key] = [_scrub(item) if isinstance(item, dict) else item for item in value]
        else:
            cleaned[key] = value
    return cleaned


def _first_real_source(detected: list[dict[str, str]], fallback: str) -> str:
    for row in detected:
        if row["source"] not in _FALLBACK_SOURCES:
            return row["source"]
    return fallback


def _aws(environ: Mapping[str, str], home: Path) -> dict[str, Any]:
    detected: list[dict[str, str]] = []
    if environ.get("AWS_ACCESS_KEY_ID") and environ.get("AWS_SECRET_ACCESS_KEY"):
        detected.append({"source": "env-static-keys", "detail": "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY set"})
    if environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        detected.append({"source": "ecs-container-role", "detail": "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI set (ECS task role)"})
    if environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") and environ.get("AWS_ROLE_ARN"):
        detected.append({"source": "web-identity-irsa", "detail": "AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN (EKS workload identity)"})
    shared = home / ".aws" / "credentials"
    if shared.is_file():
        profiles: list[str] = []
        try:
            for line in shared.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    profiles.append(stripped[1:-1])
        except OSError:
            pass
        detected.append(
            {
                "source": "shared-credentials-file",
                "detail": "~/.aws/credentials present with profile(s): " + (", ".join(sorted(set(profiles))[:8]) or "(none parsed)"),
            }
        )
    if environ.get("AWS_PROFILE"):
        detected.append({"source": "profile-selected", "detail": f"AWS_PROFILE={environ['AWS_PROFILE']}"})
    detected.append(
        {
            "source": "instance-metadata-imds",
            "detail": "not probed (no network calls); the SDK falls back to IMDS when running on EC2",
        }
    )
    warnings = []
    if any(row["source"] == "env-static-keys" for row in detected):
        warnings.append("long-lived static keys in environment — prefer workload identity / instance profiles for bank deployments")
    return {
        "provider": "aws",
        "sdk_installed": _sdk_installed("boto3"),
        "effective_source": _first_real_source(detected, "instance-metadata-imds"),
        "detected": detected,
        "cross_account_role_arn": environ.get("CRYPTOSCAN_AWS_ROLE_ARN") or environ.get("AWS_ROLE_ARN"),
        "region_hint": environ.get("AWS_DEFAULT_REGION") or environ.get("AWS_REGION"),
        "warnings": warnings,
    }


def _gcp(environ: Mapping[str, str], home: Path) -> dict[str, Any]:
    detected: list[dict[str, str]] = []
    creds_path = environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if creds_path:
        present = Path(creds_path).is_file()
        detected.append(
            {
                "source": "service-account-file",
                "detail": "GOOGLE_APPLICATION_CREDENTIALS " + ("set, file present" if present else "set, FILE MISSING"),
            }
        )
    adc = home / ".config" / "gcloud" / "application_default_credentials.json"
    if adc.is_file():
        detected.append({"source": "gcloud-adc", "detail": "gcloud application_default_credentials.json present"})
    detected.append(
        {
            "source": "metadata-server",
            "detail": "not probed (no network calls); the SDK uses the GCE/GKE metadata server when running in GCP",
        }
    )
    return {
        "provider": "gcp",
        "sdk_installed": _sdk_installed("google.oauth2.service_account"),
        "effective_source": _first_real_source(detected, "metadata-server"),
        "detected": detected,
        "project_hint": environ.get("GOOGLE_CLOUD_PROJECT") or environ.get("GCP_PROJECT"),
        "warnings": [],
    }


def _azure(environ: Mapping[str, str], home: Path) -> dict[str, Any]:
    detected: list[dict[str, str]] = []
    if environ.get("AZURE_CLIENT_ID") and environ.get("AZURE_TENANT_ID"):
        if environ.get("AZURE_CLIENT_SECRET"):
            kind = "client-secret"
        elif environ.get("AZURE_CLIENT_CERTIFICATE_PATH"):
            kind = "certificate"
        else:
            kind = "identity-without-secret (workload identity / CI)"
        detected.append({"source": "env-service-principal", "detail": f"AZURE_CLIENT_ID + AZURE_TENANT_ID ({kind})"})
    if environ.get("IDENTITY_ENDPOINT") or environ.get("MSI_ENDPOINT"):
        detected.append({"source": "managed-identity-endpoint", "detail": "IDENTITY_ENDPOINT/MSI_ENDPOINT set (App Service / Functions managed identity)"})
    az_cli = home / ".azure" / "msal_token_cache.json"
    if az_cli.is_file():
        detected.append({"source": "az-cli-cache", "detail": "azure cli token cache present (developer setup, not production)"})
    detected.append(
        {
            "source": "imds-managed-identity",
            "detail": "not probed (no network calls); DefaultAzureCredential falls back to IMDS on Azure VMs",
        }
    )
    warnings = []
    if environ.get("AZURE_CLIENT_SECRET"):
        warnings.append("client secret in environment — prefer managed identity for bank deployments")
    return {
        "provider": "azure",
        "sdk_installed": _sdk_installed("azure.identity"),
        "effective_source": _first_real_source(detected, "imds-managed-identity"),
        "detected": detected,
        "subscription_hint": environ.get("AZURE_SUBSCRIPTION_ID") or environ.get("CRYPTOSCAN_AZURE_SUBSCRIPTION"),
        "warnings": warnings,
    }


def credential_status(
    environ: Mapping[str, str] | None = None,
    home: Path | str | None = None,
) -> dict[str, Any]:
    """Diagnostic view of every provider's credential chain (secrets scrubbed)."""
    import os

    environ = os.environ if environ is None else environ
    home = Path(home) if home is not None else Path.home()
    providers = [_scrub(_aws(environ, home)), _scrub(_gcp(environ, home)), _scrub(_azure(environ, home))]
    configured = [
        row["provider"]
        for row in providers
        if any(source["source"] not in _FALLBACK_SOURCES for source in row["detected"])
    ]
    return {
        "providers": providers,
        "configured": configured,
        "notes": [
            "no network calls are made: metadata/IMDS availability is a documented SDK fallback, never verified here",
            "secret values are never included — only presence and file paths",
        ],
    }
