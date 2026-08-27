"""Org-level enumeration — discover every account in a customer estate.

A partnership scan starts one level above accounts:

- AWS:        ``organizations:ListAccounts`` on the management account
              (or a delegated admin), then assume a cross-account role in
              each member account
- Azure:      tenant-level subscription list (subscription SDK or ARM),
              Lighthouse-delegated or tenant-consented
- GCP:        Resource Manager ``projects.list`` at org or folder scope

Every enumerator returns the same shape::

    {
        "provider": "aws",
        "accounts": [                       # one row per scannable account
            {"account_id": "...", "name": "...", "status": "ACTIVE",
             "role_arn": "arn:aws:iam::...:role/CryptoScanRole"}
        ],
        "truncated": False,                 # cap hit before the org ran out
        "errors": [...],                    # never silent
   }

Clients are injectable so tests need no cloud SDKs. Fail-open on missing
SDKs stays (like the rest of cloud_scanner) but errors are reported.
"""

from __future__ import annotations

import os
from typing import Any

from cloud_scanner.core.reliability import ScanTelemetry, call_with_retry

DEFAULT_MAX_ACCOUNTS = 200


def _cap(env: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(env) or default))
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# AWS Organizations
# --------------------------------------------------------------------------- #


def enumerate_aws_org(
    *,
    session=None,
    role_name: str | None = None,
    telemetry: ScanTelemetry | None = None,
    max_accounts: int | None = None,
) -> dict[str, Any]:
    """List every account in the AWS Organization.

    ``role_name`` builds the per-member cross-account role ARN
    (arn:aws:iam::<id>:role/<role_name>) installed by the marketplace
    CloudFormation template.
    """
    role_name = role_name or os.environ.get("CRYPTOSCAN_AWS_ORG_ROLE_NAME") or "CryptoScanCrossAccountRole"
    cap = max_accounts or _cap("CRYPTOSCAN_CLOUD_ORG_MAX_ACCOUNTS", DEFAULT_MAX_ACCOUNTS)
    if telemetry:
        telemetry.providers_attempted.add("AWS")
    if session is None:
        try:
            import boto3  # type: ignore

            session = boto3.Session()
        except Exception as exc:  # noqa: BLE001 — fail-open, reported
            return _provider_error("AWS", "organizations", exc, telemetry)

    accounts: list[dict[str, Any]] = []
    truncated = False
    next_token: str | None = None
    try:
        client = session.client("organizations")
        while True:
            kwargs: dict[str, Any] = {"NextToken": next_token} if next_token else {}
            ok, value, error = call_with_retry(lambda kw=kwargs: client.list_accounts(**kw))
            if not ok:
                if telemetry:
                    telemetry.record_error("AWS", "organizations", "global", error)
                return {"provider": "aws", "accounts": accounts, "truncated": truncated, "errors": [str(error)[:300]]}
            response = value or {}
            for row in response.get("Accounts") or []:
                if str(row.get("Status") or "").upper() != "ACTIVE":
                    continue
                if len(accounts) >= cap:
                    truncated = True
                    break
                account_id = str(row.get("Id") or row.get("AccountId") or "")
                accounts.append(
                    {
                        "account_id": account_id,
                        "name": str(row.get("Name") or account_id),
                        "email": row.get("Email"),
                        "status": "ACTIVE",
                        "role_arn": f"arn:aws:iam::{account_id}:role/{role_name}" if account_id else None,
                    }
                )
            if truncated:
                break
            next_token = response.get("NextToken")
            if not next_token:
                break
    except Exception as exc:  # noqa: BLE001 — enumeration must never crash a scan
        return _provider_error("AWS", "organizations", exc, telemetry)

    if telemetry:
        telemetry.record_resources(len(accounts))
    return {"provider": "aws", "accounts": accounts, "truncated": truncated, "errors": []}


# --------------------------------------------------------------------------- #
# Azure — tenant-level subscription enumeration
# --------------------------------------------------------------------------- #


def enumerate_azure_subscriptions(
    *,
    credential=None,
    telemetry: ScanTelemetry | None = None,
    max_accounts: int | None = None,
) -> dict[str, Any]:
    """List every subscription the credential can see (tenant consent or
    Lighthouse delegation)."""
    cap = max_accounts or _cap("CRYPTOSCAN_CLOUD_ORG_MAX_ACCOUNTS", DEFAULT_MAX_ACCOUNTS)
    if telemetry:
        telemetry.providers_attempted.add("AZURE")
    if credential is None:
        try:
            from cloud_scanner.azure.auth.credential_manager import azure_credential

            credential = azure_credential()
        except Exception:
            credential = None
        if credential is None:
            try:
                from azure.identity import DefaultAzureCredential  # type: ignore

                credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
            except Exception as exc:  # noqa: BLE001
                return _provider_error("AZURE", "subscriptions", exc, telemetry)

    accounts: list[dict[str, Any]] = []
    truncated = False
    try:
        from azure.mgmt.subscription import SubscriptionClient  # type: ignore

        client = SubscriptionClient(credential)
        for sub in client.subscriptions.list():
            if str(getattr(sub, "state", "") or "").upper() not in {"ENABLED", "ENABLED ", "WARNED", "PAST_DUE"}:
                if str(getattr(sub, "state", "") or "").upper() != "ENABLED":
                    continue
            if len(accounts) >= cap:
                truncated = True
                break
            sub_id = str(getattr(sub, "subscription_id", "") or "")
            accounts.append(
                {
                    "account_id": sub_id,
                    "name": str(getattr(sub, "display_name", "") or sub_id),
                    "status": "ENABLED",
                    "subscription_id": sub_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        return _provider_error("AZURE", "subscriptions", exc, telemetry)

    if telemetry:
        telemetry.record_resources(len(accounts))
    return {"provider": "azure", "accounts": accounts, "truncated": truncated, "errors": []}


# --------------------------------------------------------------------------- #
# GCP — Resource Manager project enumeration
# --------------------------------------------------------------------------- #


def enumerate_gcp_projects(
    *,
    client=None,
    folder: str | None = None,
    organization: str | None = None,
    telemetry: ScanTelemetry | None = None,
    max_accounts: int | None = None,
) -> dict[str, Any]:
    """List every ACTIVE project under an organization or folder.

    ``client`` is a cloudresourcemanager v1 service object (injectable).
    """
    cap = max_accounts or _cap("CRYPTOSCAN_CLOUD_ORG_MAX_ACCOUNTS", DEFAULT_MAX_ACCOUNTS)
    if telemetry:
        telemetry.providers_attempted.add("GCP")
    if client is None:
        try:
            from googleapiclient.discovery import build  # type: ignore

            client = build("cloudresourcemanager", "v1", cache_discovery=False)
        except Exception as exc:  # noqa: BLE001
            return _provider_error("GCP", "cloudresourcemanager", exc, telemetry)

    filters = "lifecycleState:ACTIVE"
    if folder:
        filters += f" parent.type:folder parent.id:{folder}"
    elif organization:
        filters += f" parent.type:organization parent.id:{organization}"

    accounts: list[dict[str, Any]] = []
    truncated = False
    try:
        page_token = None
        while True:
            kwargs: dict[str, Any] = {"filter": filters}
            if page_token:
                kwargs["pageToken"] = page_token
            ok, value, error = call_with_retry(lambda kw=kwargs: client.projects().list(**kw).execute())
            if not ok:
                if telemetry:
                    telemetry.record_error("GCP", "cloudresourcemanager", "global", error)
                return {"provider": "gcp", "accounts": accounts, "truncated": truncated, "errors": [str(error)[:300]]}
            for project in (value or {}).get("projects") or []:
                if len(accounts) >= cap:
                    truncated = True
                    break
                project_id = str(project.get("projectId") or project.get("project_id") or "")
                accounts.append(
                    {
                        "account_id": project_id,
                        "name": str(project.get("name") or project_id),
                        "status": "ACTIVE",
                        "project_id": project_id,
                    }
                )
            if truncated:
                break
            page_token = (value or {}).get("nextPageToken")
            if not page_token:
                break
    except Exception as exc:  # noqa: BLE001
        return _provider_error("GCP", "cloudresourcemanager", exc, telemetry)

    if telemetry:
        telemetry.record_resources(len(accounts))
    return {"provider": "gcp", "accounts": accounts, "truncated": truncated, "errors": []}


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #


def enumerate_org(provider: str, *, telemetry: ScanTelemetry | None = None, **kwargs: Any) -> dict[str, Any]:
    """Enumerate accounts for an org provider ('aws', 'azure', 'gcp')."""
    provider = str(provider or "").lower().replace("-org", "").strip()
    if provider == "aws":
        return enumerate_aws_org(telemetry=telemetry, **kwargs)
    if provider == "azure":
        return enumerate_azure_subscriptions(telemetry=telemetry, **kwargs)
    if provider == "gcp":
        return enumerate_gcp_projects(telemetry=telemetry, **kwargs)
    return {"provider": provider, "accounts": [], "truncated": False, "errors": [f"unknown provider: {provider}"]}


def _provider_error(provider: str, service: str, exc: Exception, telemetry: ScanTelemetry | None) -> dict[str, Any]:
    if telemetry:
        telemetry.record_error(provider, service, "global", exc)
    return {"provider": provider.lower(), "accounts": [], "truncated": False, "errors": [f"{type(exc).__name__}: {exc}"[:300]]}
