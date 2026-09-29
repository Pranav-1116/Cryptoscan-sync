"""STS assume-role helper. Fail-open when boto3 or credentials are missing."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from typing import Any


def assume_role(
    role_arn: str,
    *,
    session_name: str = "cryptoscan-scan-session",
    duration_seconds: int = 3600,
    sts_client: Any | None = None,
    external_id: str | None = None,
) -> dict[str, Any] | None:
    if not role_arn:
        return None
    client = sts_client
    if client is None:
        try:
            import boto3  # type: ignore

            client = boto3.client("sts")
        except Exception as _handler_exc:
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            return None
    kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": duration_seconds,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    try:
        response = client.assume_role(**kwargs)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    creds = (response or {}).get("Credentials") or {}
    if not creds:
        return None
    return {
        "AccessKeyId": creds.get("AccessKeyId"),
        "SecretAccessKey": creds.get("SecretAccessKey"),
        "SessionToken": creds.get("SessionToken"),
        "Expiration": creds.get("Expiration"),
        "AssumedRoleUser": (response or {}).get("AssumedRoleUser"),
    }
