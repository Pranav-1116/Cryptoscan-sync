"""boto3 session factory per region."""

from __future__ import annotations

from typing import Any


def session_for_region(
    region: str,
    *,
    credentials: dict[str, Any] | None = None,
    session: Any | None = None,
):
    if session is not None:
        return session
    try:
        import boto3  # type: ignore
    except Exception:
        return None
    kwargs: dict[str, Any] = {"region_name": region}
    if credentials:
        kwargs["aws_access_key_id"] = credentials.get("AccessKeyId")
        kwargs["aws_secret_access_key"] = credentials.get("SecretAccessKey")
        kwargs["aws_session_token"] = credentials.get("SessionToken")
    try:
        return boto3.Session(**{k: v for k, v in kwargs.items() if v})
    except Exception:
        return None
