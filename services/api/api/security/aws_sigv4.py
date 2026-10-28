"""AWS Signature Version 4, in the standard library.

Two callers need it: exporting anchor receipts to S3 and reading cloud TLS
configuration read-only. A signing bug is silent (the request simply fails at the
service), so the implementation is checked against the test vector published in
the AWS documentation — see ``test_anchor_export.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import urllib.parse
from datetime import datetime, timezone
from typing import Mapping


def _now() -> datetime:
    return datetime.now(timezone.utc)


def sigv4_headers(
    *,
    method: str,
    url: str,
    body: bytes,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
    now: datetime | None = None,
    service: str = "s3",
) -> dict[str, str]:
    """Return the headers (including ``Authorization``) for one SigV4 request."""
    moment = (now or _now()).astimezone(timezone.utc)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = moment.strftime("%Y%m%d")
    parsed = urllib.parse.urlsplit(url)
    canonical_uri = urllib.parse.quote(parsed.path or "/", safe="/-_.~")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    canonical_query = "&".join(
        f"{urllib.parse.quote(key, safe='-_.~')}={urllib.parse.quote(value, safe='-_.~')}"
        for key, value in sorted(query)
    )
    headers = {str(key).lower(): str(value) for key, value in (extra_headers or {}).items()}
    headers["host"] = parsed.netloc
    headers["x-amz-content-sha256"] = hashlib.sha256(body or b"").hexdigest()
    headers["x-amz-date"] = amz_date
    if session_token:
        headers["x-amz-security-token"] = session_token
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{key}:{headers[key].strip()}\n" for key in sorted(headers))
    canonical_request = "\n".join([
        method.upper(), canonical_uri, canonical_query, canonical_headers, signed_headers,
        headers["x-amz-content-sha256"],
    ])
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    def sign(key: bytes, message: str) -> bytes:
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


