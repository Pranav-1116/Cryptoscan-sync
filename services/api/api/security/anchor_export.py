"""Export anchor receipts to storage CryptoScan does not control (spec 67 §31, spec 93 §18).

A signed receipt is only an *external* anchor once it has left this database. This
module performs that step for real, against three sinks that exist in a bank:

``FILESYSTEM``  an append-only directory (a mounted WORM volume, a CMDB drop, an
               NFS export). Writes use ``O_CREAT|O_EXCL``: an existing receipt is
               never overwritten, so the sink itself enforces "no rewrite".
``S3``          S3-compatible object storage (AWS S3, MinIO, Ceph RGW) with real
               SigV4 request signing, ``If-None-Match: *`` so a second export of
               the same anchor cannot clobber the first, and optional Object Lock
               headers when the bucket enables compliance mode.
``WEBHOOK``     an HTTPS endpoint with an HMAC-signed body (a change-ticket system,
               a SIEM, a bank's evidence bus). The signature header lets the
               receiver verify the receipt was produced by this key.

What this module refuses to do:

* claim ``external: true`` for a write that was not confirmed by the sink;
* overwrite an existing object — a duplicate export is reported as
  ``already_exported`` with the existing location, not silently replaced;
* invent credentials: with no sink configured it raises
  :class:`AnchorExportError` (surfaced as ``409 anchor_export_not_configured``).

Configuration (first match wins):

* ``ANCHOR_EXPORT_DIR``
* ``ANCHOR_EXPORT_S3_BUCKET`` + ``ANCHOR_EXPORT_S3_REGION`` +
  ``ANCHOR_EXPORT_S3_ACCESS_KEY`` + ``ANCHOR_EXPORT_S3_SECRET_KEY``, optionally
  ``ANCHOR_EXPORT_S3_ENDPOINT`` (MinIO/Ceph), ``ANCHOR_EXPORT_S3_PREFIX``,
  ``ANCHOR_EXPORT_S3_SESSION_TOKEN``, ``ANCHOR_EXPORT_S3_OBJECT_LOCK=1``
  (default: on — receipts are written with a retain-until date)
* ``ANCHOR_EXPORT_WEBHOOK_URL`` + ``ANCHOR_EXPORT_WEBHOOK_KEY``
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

SCHEMA = "cryptoscan.anchor-export/1"
DEFAULT_RETENTION_DAYS = 365 * 7

SINK_FILESYSTEM = "FILESYSTEM"
SINK_S3 = "S3"
SINK_WEBHOOK = "WEBHOOK"

Transport = Callable[[str, str, Mapping[str, str], bytes | None, float], tuple[int, bytes, Mapping[str, str]]]


class AnchorExportError(RuntimeError):
    """The receipt could not be exported honestly."""

    def __init__(self, code: str, reason: str, *, detail: Mapping[str, Any] | None = None) -> None:
        self.code = code
        self.reason = reason
        self.detail = dict(detail or {})
        super().__init__(reason)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def sink_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve the configured sink, or raise if there is none."""
    env = dict(os.environ if environ is None else environ)

    directory = (env.get("ANCHOR_EXPORT_DIR") or "").strip()
    if directory:
        return {"sink": SINK_FILESYSTEM, "directory": directory}

    bucket = (env.get("ANCHOR_EXPORT_S3_BUCKET") or "").strip()
    access_key = (env.get("ANCHOR_EXPORT_S3_ACCESS_KEY") or "").strip()
    secret_key = (env.get("ANCHOR_EXPORT_S3_SECRET_KEY") or "").strip()
    if bucket and access_key and secret_key:
        region = (env.get("ANCHOR_EXPORT_S3_REGION") or "us-east-1").strip()
        endpoint = (env.get("ANCHOR_EXPORT_S3_ENDPOINT") or f"https://s3.{region}.amazonaws.com").rstrip("/")
        return {
            "sink": SINK_S3,
            "bucket": bucket,
            "region": region,
            "endpoint": endpoint,
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": (env.get("ANCHOR_EXPORT_S3_SESSION_TOKEN") or "").strip() or None,
            "prefix": (env.get("ANCHOR_EXPORT_S3_PREFIX") or "cryptoscan/anchors").strip("/"),
            "object_lock": str(env.get("ANCHOR_EXPORT_S3_OBJECT_LOCK", "1")).lower() not in {"0", "false", "no"},
            "retention_days": int(env.get("ANCHOR_EXPORT_S3_RETENTION_DAYS") or DEFAULT_RETENTION_DAYS),
        }

    url = (env.get("ANCHOR_EXPORT_WEBHOOK_URL") or "").strip()
    key = (env.get("ANCHOR_EXPORT_WEBHOOK_KEY") or "").strip()
    if url and key:
        return {"sink": SINK_WEBHOOK, "url": url, "key": key}

    raise AnchorExportError(
        "anchor_export_not_configured",
        "no anchor export sink is configured: set ANCHOR_EXPORT_DIR, the ANCHOR_EXPORT_S3_* pair, or "
        "ANCHOR_EXPORT_WEBHOOK_URL + KEY. An anchor that never leaves this database is not external",
    )


def sink_status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Non-raising description of the sink, for status endpoints."""
    try:
        config = sink_config(environ)
    except AnchorExportError as exc:
        return {"configured": False, "sink": None, "reason": exc.reason}
    detail = {key: value for key, value in config.items()
              if key not in {"secret_key", "access_key", "key", "session_token"}}
    return {"configured": True, "sink": config["sink"], "detail": detail}


# --------------------------------------------------------------------------- #
# S3 SigV4 (stdlib only — no boto3 in this image)
# --------------------------------------------------------------------------- #
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


def _default_transport(url: str, method: str, headers: Mapping[str, str], body: bytes | None,
                       timeout: float) -> tuple[int, bytes, Mapping[str, str]]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read() or b"", dict(exc.headers)


# --------------------------------------------------------------------------- #
# sinks
# --------------------------------------------------------------------------- #
def _object_key(prefix: str, anchor_id: str) -> str:
    return f"{prefix}/{anchor_id}.json" if prefix else f"{anchor_id}.json"


def _export_filesystem(receipt: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    directory = str(config["directory"])
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{receipt['anchor_id']}.json")
    payload = json.dumps(receipt, indent=2, sort_keys=True, default=str).encode("utf-8")
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    except FileExistsError as exc:
        raise AnchorExportError(
            "already_exported",
            "this anchor already exists in the sink; an export never overwrites an existing receipt",
            detail={"location": path},
        ) from exc
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        pass
    digest = hashlib.sha256(payload).hexdigest()
    return {"location": f"file://{path}", "content_sha256": digest, "confirmable": True,
            "confirmation": "write-once file created (O_EXCL) and fsynced"}


def _export_s3(receipt: Mapping[str, Any], config: Mapping[str, Any],
               transport: Transport | None, timeout: float) -> dict[str, Any]:
    key = _object_key(str(config.get("prefix") or ""), str(receipt["anchor_id"]))
    url = f"{config['endpoint']}/{config['bucket']}/{urllib.parse.quote(key, safe='/-_.~')}"
    body = json.dumps(receipt, indent=2, sort_keys=True, default=str).encode("utf-8")
    headers = {
        "content-type": "application/json",
        "if-none-match": "*",
    }
    if config.get("object_lock"):
        retain_until = (_now() + timedelta(days=int(config.get("retention_days") or DEFAULT_RETENTION_DAYS)))
        headers["x-amz-object-lock-mode"] = "COMPLIANCE"
        headers["x-amz-object-lock-retain-until-date"] = retain_until.strftime("%Y-%m-%dT%H:%M:%SZ")
    signed = sigv4_headers(
        method="PUT", url=url, body=body, region=str(config["region"]),
        access_key=str(config["access_key"]), secret_key=str(config["secret_key"]),
        session_token=config.get("session_token"), extra_headers=headers,
    )
    request_headers = {key_name: value for key_name, value in signed.items()}
    request_headers["Content-Type"] = "application/json"
    request_headers["Host"] = signed["host"]
    request_headers["If-None-Match"] = "*"
    if config.get("object_lock"):
        request_headers["x-amz-object-lock-mode"] = str(headers["x-amz-object-lock-mode"])
        request_headers["x-amz-object-lock-retain-until-date"] = str(
            headers["x-amz-object-lock-retain-until-date"])

    sender = transport or _default_transport
    status, response_body, response_headers = sender(url, "PUT", request_headers, body, timeout)
    if status in {409, 412}:
        raise AnchorExportError(
            "already_exported",
            "the sink already holds this anchor (If-None-Match: *); an export never overwrites evidence",
            detail={"location": url},
        )
    if status >= 300:
        raise AnchorExportError(
            "anchor_export_failed",
            f"the object store refused the write: HTTP {status}",
            detail={"location": url, "status": status, "body": response_body[:400].decode("utf-8", "replace")},
        )
    etag = response_headers.get("ETag") or response_headers.get("etag")
    version = response_headers.get("x-amz-version-id") or response_headers.get("X-Amz-Version-Id")
    return {
        "location": url,
        "content_sha256": hashlib.sha256(body).hexdigest(),
        "etag": etag,
        "object_version": version,
        "object_lock": bool(config.get("object_lock")),
        "confirmable": True,
        "confirmation": "object store accepted the write (If-None-Match: *)",
    }


def _export_webhook(receipt: Mapping[str, Any], config: Mapping[str, Any],
                    transport: Transport | None, timeout: float) -> dict[str, Any]:
    body = json.dumps({"schema": SCHEMA, "receipt": receipt}, sort_keys=True, default=str).encode("utf-8")
    signature = hmac.new(str(config["key"]).encode("utf-8"), body, hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-CryptoScan-Signature": f"sha256={signature}",
        "X-CryptoScan-Anchor-Id": str(receipt["anchor_id"]),
    }
    sender = transport or _default_transport
    status, response_body, response_headers = sender(str(config["url"]), "POST", headers, body, timeout)
    if status >= 300:
        raise AnchorExportError(
            "anchor_export_failed",
            f"the receiver refused the receipt: HTTP {status}",
            detail={"location": str(config["url"]), "status": status,
                    "body": response_body[:400].decode("utf-8", "replace")},
        )
    return {
        "location": str(config["url"]),
        "content_sha256": hashlib.sha256(body).hexdigest(),
        "receiver_reference": response_headers.get("X-Request-Id") or response_headers.get("x-request-id"),
        "confirmable": True,
        "confirmation": f"receiver acknowledged with HTTP {status}",
    }


def export_receipt(
    receipt: Mapping[str, Any],
    *,
    config: Mapping[str, Any] | None = None,
    transport: Transport | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Write one signed receipt to the configured sink; ``external`` is only true on confirmation."""
    resolved = dict(config) if config else sink_config()
    sink = resolved["sink"]
    if sink == SINK_FILESYSTEM:
        result = _export_filesystem(receipt, resolved)
    elif sink == SINK_S3:
        result = _export_s3(receipt, resolved, transport, timeout)
    elif sink == SINK_WEBHOOK:
        result = _export_webhook(receipt, resolved, transport, timeout)
    else:  # pragma: no cover - sink_config is the only producer
        raise AnchorExportError("unknown_sink", f"unknown sink {sink!r}")

    return {
        "schema": SCHEMA,
        "anchor_id": receipt.get("anchor_id"),
        "projection_id": receipt.get("projection_id"),
        "sink": sink,
        "exported_at": _now().isoformat(),
        "grip": "the sink acknowledged the write — that is what makes this an external anchor",
        "external": True,
        **result,
        "boundary": (
            "an exported receipt proves the BOM set existed at that time and has not been rewritten since; it "
            "does not prove the facts inside the BOMs are correct"
        ),
    }
