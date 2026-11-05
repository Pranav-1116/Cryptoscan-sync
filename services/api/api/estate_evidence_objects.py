"""The evidence object tier: content-addressed artefacts in object storage (spec 94 §7).

The twin's evidence records live in PostgreSQL with a hash on every one. The specification
also asks for an object tier — S3, MinIO or a WORM volume — holding the *artefacts* those
records describe, with PostgreSQL keeping only the identifier and the hash.

This module is that tier, and it is deliberately small, because the interesting part is
what it refuses:

* **the address is the content.** An object is keyed by the sha256 of what its record
  *asserts*, so a read that returns different content under that address is an integrity
  failure, not a cached copy. There is no "latest" and no mutable slot. The one exclusion
  is ``observed_at`` when it is the build-time clock — hashing it would give the same
  stored discovery a new address on every read, which is the defect
  ``EstateGraph.fingerprint`` already documents; the value is archived inside the object
  and the wrapper names the exclusion.
* **a write never overwrites.** ``If-None-Match: *`` on the object store and
  ``O_CREAT|O_EXCL`` on the filesystem sink: a second store of the same content is
  reported as ``already_stored`` with the existing location. Re-storing evidence must not
  be able to change it.
* **an absent object is a tier gap.** ``not_stored`` is reported as such. It is never
  rendered as "this evidence has no artefact" — the record may simply not have been
  archived yet, and the two are different findings.
* **no credentials are invented.** With no sink configured the module raises
  ``not_configured`` and the caller reports the tier as unconfigured rather than writing
  to a temporary directory that looks like it worked.

Configuration (first match wins, and the anchor-export sink is reused so a deployment
configures one object store rather than two):

* ``EVIDENCE_OBJECT_DIR`` — an append-only directory (a mounted WORM volume, an NFS export)
* ``EVIDENCE_OBJECT_S3_BUCKET`` + ``EVIDENCE_OBJECT_S3_ACCESS_KEY`` +
  ``EVIDENCE_OBJECT_S3_SECRET_KEY``, optionally ``EVIDENCE_OBJECT_S3_REGION``,
  ``EVIDENCE_OBJECT_S3_ENDPOINT`` (MinIO/Ceph), ``EVIDENCE_OBJECT_S3_PREFIX``,
  ``EVIDENCE_OBJECT_S3_SESSION_TOKEN``
* the same values under ``ANCHOR_EXPORT_S3_*``, reusing the bucket this deployment already
  has for anchor receipts
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

from api.security.aws_sigv4 import sigv4_headers

SCHEMA = "cryptoscan.evidence-object-tier/1"

SINK_FILESYSTEM = "FILESYSTEM"
SINK_S3 = "S3"

Transport = Callable[[str, str, Mapping[str, str], bytes | None, float],
                     tuple[int, bytes, Mapping[str, str]]]


class EvidenceObjectError(RuntimeError):
    """The object could not be stored or read back honestly."""

    def __init__(self, code: str, reason: str, *, detail: Mapping[str, Any] | None = None) -> None:
        self.code = code
        self.reason = reason
        self.detail = dict(detail or {})
        super().__init__(reason)


def _default_transport(url: str, method: str, headers: Mapping[str, str], body: bytes | None,
                       timeout: float) -> tuple[int, bytes, Mapping[str, str]]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read() or b"", dict(exc.headers)


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def tier_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The configured sink, or raise. A tier with no sink is not an empty tier."""
    env = dict(os.environ if environ is None else environ)

    directory = (env.get("EVIDENCE_OBJECT_DIR") or "").strip()
    if directory:
        return {"sink": SINK_FILESYSTEM, "directory": directory}

    def _pick(name: str, default: str = "") -> str:
        return (env.get(f"EVIDENCE_OBJECT_{name}") or env.get(f"ANCHOR_EXPORT_{name}") or default).strip()

    bucket = _pick("S3_BUCKET")
    access_key = _pick("S3_ACCESS_KEY")
    secret_key = _pick("S3_SECRET_KEY")
    if bucket and access_key and secret_key:
        region = _pick("S3_REGION", "us-east-1")
        endpoint = (_pick("S3_ENDPOINT") or f"https://s3.{region}.amazonaws.com").rstrip("/")
        return {
            "sink": SINK_S3,
            "bucket": bucket,
            "region": region,
            "endpoint": endpoint,
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": _pick("S3_SESSION_TOKEN") or None,
            "prefix": (env.get("EVIDENCE_OBJECT_S3_PREFIX") or "cryptoscan/evidence").strip("/"),
        }

    raise EvidenceObjectError(
        "not_configured",
        "no evidence object tier is configured: set EVIDENCE_OBJECT_DIR, the "
        "EVIDENCE_OBJECT_S3_* triple, or the ANCHOR_EXPORT_S3_* bucket this deployment "
        "already uses. Evidence that was never archived is a tier gap, not a missing finding",
    )


def tier_status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Non-raising description of the tier, for a status surface."""
    try:
        config = tier_config(environ)
    except EvidenceObjectError as exc:
        return {
            "schema": SCHEMA,
            "configured": False,
            "sink": None,
            "reason": exc.reason,
            "note": (
                "evidence records remain in PostgreSQL with their hashes; only the artefact "
                "tier is absent, and nothing here is counted as 'no evidence'"
            ),
        }
    detail = {
        key: value for key, value in config.items()
        if key not in {"secret_key", "access_key", "session_token"}
    }
    return {
        "schema": SCHEMA,
        "configured": True,
        "sink": config["sink"],
        "detail": detail,
        "note": (
            "the address of an object is the sha256 of its own bytes; a read that returns "
            "different bytes is refused"
        ),
    }


# --------------------------------------------------------------------------- #
# canonical bytes and their address
# --------------------------------------------------------------------------- #
OBJECT_SCHEMA = "cryptoscan.evidence-object/1"

#: Fields excluded from an object's address, and why. ``observed_at`` is the clock at
#: build time when the discovery payload did not assert it, so hashing it would give the
#: same stored evidence a different address on every read — the exact defect
#: ``EstateGraph.fingerprint`` documents and avoids. The value is still archived *inside*
#: the object; it is simply not part of the address.
ADDRESS_EXCLUDED: tuple[str, ...] = ("observed_at",)


def _addressed_content(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in ADDRESS_EXCLUDED}


def content_address(record: Mapping[str, Any]) -> str:
    """The sha256 of what the record *asserts* — its content, not its build bookkeeping."""
    material = json.dumps(_addressed_content(record), sort_keys=True, separators=(",", ":"),
                          default=str).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def canonical_bytes(record: Mapping[str, Any]) -> bytes:
    """The bytes stored for one record: the content, its address, and what was excluded."""
    wrapper = {
        "schema": OBJECT_SCHEMA,
        "content": dict(record),
        "address": content_address(record),
        "address_excludes": list(ADDRESS_EXCLUDED),
    }
    return json.dumps(wrapper, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def digest_of(record: Mapping[str, Any] | bytes) -> str:
    if isinstance(record, bytes):
        return content_address(json.loads(record)["content"])
    return content_address(record)


def _object_key(prefix: str, digest: str) -> str:
    shard = f"{digest[:2]}/{digest[2:4]}"
    return f"{prefix}/{shard}/{digest}.json" if prefix else f"{shard}/{digest}.json"


# --------------------------------------------------------------------------- #
# sinks
# --------------------------------------------------------------------------- #
def _store_filesystem(body: bytes, digest: str, config: Mapping[str, Any]) -> dict[str, Any]:
    directory = os.path.join(str(config["directory"]), digest[:2], digest[2:4])
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{digest}.json")
    try:
        # O_EXCL is the whole point: a duplicate is a no-op, never a rewrite
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
    except FileExistsError:
        return {
            "stored": False,
            "already_stored": True,
            "location": path,
            "digest": digest,
            "note": "the sink already holds these bytes; an archive never rewrites evidence",
        }
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(body)
    return {"stored": True, "already_stored": False, "location": path, "digest": digest}


def _store_s3(body: bytes, digest: str, config: Mapping[str, Any],
              transport: Transport | None, timeout: float) -> dict[str, Any]:
    key = _object_key(str(config.get("prefix") or ""), digest)
    url = f"{config['endpoint']}/{config['bucket']}/{urllib.parse.quote(key, safe='/-_.~')}"
    signed = sigv4_headers(
        method="PUT", url=url, body=body, region=str(config["region"]),
        access_key=str(config["access_key"]), secret_key=str(config["secret_key"]),
        session_token=config.get("session_token"), extra_headers={"content-type": "application/json"},
    )
    headers = dict(signed)
    headers["Content-Type"] = "application/json"
    headers["Host"] = signed["host"]
    headers["If-None-Match"] = "*"

    sender = transport or _default_transport
    status, response_body, response_headers = sender(url, "PUT", headers, body, timeout)
    if status in {409, 412}:
        return {
            "stored": False,
            "already_stored": True,
            "location": url,
            "digest": digest,
            "note": "the sink already holds these bytes; an archive never rewrites evidence",
        }
    if status >= 300:
        raise EvidenceObjectError(
            "store_failed",
            f"the object store refused the write: HTTP {status}",
            detail={"location": url, "status": status,
                    "body": response_body[:400].decode("utf-8", "replace")},
        )
    return {
        "stored": True,
        "already_stored": False,
        "location": url,
        "digest": digest,
        "etag": response_headers.get("ETag") or response_headers.get("etag"),
        "object_version": (response_headers.get("x-amz-version-id")
                           or response_headers.get("X-Amz-Version-Id")),
    }


def _read_filesystem(digest: str, config: Mapping[str, Any]) -> dict[str, Any]:
    path = os.path.join(str(config["directory"]), digest[:2], digest[2:4], f"{digest}.json")
    try:
        with open(path, "rb") as handle:
            return {"body": handle.read(), "location": path}
    except FileNotFoundError:
        raise EvidenceObjectError(
            "not_stored",
            "no object with that digest is in the tier. That is a tier gap, not 'this "
            "evidence has no artefact': the record may not have been archived yet",
            detail={"digest": digest},
        )


def _read_s3(digest: str, config: Mapping[str, Any], transport: Transport | None,
             timeout: float) -> dict[str, Any]:
    key = _object_key(str(config.get("prefix") or ""), digest)
    url = f"{config['endpoint']}/{config['bucket']}/{urllib.parse.quote(key, safe='/-_.~')}"
    signed = sigv4_headers(
        method="GET", url=url, body=b"", region=str(config["region"]),
        access_key=str(config["access_key"]), secret_key=str(config["secret_key"]),
        session_token=config.get("session_token"),
    )
    headers = dict(signed)
    headers["Host"] = signed["host"]
    sender = transport or _default_transport
    status, body, _response_headers = sender(url, "GET", headers, None, timeout)
    if status == 404:
        raise EvidenceObjectError(
            "not_stored",
            "no object with that digest is in the tier. That is a tier gap, not 'this "
            "evidence has no artefact': the record may not have been archived yet",
            detail={"digest": digest, "location": url},
        )
    if status >= 300:
        raise EvidenceObjectError(
            "read_failed",
            f"the object store refused the read: HTTP {status}",
            detail={"digest": digest, "location": url, "status": status},
        )
    return {"body": body, "location": url}


# --------------------------------------------------------------------------- #
# public surface
# --------------------------------------------------------------------------- #
def store(record: Mapping[str, Any], *, transport: Transport | None = None,
          config: Mapping[str, Any] | None = None, timeout: float = 20.0) -> dict[str, Any]:
    """Archive one evidence record by content address. Idempotent, never destructive."""
    resolved = dict(config or tier_config())
    body = canonical_bytes(record)
    digest = content_address(record)
    if resolved["sink"] == SINK_FILESYSTEM:
        result = _store_filesystem(body, digest, resolved)
    elif resolved["sink"] == SINK_S3:
        result = _store_s3(body, digest, resolved, transport, timeout)
    else:  # pragma: no cover - tier_config cannot produce this
        raise EvidenceObjectError("not_configured", f"unknown sink {resolved['sink']!r}")
    return {
        "schema": SCHEMA,
        "sink": resolved["sink"],
        "bytes": len(body),
        "address": f"sha256:{digest}",
        "verified": _verify(body, digest),
        "address_excludes": list(ADDRESS_EXCLUDED),
        **result,
    }


def fetch(digest: str, *, transport: Transport | None = None,
          config: Mapping[str, Any] | None = None, timeout: float = 20.0) -> dict[str, Any]:
    """Read an object back and refuse it if the bytes are not what the digest names."""
    resolved = dict(config or tier_config())
    address = str(digest).strip().lower()
    if address.startswith("sha256:"):
        address = address[len("sha256:"):]
    if len(address) != 64 or any(character not in "0123456789abcdef" for character in address):
        raise EvidenceObjectError(
            "invalid_digest",
            "an object is addressed by a 64-character sha256; anything else is not an address",
            detail={"digest": str(digest)[:80]},
        )
    if resolved["sink"] == SINK_FILESYSTEM:
        raw = _read_filesystem(address, resolved)
    elif resolved["sink"] == SINK_S3:
        raw = _read_s3(address, resolved, transport, timeout)
    else:  # pragma: no cover
        raise EvidenceObjectError("not_configured", f"unknown sink {resolved['sink']!r}")
    body = raw["body"]
    if not _verify(body, address):
        raise EvidenceObjectError(
            "integrity_mismatch",
            "the store returned an object whose content does not hash to the address that "
            "named it. The object is refused: a tier that can return different evidence under "
            "the same name is not an archive",
            detail={"digest": address, "location": raw["location"],
                    "actual": _actual_address(body)},
        )
    try:
        wrapper = json.loads(body)
        record = wrapper["content"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:  # pragma: no cover
        raise EvidenceObjectError("unreadable_object", f"stored bytes are not an object: {exc}")
    return {
        "schema": SCHEMA,
        "sink": resolved["sink"],
        "address": f"sha256:{address}",
        "location": raw["location"],
        "verified": True,
        "bytes": len(body),
        "record": record,
    }


def _actual_address(body: bytes) -> str | None:
    try:
        return content_address(json.loads(body)["content"])
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def _verify(body: bytes, digest: str) -> bool:
    """An object is intact when the content it carries still hashes to its address."""
    return _actual_address(body) == digest


__all__ = [
    "SCHEMA",
    "SINK_FILESYSTEM",
    "SINK_S3",
    "EvidenceObjectError",
    "ADDRESS_EXCLUDED",
    "canonical_bytes",
    "content_address",
    "digest_of",
    "fetch",
    "store",
    "tier_config",
    "tier_status",
]
