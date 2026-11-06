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
* ``EVIDENCE_OBJECT_S3_BUCKET`` + ``EVIDENCE_OBJECT_S3_ACCESS_KEY_FILE`` +
  ``EVIDENCE_OBJECT_S3_SECRET_KEY_FILE`` (required in production), optionally
  ``EVIDENCE_OBJECT_S3_REGION``, ``EVIDENCE_OBJECT_S3_ENDPOINT`` (MinIO/Ceph),
  ``EVIDENCE_OBJECT_S3_PREFIX``, ``EVIDENCE_OBJECT_S3_SESSION_TOKEN_FILE``. The
  default key prefix is ``tenants/<tenant>/evidence``. Legacy inline credentials
  remain development-only.
* the same values under ``ANCHOR_EXPORT_S3_*``, reusing the bucket this deployment already
  has for anchor receipts
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

from api.security.aws_sigv4 import sigv4_headers

SCHEMA = "cryptoscan.evidence-object-tier/1"
MAX_OBJECT_BYTES = 64 * 1024 * 1024

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
    ca_bundle = (os.environ.get("EVIDENCE_OBJECT_S3_CA_BUNDLE") or
                 os.environ.get("SBOM_S3_CA_BUNDLE") or "").strip()
    try:
        context = ssl.create_default_context(cafile=ca_bundle or None) if url.startswith("https://") else None
    except OSError as exc:
        raise EvidenceObjectError("invalid_endpoint", "bank evidence CA bundle could not be loaded") from exc
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return int(response.status), response.read(MAX_OBJECT_BYTES + 1), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(4096) or b"", dict(exc.headers)
    except (urllib.error.URLError, OSError) as exc:
        raise EvidenceObjectError("transport_unavailable", "bank evidence store is unreachable") from exc


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def _credential_file(path: str) -> str:
    file = Path(path)
    try:
        if not file.is_absolute() or file.is_symlink() or not file.is_file() or not 0 < file.stat().st_size <= 512:
            raise EvidenceObjectError("invalid_credential", "bank evidence credential file is absent or unsafe")
        value = file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise EvidenceObjectError("invalid_credential", "bank evidence credential file cannot be read") from exc
    if not value or "\n" in value or "\r" in value:
        raise EvidenceObjectError("invalid_credential", "bank evidence credential file is malformed")
    return value


def tier_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The configured sink, or raise. A tier with no sink is not an empty tier."""
    env = dict(os.environ if environ is None else environ)

    directory = (env.get("EVIDENCE_OBJECT_DIR") or "").strip()
    if directory:
        return {"sink": SINK_FILESYSTEM, "directory": directory}

    def _pick(name: str, default: str = "") -> str:
        return (env.get(f"EVIDENCE_OBJECT_{name}") or env.get(f"ANCHOR_EXPORT_{name}") or default).strip()

    bucket = _pick("S3_BUCKET")
    access_file = _pick("S3_ACCESS_KEY_FILE")
    secret_file = _pick("S3_SECRET_KEY_FILE")
    session_file = _pick("S3_SESSION_TOKEN_FILE")
    inline_session = _pick("S3_SESSION_TOKEN")
    from shared_config import environment as platform_environment

    effective = (platform_environment.environment_name() if environ is None else
                 platform_environment.environment_name(environ=env))
    production = effective == "production"
    ca_bundle = (env.get("EVIDENCE_OBJECT_S3_CA_BUNDLE") or env.get("SBOM_S3_CA_BUNDLE") or "").strip()
    if production and bucket and (not access_file or not secret_file or (inline_session and not session_file)):
        raise EvidenceObjectError("invalid_credential", "production evidence S3 needs credential files")
    if production and bucket and (not ca_bundle or not Path(ca_bundle).is_absolute()
                                  or not Path(ca_bundle).is_file()):
        raise EvidenceObjectError("invalid_endpoint", "production evidence S3 needs a bank-trusted CA bundle")
    access_key = _credential_file(access_file) if access_file else _pick("S3_ACCESS_KEY")
    secret_key = _credential_file(secret_file) if secret_file else _pick("S3_SECRET_KEY")
    session_token = _credential_file(session_file) if session_file else inline_session or None
    if bucket and access_key and secret_key:
        region = _pick("S3_REGION", "us-east-1")
        endpoint = (_pick("S3_ENDPOINT") or f"https://s3.{region}.amazonaws.com").rstrip("/")
        try:
            parsed = urllib.parse.urlsplit(endpoint)
            _ = parsed.port
        except ValueError as exc:
            raise EvidenceObjectError("invalid_endpoint", "bank evidence endpoint is malformed") from exc
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"} or (parsed.scheme != "https" and not (
                    local and effective in {"development", "test"}))):
            raise EvidenceObjectError("invalid_endpoint", "bank evidence S3 needs HTTPS; HTTP is local-only")
        return {
            "sink": SINK_S3,
            "bucket": bucket,
            "region": region,
            "endpoint": endpoint,
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": session_token,
            "ca_bundle": ca_bundle or None,
            "prefix": (env.get("EVIDENCE_OBJECT_S3_PREFIX") or "tenants").strip("/"),
        }

    raise EvidenceObjectError(
        "not_configured",
        "no evidence object tier is configured: set EVIDENCE_OBJECT_DIR, the "
        "EVIDENCE_OBJECT_S3_* triple, or the ANCHOR_EXPORT_S3_* bucket this deployment "
        "already uses. Evidence that was never archived is a tier gap, not a missing finding",
    )


def scoped_config(config: Mapping[str, Any], tenant_id: str | None) -> dict[str, Any]:
    """Keep identical evidence addresses in separate tenant storage namespaces."""
    tenant = str(tenant_id or "platform")
    if not tenant or len(tenant) > 80 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for character in tenant):
        raise EvidenceObjectError("invalid_tenant", "evidence object tenant scope is invalid")
    scoped = dict(config)
    if scoped["sink"] == SINK_FILESYSTEM:
        scoped["directory"] = os.path.join(str(scoped["directory"]), "tenants", tenant)
    elif scoped["sink"] == SINK_S3:
        prefix = str(scoped.get("prefix") or "").strip("/")
        scoped["prefix"] = (f"tenants/{tenant}/evidence" if prefix == "tenants" else
                            "/".join(part for part in (prefix, "tenants", tenant) if part))
    else:
        raise EvidenceObjectError("not_configured", "unknown evidence object sink")
    return scoped


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
            "the address hashes asserted content but excludes the build-time observed_at clock; "
            "a new write requires exact-byte readback, and an existing key is verified before retry"
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
        existing = _read_filesystem(digest, config)["body"]
        if not _verify(existing, digest):
            raise EvidenceObjectError("integrity_mismatch", "the existing evidence object is corrupt")
        return {
            "stored": False,
            "already_stored": True,
            "location": path,
            "digest": digest,
            "retained_bytes": len(existing),
            "note": "the sink already holds this addressed content; its original clock is retained",
        }
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
    existing = _read_filesystem(digest, config)["body"]
    if existing != body:
        raise EvidenceObjectError("integrity_mismatch", "filesystem write failed exact-byte readback")
    return {"stored": True, "already_stored": False, "location": path, "digest": digest,
            "retained_bytes": len(existing)}


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
        existing = _read_s3(digest, config, transport, timeout)["body"]
        if not _verify(existing, digest):
            raise EvidenceObjectError("integrity_mismatch", "the existing evidence object is corrupt")
        return {
            "stored": False,
            "already_stored": True,
            "location": url,
            "digest": digest,
            "retained_bytes": len(existing),
            "note": "the sink already holds this addressed content; its original clock is retained",
        }
    if status >= 300:
        raise EvidenceObjectError(
            "store_failed",
            f"the object store refused the write: HTTP {status}",
            detail={"location": url, "status": status,
                    "body": response_body[:400].decode("utf-8", "replace")},
        )
    returned = _read_s3(digest, config, transport, timeout)["body"]
    if returned != body:
        raise EvidenceObjectError("integrity_mismatch", "object write failed exact-byte readback")
    return {
        "stored": True,
        "already_stored": False,
        "location": url,
        "digest": digest,
        "retained_bytes": len(returned),
        "etag": response_headers.get("ETag") or response_headers.get("etag"),
        "object_version": (response_headers.get("x-amz-version-id")
                           or response_headers.get("X-Amz-Version-Id")),
    }


def _read_filesystem(digest: str, config: Mapping[str, Any]) -> dict[str, Any]:
    path = os.path.join(str(config["directory"]), digest[:2], digest[2:4], f"{digest}.json")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            body = handle.read(MAX_OBJECT_BYTES + 1)
    except FileNotFoundError as exc:
        raise EvidenceObjectError(
            "not_stored",
            "no object with that digest is in the tier. That is a tier gap, not 'this "
            "evidence has no artefact': the record may not have been archived yet",
            detail={"digest": digest},
        ) from exc
    except OSError as exc:
        raise EvidenceObjectError("read_failed", "the evidence object could not be opened safely") from exc
    if len(body) > MAX_OBJECT_BYTES:
        raise EvidenceObjectError("read_failed", "evidence object exceeds the bounded read")
    return {"body": body, "location": path}


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
    if len(body) > MAX_OBJECT_BYTES:
        raise EvidenceObjectError("read_failed", "evidence object exceeds the bounded read")
    return {"body": body, "location": url}


# --------------------------------------------------------------------------- #
# public surface
# --------------------------------------------------------------------------- #
def store(record: Mapping[str, Any], *, transport: Transport | None = None,
          config: Mapping[str, Any] | None = None, timeout: float = 20.0) -> dict[str, Any]:
    """Archive one evidence record by content address. Idempotent, never destructive."""
    resolved = dict(config or tier_config())
    body = canonical_bytes(record)
    if len(body) > MAX_OBJECT_BYTES:
        raise EvidenceObjectError("store_failed", "evidence object exceeds the bounded write")
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
        "bytes": result.pop("retained_bytes"),
        "address": f"sha256:{digest}",
        "verified": True,
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
    """Require the expected envelope as well as the addressed content."""
    try:
        wrapper = json.loads(body)
        return (isinstance(wrapper, dict) and wrapper.get("schema") == OBJECT_SCHEMA
                and wrapper.get("address") == digest
                and wrapper.get("address_excludes") == list(ADDRESS_EXCLUDED)
                and isinstance(wrapper.get("content"), dict)
                and content_address(wrapper["content"]) == digest)
    except (json.JSONDecodeError, TypeError, ValueError, KeyError):
        return False


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
