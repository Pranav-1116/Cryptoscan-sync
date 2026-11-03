"""Bank-owned S3/MinIO backend for already-sealed SBOM/BOM artifact bytes.

PostgreSQL/evidence manifests remain authoritative. This store holds bytes under
tenant-prefixed keys, checks every write by reading it back, and refuses a retry
that would replace different bytes at the same key. Versioning is required but
is not WORM, a second site, or bank backup qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import ClientError

from devsecops.artifact_crypto import ArtifactCryptoError, normalize_tenant
from devsecops.artifact_store import StorageRefused

MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFESTS = 10000
_PROBE_KEY = ".cryptoscan/probe/v1"
_PROBE = b"cryptoscan-bank-owned-artifact-store-probe-v1"
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _credential(path: str) -> str:
    file = Path(path)
    try:
        if not file.is_file() or file.is_symlink() or file.stat().st_size > 512:
            raise StorageRefused("Bank object-store credential file is absent, linked or oversized")
        value = file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise StorageRefused("Bank object-store credential file cannot be read") from exc
    if not value or "\n" in value or "\r" in value:
        raise StorageRefused("Bank object-store credential file is empty or malformed")
    return value


def _key(value: str) -> str:
    key = str(value)
    if (not key.startswith("tenants/") or len(key) > 512
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", key)
            or any(part in {"", ".", ".."} for part in key.split("/"))):
        raise StorageRefused("Artifact key is not an exact tenant-prefixed object identity")
    return key


def _manifest_key(key: str, manifest: dict) -> str:
    identity = _key(key)
    bucket = identity.split("/", 2)[1]
    try:
        tenant = normalize_tenant(manifest.get("tenant_id"))
    except ArtifactCryptoError as exc:
        raise StorageRefused("Bank manifest tenant identity is invalid") from exc
    if (manifest.get("storage_key") != identity
            or manifest.get("tenant_bucket", bucket) != bucket or tenant != bucket):
        raise StorageRefused("Bank manifest identity does not match its tenant object key")
    return identity


def _config(environment: str) -> dict[str, str] | None:
    endpoint = os.getenv("SBOM_S3_ENDPOINT", "").strip()
    if not endpoint:
        return None
    try:
        parsed = urlsplit(endpoint)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        _ = parsed.port  # validate malformed/out-of-range ports before creating a client
    except ValueError as exc:
        raise StorageRefused("Bank object-store endpoint is malformed") from exc
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}
            or (parsed.scheme != "https" and not (local and environment in {"test", "dev", "development", "local", "ci"}))):
        raise StorageRefused("Bank object-store endpoint requires HTTPS; HTTP is loopback development only")
    bucket = os.getenv("SBOM_S3_BUCKET", "").strip()
    access = os.getenv("SBOM_S3_ACCESS_KEY_FILE", "").strip()
    secret = os.getenv("SBOM_S3_SECRET_KEY_FILE", "").strip()
    if not _BUCKET.fullmatch(bucket) or not access or not secret:
        raise StorageRefused("Versioned bank S3 bucket and credential-file paths must be configured")
    ca = os.getenv("SBOM_S3_CA_BUNDLE", "").strip()
    if environment == "production" and (not ca or not Path(ca).is_file()):
        raise StorageRefused("Production S3 endpoint needs a bank-trusted CA bundle")
    return {"endpoint": endpoint.rstrip("/"), "bucket": bucket, "access": access,
            "secret": secret, "ca": ca, "region": os.getenv("SBOM_S3_REGION", "us-east-1")}


class S3ArtifactStorage:
    def __init__(self, config: dict[str, str]):
        import boto3

        self.bucket = config["bucket"]
        self.client = boto3.client(
            "s3", endpoint_url=config["endpoint"], region_name=config["region"],
            aws_access_key_id=_credential(config["access"]),
            aws_secret_access_key=_credential(config["secret"]),
            verify=config["ca"] or True,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                          retries={"max_attempts": 1}, connect_timeout=3, read_timeout=10),
        )
        try:
            self.client.head_bucket(Bucket=self.bucket)
            if self.client.get_bucket_versioning(Bucket=self.bucket).get("Status") != "Enabled":
                raise StorageRefused("Bank artifact bucket versioning is not enabled")
        except StorageRefused:
            raise
        except Exception as exc:
            raise StorageRefused("Bank object store is unavailable or unauthorized") from exc

    def _read(self, key: str, limit: int) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            if int(response.get("ContentLength", limit + 1)) > limit:
                response["Body"].close()
                raise StorageRefused("Artifact exceeds the bounded object read")
            with response["Body"] as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise StorageRefused("Artifact exceeds the bounded object read")
            expected = (response.get("Metadata") or {}).get("sha256")
            if expected != hashlib.sha256(data).hexdigest():
                raise StorageRefused("Object bytes disagree with their stored SHA-256")
            return data
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchKey", "NotFound"}:
                raise FileNotFoundError(f"bank artifact not found: {key}") from exc
            raise StorageRefused("Bank object read failed") from exc
        except StorageRefused:
            raise
        except Exception as exc:
            raise StorageRefused("Bank object read failed") from exc

    def _put(self, key: str, blob: bytes, limit: int) -> None:
        if not isinstance(blob, bytes) or not 0 < len(blob) <= limit:
            raise StorageRefused("Artifact is empty, unbounded or not bytes")
        digest = hashlib.sha256(blob).hexdigest()
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"404", "NoSuchKey", "NotFound"}:
                raise StorageRefused("Bank object identity could not be checked") from exc
        except Exception as exc:
            raise StorageRefused("Bank object identity could not be checked") from exc
        else:
            if self._read(key, limit) != blob:
                raise StorageRefused("Artifact key already holds different bytes; refusing replacement")
            return
        try:
            self.client.put_object(Bucket=self.bucket, Key=key, Body=blob,
                                   Metadata={"sha256": digest}, ContentType="application/octet-stream",
                                   IfNoneMatch="*")
        except ClientError as exc:
            # A concurrent writer may have won the key. Verify its exact bytes;
            # never overwrite it or claim success on a conflicting version.
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"PreconditionFailed", "412", "ConditionalRequestConflict", "409"}:
                raise StorageRefused("Bank object write failed") from exc
            if self._read(key, limit) != blob:
                raise StorageRefused("Concurrent artifact write conflicts with retained bytes") from exc
        except Exception as exc:
            raise StorageRefused("Bank object write failed") from exc
        if self._read(key, limit) != blob:
            raise StorageRefused("Bank object write did not survive exact-byte readback")

    def probe(self) -> None:
        self._put(_PROBE_KEY, _PROBE, len(_PROBE))

    def put(self, key: str, blob: bytes) -> None:
        self._put(_key(key), blob, MAX_OBJECT_BYTES)

    def put_manifest(self, key: str, manifest: dict) -> None:
        identity = _manifest_key(key, manifest)
        raw = json.dumps(manifest, sort_keys=True, default=str).encode("utf-8")
        self._put(identity + ".manifest.json", raw, MAX_MANIFEST_BYTES)

    def get(self, key: str) -> bytes:
        return self._read(_key(key), MAX_OBJECT_BYTES)

    def list_manifests(self) -> list[dict]:
        rows: list[dict] = []
        token = None
        while True:
            kwargs = {"Bucket": self.bucket, "Prefix": "tenants/", "MaxKeys": 1000}
            if token:
                kwargs["ContinuationToken"] = token
            try:
                page = self.client.list_objects_v2(**kwargs)
            except Exception as exc:
                raise StorageRefused("Bank manifest listing failed") from exc
            for entry in page.get("Contents") or []:
                name = str(entry.get("Key") or "")
                if not name.endswith(".manifest.json"):
                    continue
                identity = _key(name[:-len(".manifest.json")])
                try:
                    manifest = json.loads(self._read(name, MAX_MANIFEST_BYTES))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise StorageRefused("Bank manifest is not valid JSON") from exc
                if not isinstance(manifest, dict):
                    raise StorageRefused("Bank manifest is not a JSON object")
                _manifest_key(identity, manifest)
                rows.append(dict(manifest))
                if len(rows) > MAX_MANIFESTS:
                    raise StorageRefused("Bank manifest list exceeds review budget")
            if not page.get("IsTruncated"):
                return sorted(rows, key=lambda item: item["storage_key"])
            token = page.get("NextContinuationToken")
            if not token:
                raise StorageRefused("Bank manifest pagination is incomplete")

    def delete(self, key: str) -> None:
        _key(key)
        raise StorageRefused("Evidence deletion requires a separately reviewed retention workflow")


def from_environment(environment: str) -> S3ArtifactStorage | None:
    config = _config(environment)
    return S3ArtifactStorage(config) if config else None
