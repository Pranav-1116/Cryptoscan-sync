"""Read-only 'air-gapped' mode + offline signed feed/CVE bundle import.

Deterministic (no AI). In air-gapped mode the platform must not reach external
networks; offline updates (NVD/CVE feeds, registry/advisory lists, CRL/CT
snapshots) arrive as a **signed bundle** that is verified (HMAC + hash) before
any entry is ingested. This module:

- resolves the effective mode (airgap on/off, allowed endpoints) and classifies
  a target URL as permitted or blocked (fail-closed),
- builds/verifies a signed feed bundle (manifest HMAC + per-entry sha256), and
- applies bundle contents to a feed store through an injected sink.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import tarfile
import io
from dataclasses import dataclass
from typing import Any, Iterable, Protocol

BUNDLE_FORMAT = "cryptoscan-offline-feed-v1"
# External hosts the platform would otherwise contact (blocked in airgap).
EXTERNAL_FEED_HOSTS = (
    "services.nvd.nist.gov", "crt.sh", "pypi.org", "api.osv.dev",
    "github.com", "objects.githubusercontent.com", "registry-1.docker.io",
)


class AirgapError(ValueError):
    pass


@dataclass
class AirgapPolicy:
    airgap: bool = False
    allowlist: tuple[str, ...] = ()  # hosts still permitted (e.g. internal mirror)

    def allows(self, url: str) -> bool:
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
        if not self.airgap:
            return True
        if not host:
            return False
        for allowed in self.allowlist:
            if host == allowed.lower() or host.endswith("." + allowed.lower()):
                return True
        return False


def network_decision(url: str, policy: AirgapPolicy) -> dict[str, Any]:
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
    permitted = policy.allows(url)
    is_external = any(host == h or host.endswith("." + h) for h in EXTERNAL_FEED_HOSTS)
    return {"url": url, "host": host, "airgap": policy.airgap,
            "is_external_feed": is_external, "permitted": permitted,
            "action": "ALLOW" if permitted else "BLOCK"}


# Read-only enforcement: in air-gap mode the platform must refuse MUTATING
# operations that could change estate state (active scans, connector pushes,
# outbound delivery). Reads and the offline feed import are always permitted.
_MUTATING_OPERATIONS = frozenset({
    "scan.trigger", "scan.schedule", "connector.deliver", "webhook.send",
    "ticket.create", "siem.push", "bus.publish", "chat.card.send",
    "cloud.discover", "network.probe", "backup.restore",
})
_READ_ONLY_ALLOWED = frozenset({
    "feed.import", "report.read", "audit.verify", "finding.read",
    "ot.decode", "backup.create", "dashboard.read",
    # an offline update pack arriving on media is the only way a disconnected
    # install gets new detections, so installing/removing one is not a mutation
    # that air-gap mode should block (it still never reaches the network)
    "knowledge.install", "knowledge.uninstall",
})


class AirgapReadOnlyError(PermissionError):
    pass


def enforce_operation(operation: str, policy: AirgapPolicy) -> dict[str, Any]:
    """Fail-closed guard: block mutating/networked operations when air-gapped.

    Read operations and the offline feed import remain allowed. Raises
    AirgapReadOnlyError for blocked mutations; returns a decision dict for
    allowed operations."""
    if not policy.airgap:
        return {"operation": operation, "airgap": False, "allowed": True, "action": "ALLOW"}
    if operation in _READ_ONLY_ALLOWED:
        return {"operation": operation, "airgap": True, "allowed": True, "action": "ALLOW_READONLY"}
    if operation in _MUTATING_OPERATIONS or operation.startswith(("scan.", "connector.", "send.")):
        raise AirgapReadOnlyError(
            f"operation {operation!r} blocked: platform is in read-only air-gapped mode")
    # Unknown operations default to deny in air-gap mode (fail-closed).
    raise AirgapReadOnlyError(f"operation {operation!r} not on the air-gap allowlist")


# ---------------------------------------------------------- bundle build ---- #
def build_bundle(entries: Iterable[dict[str, Any]], *, secret: str,
                 created_by: str = "offline-updater") -> dict[str, Any]:
    """Build a signed offline feed bundle.

    Each entry: {"feed":"nvd|osv|registry|ct|crl", "id":..., "payload":{...}}.
    The manifest lists per-entry sha256; the whole manifest is HMAC-signed.
    """
    items = []
    manifest_entries = []
    for e in entries:
        raw = json.dumps(e, sort_keys=True, default=str).encode()
        items.append(raw)
        manifest_entries.append({"feed": e.get("feed"), "id": e.get("id"),
                                 "sha256": hashlib.sha256(raw).hexdigest()})
    tar = _pack(items)
    manifest = {
        "format": BUNDLE_FORMAT,
        "created_by": created_by,
        "entry_count": len(manifest_entries),
        "bundle_sha256": hashlib.sha256(tar).hexdigest(),
        "entries": manifest_entries,
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["signature"] = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    return {"manifest": manifest, "tar_b64": __import__("base64").b64encode(tar).decode()}


def _pack(items: list[bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i, raw in enumerate(items):
            info = tarfile.TarInfo(f"entry-{i:06d}.json")
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def _unpack(tar_blob: bytes) -> list[bytes]:
    out = []
    with tarfile.open(fileobj=io.BytesIO(tar_blob), mode="r") as tf:
        for m in sorted(tf.getmembers(), key=lambda m: m.name):
            f = tf.extractfile(m)
            out.append(f.read() if f else b"")
    return out


# --------------------------------------------------------- bundle verify ---- #
class FeedSink(Protocol):
    def upsert_feed(self, feed: str, entry_id: str, payload: dict) -> int: ...
    def finalize(self, applied: int) -> None: ...


def import_bundle(bundle: dict[str, Any], *, secret: str, sink: FeedSink,
                  require_airgap: bool = False) -> dict[str, Any]:
    """Verify signature + hashes, then apply entries via the sink. Fail-closed."""
    import base64

    manifest = bundle.get("manifest") or {}
    if manifest.get("format") != BUNDLE_FORMAT:
        raise AirgapError("unsupported bundle format")
    signature = manifest.get("signature")
    body = {k: v for k, v in manifest.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if not signature or not hmac.compare_digest(
        hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest(), signature
    ):
        raise AirgapError("bundle signature verification failed — refusing import")

    try:
        tar_blob = base64.b64decode(bundle["tar_b64"])
    except Exception as exc:  # noqa: BLE001
        raise AirgapError("bundle payload is not valid base64") from exc
    if hashlib.sha256(tar_blob).hexdigest() != manifest.get("bundle_sha256"):
        raise AirgapError("bundle archive hash mismatch (corrupt/tampered)")

    items = _unpack(tar_blob)
    if len(items) != len(manifest["entries"]):
        raise AirgapError("entry count does not match manifest")

    applied = 0
    feeds: dict[str, int] = {}
    for meta, raw in zip(manifest["entries"], items):
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise AirgapError(f"entry {meta.get('id')} hash mismatch — aborting import")
        entry = json.loads(raw)
        n = sink.upsert_feed(meta["feed"], meta["id"], entry.get("payload", entry))
        applied += 1
        feeds[meta["feed"]] = feeds.get(meta["feed"], 0) + (n or 1)
    sink.finalize(applied)
    return {"imported": applied, "by_feed": feeds, "status": "APPLIED",
            "require_airgap": require_airgap}


class InMemoryFeedSink:
    """Deterministic sink for tests/offline import staging."""

    def __init__(self):
        self.feeds: dict[str, dict] = {}

    def upsert_feed(self, feed: str, entry_id: str, payload: dict) -> int:
        bucket = self.feeds.setdefault(feed, {})
        new = entry_id not in bucket
        bucket[entry_id] = payload
        return 1 if new else 0

    def finalize(self, applied: int) -> None:
        self.applied = applied
