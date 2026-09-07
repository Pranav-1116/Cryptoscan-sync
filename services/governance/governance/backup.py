"""Automated encrypted backup, point-in-time restore, and retention/purge.

Deterministic (no AI). Backups are produced by a pluggable backend (Postgres
pg_dump-style or Neo4j neo4j-admin-style; tests inject a fake). The platform
wraps each artifact with:
- authenticated encryption (Fernet-like AES via the `cryptography` package when
  available; otherwise a deterministic, dependency-free AESGCM shim is NOT
  attempted — we require the real cryptography primitive so encryption is never
  toy crypto), and
- a signed manifest (HMAC) binding archive contents, engine, timestamp and
  sequence so restore can verify integrity before it touches a database.

Retention implements a grandfather-father-son + age policy and is pure.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import tarfile
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol

from cryptography.fernet import Fernet, InvalidToken


class BackupError(ValueError):
    pass


# ---------------------------------------------------------------- backend --- #
class BackupBackend(Protocol):
    """Pluggable DB engine. ``dump`` returns raw bytes for a DB id; ``restore``
    applies bytes to a target."""

    name: str

    def dump(self, database_id: str) -> bytes: ...
    def restore(self, database_id: str, payload: bytes) -> dict[str, Any]: ...


@dataclass
class BackupArtifact:
    backup_id: str
    database_id: str
    engine: str
    created_at: str
    sequence: int
    point_in_time: str
    size_bytes: int
    sha256: str
    manifest_sig: str


# --------------------------------------------------------------- create ----- #
def create_backup(
    *,
    backend: BackupBackend,
    database_id: str,
    encryption_key: bytes,
    signing_secret: str,
    now: dt.datetime | None = None,
    sequence: int = 1,
    wal_tail: bytes | None = None,
) -> dict[str, Any]:
    """Dump, encrypt (Fernet/AES), and produce a signed manifest.

    ``wal_tail`` simulates the write-ahead-log tail needed for PITR; it is
    bundled with the base dump inside the tar and recorded in the manifest.
    """
    ref = now or dt.datetime.now(dt.timezone.utc)
    ts = ref.isoformat()
    raw = backend.dump(database_id)
    sha = hashlib.sha256(raw).hexdigest()

    tar_path = _bundle_tar(database_id, raw, wal_tail or b"", ts)
    fernet = Fernet(encryption_key)
    ciphertext = fernet.encrypt(tar_path)

    # Include the timestamp in the id so identical dump content at different
    # times still yields a unique backup id (retention tracks each artifact).
    manifest = {
        "backup_id": f"bk-{sha[:12]}-{sequence}-{ts.replace('-', '').replace(':', '').replace('+00:00', 'Z')}",
        "database_id": database_id,
        "engine": getattr(backend, "name", "unknown"),
        "created_at": ts,
        "sequence": sequence,
        "point_in_time": ts,
        "plaintext_sha256": sha,
        "archive_sha256": hashlib.sha256(tar_path).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "size_bytes": len(raw),
        "has_wal_tail": wal_tail is not None,
        "format": "cryptoscan-backup-v1",
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["signature"] = hmac.new(signing_secret.encode(), canonical, hashlib.sha256).hexdigest()
    return {"manifest": manifest, "ciphertext": ciphertext, "plaintext_preview_sha": sha}


def _bundle_tar(database_id: str, raw: bytes, wal: bytes, ts: str) -> bytes:
    import io

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for arcname, data in (("dump.bin", raw), ("wal.bin", wal),
                              ("meta.json", json.dumps({"database_id": database_id, "ts": ts}).encode())):
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --------------------------------------------------------------- restore ---- #
def restore_backup(
    *,
    backend: BackupBackend,
    database_id: str,
    ciphertext: bytes,
    manifest: dict[str, Any],
    encryption_key: bytes,
    signing_secret: str,
    target_point_in_time: str | None = None,
) -> dict[str, Any]:
    """Verify signature + integrity, decrypt, replay (base + optional WAL to a
    PIT), then restore through the backend. Fail-closed on any mismatch."""
    sig = manifest.get("signature")
    body = {k: v for k, v in manifest.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if not sig or not hmac.compare_digest(
        hmac.new(signing_secret.encode(), canonical, hashlib.sha256).hexdigest(), sig
    ):
        raise BackupError("manifest signature verification failed — refusing to restore")
    if manifest.get("ciphertext_sha256") != hashlib.sha256(ciphertext).hexdigest():
        raise BackupError("ciphertext hash does not match manifest (corrupt/tampered)")

    try:
        plain = Fernet(encryption_key).decrypt(ciphertext)
    except InvalidToken as exc:
        raise BackupError("decryption failed (wrong key or corrupt archive)") from exc

    if manifest.get("archive_sha256") != hashlib.sha256(plain).hexdigest():
        raise BackupError("decrypted archive hash mismatch")

    dump, wal, meta = _unbundle_tar(plain)
    if manifest.get("plaintext_sha256") != hashlib.sha256(dump).hexdigest():
        raise BackupError("dump payload hash mismatch after decrypt")

    pit = target_point_in_time or manifest.get("point_in_time")
    result = backend.restore(database_id, dump)
    applied_wal = False
    if wal and target_point_in_time:
        # PITR: backend replays WAL up to the requested point when supported
        replay = getattr(backend, "replay_wal", None)
        if callable(replay):
            result = replay(database_id, wal, target_point_in_time)
            applied_wal = True
    return {"restored": True, "database_id": database_id, "engine": manifest.get("engine"),
            "point_in_time": pit, "wal_applied": applied_wal,
            "size_bytes": len(dump), "backend_result": result}


def _unbundle_tar(blob: bytes) -> tuple[bytes, bytes, dict]:
    import io

    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r") as tf:
        for member in tf.getmembers():
            f = tf.extractfile(member)
            out[member.name] = f.read() if f else b""
    meta = json.loads(out.get("meta.json", b"{}").decode() or "{}")
    return out.get("dump.bin", b""), out.get("wal.bin", b""), meta


# --------------------------------------------------------------- retention -- #
DEFAULT_RETENTION = {"daily_keep_days": 14, "weekly_keep_weeks": 8,
                     "monthly_keep_months": 12, "yearly_keep_years": 3}


def classify_backup(created_at: dt.datetime, *, now: dt.datetime | None = None) -> str:
    """GFS tier: daily/weekly(anchor day)/monthly(anchor)/yearly(anchor)."""
    ref = now or dt.datetime.now(dt.timezone.utc)
    d = created_at.astimezone(dt.timezone.utc)
    age_days = (ref.date() - d.date()).days
    if d.month == 1 and d.day == 1:
        return "yearly"
    if d.day == 1:
        return "monthly"
    if d.weekday() == 6:  # Sunday anchor
        return "weekly"
    return "daily"


def apply_retention(
    backups: Iterable[dict[str, Any]],
    *,
    now: dt.datetime | None = None,
    policy: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Decide which backups to keep/purge under GFS + age limits (pure)."""
    ref = now or dt.datetime.now(dt.timezone.utc)
    pol = {**DEFAULT_RETENTION, **(policy or {})}
    keep, purge = [], []
    for b in backups:
        created = _dt(b.get("created_at"))
        if created is None:
            purge.append({"backup_id": b.get("backup_id"), "reason": "unparseable timestamp"})
            continue
        tier = classify_backup(created, now=ref)
        age_days = (ref.date() - created.astimezone(dt.timezone.utc).date()).days
        limit_days = {
            "daily": pol["daily_keep_days"],
            "weekly": pol["weekly_keep_weeks"] * 7,
            "monthly": pol["monthly_keep_months"] * 31,
            "yearly": pol["yearly_keep_years"] * 366,
        }[tier]
        decision = "keep" if age_days <= limit_days else "purge"
        (keep if decision == "keep" else purge).append({
            "backup_id": b.get("backup_id"), "tier": tier,
            "age_days": age_days, "limit_days": limit_days,
            **({"reason": f"older than {tier} retention ({limit_days}d)"} if decision == "purge" else {}),
        })
    return {"policy": pol, "kept": len(keep), "purged": len(purge),
            "keep": keep, "purge": purge}


def _dt(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, str):
        try:
            p = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return p if p.tzinfo else p.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            return None
    return None


def generate_encryption_key() -> bytes:
    """Fernet key (urlsafe base64 of 32 random bytes)."""
    return Fernet.generate_key()
