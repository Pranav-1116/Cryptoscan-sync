"""Live CBOM service: continuously versioned, signed, hash-chained CBOMs.

- Current CBOM per system + full version history (JSONL, one line per
  version — the S3-WORM story is a bucket-upload of the same lines).
- Every version is compact-JWS signed (HS256, stdlib HMAC — the JWS compact
  serialization) and hash-chained to the previous version: tampering with
  any historical version breaks every later chain verification.
- Diff between any two versions is deterministic (added/removed/changed).
- Freshness metric: seconds since last update, with an honest stale flag
  against the configured threshold — never fabricated freshness.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from eventstream.envelope import canonical_bytes

_DEFAULT_SECRET = "dev-cbom-secret-0123456789abcdef"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jws_sign(payload: dict[str, Any], secret: str) -> str:
    """Compact JWS (HS256): base64url(header).base64url(payload).sig"""
    header = {"alg": "HS256", "typ": "JWS"}
    signing = _b64u(canonical_bytes(header)) + "." + _b64u(canonical_bytes(payload))
    sig = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    return signing + "." + _b64u(sig)


def jws_verify(token: str, secret: str) -> bool:
    try:
        h, p, s = token.split(".")
        signing = f"{h}.{p}"
        expected = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))):
            return False
        json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        return True
    except Exception:
        return False


def version_hash(doc: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256((canonical_bytes(doc) + prev_hash.encode()).decode().encode()).hexdigest()


class LiveCbomService:
    def __init__(self, store_dir: str | os.PathLike[str], *, secret: str | None = None,
                 stale_after_seconds: int = 3600):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        configured_secret = secret or os.environ.get("CBOM_SIGNING_SECRET")
        if (os.environ.get("ENVIRONMENT", "").strip().lower() == "production"
                and (not configured_secret or configured_secret == _DEFAULT_SECRET)):
            raise RuntimeError("CBOM_SIGNING_SECRET is required in production; refusing the development signing key")
        self.secret = configured_secret or _DEFAULT_SECRET
        self.stale_after_seconds = stale_after_seconds
        self._current: dict[str, dict[str, Any]] = {}
        self._load()

    # ---------------------------------------------------------------- storage

    def _path(self, system_id: str) -> Path:
        safe = "".join(ch for ch in system_id if ch.isalnum() or ch in "-_.") or "default"
        return self.store_dir / f"{safe}.jsonl"

    def _load(self) -> None:
        for path in self.store_dir.glob("*.jsonl"):
            last = None
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = json.loads(line)
            if last:
                self._current[last["system_id"]] = last

    # ---------------------------------------------------------------- versions

    def update(self, system_id: str, assets: list[dict[str, Any]]) -> dict[str, Any]:
        """Fold the current asset set into a new signed, chained version."""
        prev = self._current.get(system_id)
        version_no = int(prev["version_no"]) + 1 if prev else 1
        prev_hash = prev["version_hash"] if prev else "0" * 64
        doc = {
            "system_id": system_id,
            "version_no": version_no,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "asset_count": len(assets),
            "assets": sorted(
                assets,
                key=lambda a: (str(a.get("kind")), str(a.get("endpoint")), str(a.get("cert_fingerprint"))),
            ),
        }
        vh = version_hash(doc, prev_hash)
        record = {
            "system_id": system_id,
            "version_no": version_no,
            "generated_at": doc["generated_at"],
            "version_hash": vh,
            "prev_hash": prev_hash,
            "asset_count": doc["asset_count"],
            "jws": jws_sign({"system_id": system_id, "version_no": version_no,
                             "generated_at": doc["generated_at"], "version_hash": vh},
                            self.secret),
            "doc": doc,
        }
        with self._path(system_id).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        self._current[system_id] = record
        return record

    def list_systems(self) -> list[str]:
        """System ids with at least one versioned CBOM on disk."""
        if not self.store_dir.exists():
            return []
        return sorted(path.stem for path in self.store_dir.glob("*.jsonl"))

    def current(self, system_id: str) -> dict[str, Any] | None:
        rec = self._current.get(system_id)
        if rec is None:
            return None
        age = int(time.time() - time.mktime(time.strptime(rec["generated_at"], "%Y-%m-%dT%H:%M:%SZ")))
        rec = dict(rec)
        rec["freshness"] = {"seconds_since_update": age,
                            "stale_after_seconds": self.stale_after_seconds,
                            "stale": age > self.stale_after_seconds}
        return rec

    def verify_chain(self, system_id: str) -> dict[str, Any]:
        """Re-verify signatures + the hash chain from the beginning of time."""
        path = self._path(system_id)
        if not path.exists():
            return {"system_id": system_id, "versions": 0, "chain_valid": True}
        prev = "0" * 64
        versions = 0
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                versions += 1
                if not jws_verify(rec["jws"], self.secret):
                    return {"system_id": system_id, "versions": versions,
                            "chain_valid": False, "broke_at": rec["version_no"],
                            "reason": "signature"}
                expected = version_hash(rec["doc"], prev)
                if expected != rec["version_hash"] or rec["prev_hash"] != prev:
                    return {"system_id": system_id, "versions": versions,
                            "chain_valid": False, "broke_at": rec["version_no"],
                            "reason": "chain"}
                prev = rec["version_hash"]
        return {"system_id": system_id, "versions": versions, "chain_valid": True}

    def load_version(self, system_id: str, version_no: int) -> dict[str, Any] | None:
        path = self._path(system_id)
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    if rec["version_no"] == version_no:
                        return rec
        return None

    def diff(self, system_id: str, from_no: int, to_no: int) -> dict[str, Any] | None:
        a, b = self.load_version(system_id, from_no), self.load_version(system_id, to_no)
        if a is None or b is None:
            return None

        def index(rec: dict[str, Any]) -> dict[tuple, dict]:
            return {(str(x.get("kind")), str(x.get("endpoint")), str(x.get("cert_fingerprint"))): x
                    for x in rec["doc"]["assets"]}

        ia, ib = index(a), index(b)
        added = [ib[k] for k in ib.keys() - ia.keys()]
        removed = [ia[k] for k in ia.keys() - ib.keys()]
        changed = [
            {"before": ia[k], "after": ib[k]}
            for k in ia.keys() & ib.keys()
            if canonical_bytes(ia[k]) != canonical_bytes(ib[k])
        ]
        return {"system_id": system_id, "from": from_no, "to": to_no,
                "added": added, "removed": removed, "changed": changed}

    def systems(self) -> list[str]:
        return sorted(self._current)


class CbomProjector:
    """Folds normalized-events into per-system live CBOMs (consumer group
    'cbom-service'). An update is only written when the asset set actually
    changed — version count is honest, not per-event spam."""

    CONSUMER = "cbom-service"

    def __init__(self, bus: Any, service: LiveCbomService):
        self.bus = bus
        self.service = service
        self.assets: dict[str, dict[str, dict[str, Any]]] = {}

    VOLATILE = ("observed_at", "source")

    @staticmethod
    def _stable(c: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in c.items() if k not in CbomProjector.VOLATILE}

    def drain(self, *, limit: int = 500) -> int:
        events = self.bus.read("normalized-events", self.CONSUMER, limit=limit)
        touched: set[str] = set()
        for env in events:
            c = env["payload"]
            system = str(c.get("system") or c.get("host") or "default")
            if c.get("kind") not in {"tls_finding", "telecom_nf", "cert"}:
                self.bus.commit("normalized-events", self.CONSUMER, int(env["seq"]))
                continue
            key = c.get("extra", {}).get("dedup_key") or c.get("cert_fingerprint") \
                or f"{c.get('kind')}:{c.get('endpoint')}"
            bucket = self.assets.setdefault(system, {})
            before = self._stable(bucket.get(str(key), {}))
            bucket[str(key)] = c
            if self._stable(bucket[str(key)]) != before:
                touched.add(system)
            self.bus.commit("normalized-events", self.CONSUMER, int(env["seq"]))
        for system in touched:
            self.service.update(system, list(self.assets.get(system, {}).values()))
        return len(events)
