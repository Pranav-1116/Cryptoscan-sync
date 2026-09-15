"""HMAC-signed, timestamped event envelopes (transport-agnostic).

Every event on the wire is: versioned, sequenced, timestamped (UTC), keyed
(for partition ordering) and HMAC-SHA256-signed over the canonical JSON of
its content. Verification is constant-time; a tampered payload or a moved
field breaks the signature. Canonicalization is deterministic (sorted keys,
compact separators, UTF-8) so independent producers produce byte-identical
signatures for identical content.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

ENV_VERSION = 1


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding (the only form ever hashed or signed)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sign_envelope(
    payload: dict[str, Any],
    *,
    topic: str,
    key: str,
    seq: int,
    source: str,
    secret: str,
    ts: str | None = None,
) -> dict[str, Any]:
    """Wrap + sign a payload for a topic. `ts` is injectable for tests."""
    from eventstream.topics import validate_topic

    validate_topic(topic)
    body = {
        "v": ENV_VERSION,
        "topic": topic,
        "key": key,
        "seq": int(seq),
        "source": source,
        "ts": ts or utc_now_iso(),
        "payload": payload,
        "payload_hash": content_hash(payload),
    }
    body["hmac"] = hmac.new(secret.encode("utf-8"), canonical_bytes(body), hashlib.sha256).hexdigest()
    return body


def verify_envelope(env: dict[str, Any], secret: str) -> bool:
    """Constant-time verification of the envelope signature and payload hash."""
    body = {k: v for k, v in env.items() if k != "hmac"}
    expected = hmac.new(secret.encode("utf-8"), canonical_bytes(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(env.get("hmac", ""))):
        return False
    if "payload" not in env:
        return False
    return hmac.compare_digest(content_hash(env["payload"]), str(env.get("payload_hash", "")))
