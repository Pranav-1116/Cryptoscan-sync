"""Crypto threat-intel: advisory validation + signed bundles (deep/30, R31).

Pure functions over plain dicts: validate an advisory entry, build a
signed bundle (same canonical-JSON + SHA-256 + HMAC convention as the
platform's air-gap transfers), verify one back. The store side (SQL
upsert) lives in the repository; this module is the trust boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

BUNDLE_FORMAT = "zelnx-threat-intel/v1"

from db.models.threat_advisory import ADVISORY_TYPES, SEVERITIES


class AdvisoryError(ValueError):
    """Invalid advisory or bundle — nothing is persisted."""


def _canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()


def _parse_date(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AdvisoryError(f"unparseable date {value!r}") from exc


def validate_advisory(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Validate + normalize one advisory entry."""
    if not isinstance(entry, Mapping):
        raise AdvisoryError("advisory entry must be an object")
    advisory_id = str(entry.get("advisory_id") or entry.get("id") or "").strip()
    if not advisory_id:
        raise AdvisoryError("advisory needs an advisory_id")
    source = str(entry.get("source") or "").strip()
    if not source:
        raise AdvisoryError(f"advisory '{advisory_id}' needs a source")
    advisory_type = str(entry.get("advisory_type") or "").strip().upper()
    if advisory_type not in ADVISORY_TYPES:
        raise AdvisoryError(
            f"advisory '{advisory_id}' type '{advisory_type}' unknown "
            f"(one of {sorted(ADVISORY_TYPES)})")
    algorithm = str(entry.get("algorithm") or "").strip()
    if not algorithm:
        raise AdvisoryError(f"advisory '{advisory_id}' needs an algorithm")
    severity = str(entry.get("severity") or "MEDIUM").strip().upper()
    if severity not in SEVERITIES:
        raise AdvisoryError(
            f"advisory '{advisory_id}' severity '{severity}' unknown "
            f"(one of {sorted(SEVERITIES)})")
    details = entry.get("details") or {}
    if not isinstance(details, Mapping):
        raise AdvisoryError(f"advisory '{advisory_id}' details must be an object")
    return {
        "advisory_id": advisory_id,
        "source": source,
        "advisory_type": advisory_type,
        "algorithm": algorithm,
        "severity": severity,
        "title": (str(entry["title"])[:400] if entry.get("title") else None),
        "summary": str(entry["summary"]) if entry.get("summary") else None,
        "url": str(entry["url"]) if entry.get("url") else None,
        "published_at": _parse_date(entry.get("published_at")),
        "effective_date": _parse_date(entry.get("effective_date")),
        "details": dict(details),
    }


def validate_advisories(entries: Iterable[Any]) -> list[dict[str, Any]]:
    out = [validate_advisory(e) for e in entries or ()]
    seen: set[tuple[str, str]] = set()
    for item in out:
        key = (item["source"], item["advisory_id"])
        if key in seen:
            raise AdvisoryError(
                f"duplicate advisory {item['advisory_id']} from {item['source']}")
        seen.add(key)
    return out


def build_advisory_bundle(advisories: list[dict[str, Any]], *, secret: str,
                          bundle_id: str = "", generated_at: Optional[datetime] = None) -> dict[str, Any]:
    """Sign a set of validated advisories for transfer to a disconnected site.

    The signed document carries datetimes as ISO strings so the bundle is
    JSON-stable across processes (verify parses them back).
    """
    if len((secret or "").encode()) < 8:
        raise AdvisoryError("signing secret too short (min 8 bytes)")
    entries = []
    for entry in advisories:
        row = dict(entry)
        for stamp in ("published_at", "effective_date"):
            if isinstance(row.get(stamp), datetime):
                row[stamp] = row[stamp].isoformat()
        entries.append(row)
    doc = {
        "format": BUNDLE_FORMAT,
        "bundle_id": bundle_id or f"bundle-{len(advisories)}",
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(),
        "advisories": entries,
    }
    canonical = _canonical(doc)
    return {
        "package": doc,
        "content_hash": hashlib.sha256(canonical).hexdigest(),
        "signature": hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest(),
    }


def verify_advisory_bundle(bundle: Mapping[str, Any], *, secret: str) -> list[dict[str, Any]]:
    """Verify a bundle and return its validated advisories.

    Tamper checks first, then entry validation — a rejected bundle
    yields NOTHING, so a partially-bad bundle cannot half-import.
    """
    package = bundle.get("package")
    if not isinstance(package, Mapping) or package.get("format") != BUNDLE_FORMAT:
        raise AdvisoryError("not a zelnx-threat-intel/v1 bundle")
    canonical = _canonical(package)
    if hashlib.sha256(canonical).hexdigest() != bundle.get("content_hash"):
        raise AdvisoryError("content hash mismatch — bundle tampered or corrupt")
    if not hmac.compare_digest(
        hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest(),
        str(bundle.get("signature") or ""),
    ):
        raise AdvisoryError("signature mismatch — untrusted bundle")
    return validate_advisories(package.get("advisories") or [])


def advisory_relevance(advisory: Mapping[str, Any], *, algorithm: str,
                       now: Optional[datetime] = None) -> dict[str, Any]:
    """Annotation-only relevance for one asset algorithm.

    Effective-date aware: a restriction effective in the future is
    reported as UPCOMING, not current — an advisory never rewrites a
    score, and its timing is stated.
    """
    moment = now or datetime.now(timezone.utc)
    effective = advisory.get("effective_date")
    if isinstance(effective, str):
        effective = _parse_date(effective)
    timing = "STANDING"
    if effective is not None:
        timing = "CURRENT" if moment >= effective else "UPCOMING"
    return {
        "advisory_id": advisory.get("advisory_id"),
        "source": advisory.get("source"),
        "advisory_type": advisory.get("advisory_type"),
        "severity": advisory.get("severity"),
        "title": advisory.get("title"),
        "url": advisory.get("url"),
        "effective_date": (
            effective.isoformat() if isinstance(effective, datetime) else None),
        "timing": timing,
        "note": "annotation only — advisories never rewrite stored scores",
    }


# --------------------------------------------------------------------------- #
# Feed layer (audit deep/30 + 63 feeds remainder, round 35): a feed is an
# HTTP endpoint serving the same signed bundle format the platform itself
# exports. Fetch -> verify -> entries; a tampered or malformed feed yields
# an error, never partial imports. The actual feed URLs/secrets are
# deployment configuration; this code never guesses them.
# --------------------------------------------------------------------------- #

def sync_feed(
    url: str,
    *,
    secret: str,
    timeout: float = 15.0,
    fetch=None,
) -> dict:
    """Fetch one signed advisory bundle from a feed and verify it.

    ``fetch`` is injectable for tests (defaults to ``httpx.get``); it must
    return an object with ``status_code`` and ``json()``. Returns
    ``{"ok": True, "entries": [...]}`` or ``{"ok": False, "error": ...}``
    — callers decide what to persist; nothing is persisted here.
    """
    if not (url or "").strip():
        return {"ok": False, "error": "empty feed url"}
    if not (secret or "").strip():
        return {"ok": False, "error": "feed secret not configured"}
    if fetch is None:
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx ships with the API
            return {"ok": False, "error": "httpx unavailable"}
        fetch = httpx.get
    try:
        response = fetch(url, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": f"fetch failed: {exc}"}
    if getattr(response, "status_code", 0) != 200:
        return {"ok": False, "error": f"feed returned {getattr(response, 'status_code', '?')}"}
    try:
        bundle = response.json()
    except Exception as exc:
        return {"ok": False, "error": f"feed body is not JSON: {exc}"}
    try:
        entries = verify_advisory_bundle(bundle, secret=secret)
    except AdvisoryError as exc:
        return {"ok": False, "error": f"bundle rejected: {exc}"}
    return {"ok": True, "entries": entries}


def sync_feeds(
    feeds: list[dict],
    *,
    secret: str,
    timeout: float = 15.0,
    fetch=None,
) -> dict:
    """Sync every configured feed; each one independently.

    ``feeds`` is ``[{"name": ..., "url": ...}]`` — names are labels for
    the result report. One bad feed never blocks the others.
    """
    results = []
    ok = 0
    entries_total: list = []
    for feed in feeds:
        name = str(feed.get("name") or feed.get("url") or "feed")
        result = sync_feed(str(feed.get("url") or ""), secret=secret,
                           timeout=timeout, fetch=fetch)
        if result.get("ok"):
            ok += 1
            entries_total.extend(result["entries"])
            results.append({"feed": name, "ok": True, "entries": len(result["entries"])})
        else:
            results.append({"feed": name, "ok": False, "error": result.get("error")})
    return {"feeds_total": len(feeds), "feeds_ok": ok, "results": results,
            "entries": entries_total}
