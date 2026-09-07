"""Offline feed ingestion into the real vulnerability/feed store (feature 26).

Closes the gap where imported air-gap bundles landed in an in-memory sink and
were discarded. `FeedSink` implementations write CVE/advisory entries where the
scanners actually read them:

- `SqlVulnerabilityFeedSink` upserts into the `vulnerabilities` table via the
  repository pattern (deterministic; de-duplicates on (cve, package, version)).
- `InMemoryFeedSink` is retained for tests.

The sink is feed-aware: `nvd`/`osv`/`registry` entries map onto the vulnerability
schema; unknown feeds are namespaced into `summary` so nothing is silently lost.
"""

from __future__ import annotations

from typing import Any, Protocol


class FeedSink(Protocol):
    def upsert_feed(self, feed: str, entry_id: str, payload: dict) -> int: ...
    def finalize(self, applied: int) -> None: ...


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2,
                   "LOW": 1, "INFO": 0, "NONE": 0}


def normalize_entry(feed: str, entry_id: str, payload: dict) -> dict[str, Any]:
    """Map any supported feed entry to the platform vulnerability schema.

    Deterministic; tolerates NVD-style and OSV-style payloads. Returns a dict
    with keys: cve, package, affected, severity, summary, package_version.
    """
    cve = payload.get("cve") or payload.get("id") or entry_id
    package = str(payload.get("package") or payload.get("affected_package")
                  or payload.get("pkg") or feed).lower()
    version = payload.get("version") or payload.get("package_version") \
        or payload.get("introduced") or (payload.get("affected") if isinstance(payload.get("affected"), str) else None)
    sev_raw = str(payload.get("severity") or payload.get("cvss_severity") or "").upper()
    if sev_raw in _SEVERITY_ORDER:
        sev = sev_raw
    else:
        # numeric CVSS (in severity field or cvss) -> severity band
        try:
            score = float(payload.get("cvss") if payload.get("cvss") is not None else sev_raw)
            sev = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else
                   "MEDIUM" if score >= 4 else "LOW")
        except (TypeError, ValueError):
            sev = "MEDIUM"
    summary = payload.get("summary") or payload.get("desc") or payload.get("description") \
        or f"[{feed}] {entry_id}"
    return {"cve": str(cve), "package": package, "affected": payload.get("affected_range"),
            "severity": sev, "summary": str(summary)[:2000], "version": version,
            "feed": feed}


class InMemoryFeedSink:
    def __init__(self):
        self.feeds: dict[str, dict] = {}
        self.applied = 0

    def upsert_feed(self, feed: str, entry_id: str, payload: dict) -> int:
        norm = normalize_entry(feed, entry_id, payload)
        bucket = self.feeds.setdefault(feed, {})
        key = f"{norm['cve']}|{norm['package']}|{norm['version'] or ''}"
        new = key not in bucket
        bucket[key] = norm
        return 1 if new else 0

    def finalize(self, applied: int) -> None:
        self.applied = applied


class SqlVulnerabilityFeedSink:
    """Upsert offline feed entries into the live vulnerabilities table.

    Takes a SQLAlchemy session; uses a merge-on-(cve,package,version) strategy so
    re-importing a bundle is idempotent (no duplicate CVE rows)."""

    def __init__(self, session):
        self.session = session
        self.inserted = 0
        self.updated = 0

    def upsert_feed(self, feed: str, entry_id: str, payload: dict) -> int:
        from sqlalchemy import select
        from db.models.vulnerability import Vulnerability

        norm = normalize_entry(feed, entry_id, payload)
        existing = self.session.execute(
            select(Vulnerability).where(
                Vulnerability.cve == norm["cve"],
                Vulnerability.package == norm["package"],
                Vulnerability.package_version == (norm["version"] or None),
            )
        ).scalars().first()
        if existing is not None:
            existing.severity = norm["severity"]
            existing.summary = norm["summary"]
            existing.affected = norm["affected"]
            self.updated += 1
            return 0
        self.session.add(Vulnerability(
            cve=norm["cve"], package=norm["package"], affected=norm["affected"],
            severity=norm["severity"], summary=norm["summary"],
            package_version=norm["version"], scan_id=f"feed:{feed}"))
        self.inserted += 1
        return 1

    def finalize(self, applied: int) -> None:
        self.session.commit()
