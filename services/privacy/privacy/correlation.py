"""Finding deduplication + correlation (spec #21, #22).

Five scanners may independently surface what is really one problem:

    Network, Application, Certificate, Cloud, Crypto -> ONE finding

This module merges identical root-cause findings from many sources into a single
finding carrying *evidence* from each, and then turns related findings into
attack/dependency chains (Weak TLS + weak certificate + internet exposure +
critical app -> CRITICAL BUSINESS RISK).

Both functions are pure/deterministic: they key on a stable ``finding_fingerprint``
and never mutate the source records.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable


#: canonical risk ranks, low -> high. Used to roll a chain up to its worst stage.
RISK_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: a short taxonomy of finding *categories* so unrelated findings never merge.
CATEGORIES = (
    "weak_tls", "weak_certificate", "weak_crypto", "internet_exposure",
    "key_size", "pqc_readiness", "firmware", "misconfiguration",
    "unpatched", "credential", "protocol", "certificate_expiry",
)


def finding_fingerprint(*, category: str, asset_id: str,
                        algorithm: str | None = None,
                        key_size: int | None = None,
                        cve: str | None = None,
                        port: int | None = None,
                        extra: dict[str, Any] | None = None) -> str:
    """Stable identity for a finding, so the same root cause from many scanners
    deduplicates regardless of which scanner reported it.

    The fingerprint is intentionally *not* the detector: a network scan and a
    crypto scan that both see AES-128 weak usage on ``asset-42`` yield the same
    fingerprint and merge.
    """
    parts = [
        (category or "").strip().lower(),
        (asset_id or "").strip().lower(),
        (algorithm or "").strip().lower(),
        str(key_size or ""),
        (cve or "").strip().lower(),
        str(port or ""),
    ]
    if extra:
        for k in sorted(extra):
            parts.append(f"{k}={str(extra[k]).strip().lower()}")
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
    return digest


@dataclass
class CorrelatedFinding:
    """One deduplicated finding with all corroborating evidence."""

    fingerprint: str
    category: str
    asset_id: str
    severity: str
    title: str
    sources: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "category": self.category,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "title": self.title,
            "sources": sorted(set(self.sources)),
            "evidence": self.evidence,
        }


def correlate_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse many raw findings into deduplicated :class:`CorrelatedFinding`.

    Input findings should carry ``category``, ``asset_id`` (or ``asset``),
    ``severity``, ``title``, and -- optionally -- the same key fields used by
    :func:`finding_fingerprint`. The first occurrence's severity/title win as the
    canonical label; every source's evidence is aggregated under it.
    """
    by_fp: dict[str, CorrelatedFinding] = {}
    for raw in findings:
        category = str(raw.get("category") or "unknown").strip().lower()
        asset_id = str(raw.get("asset_id") or raw.get("asset") or "").strip().lower()
        fp = finding_fingerprint(
            category=category, asset_id=asset_id,
            algorithm=raw.get("algorithm"), key_size=raw.get("key_size"),
            cve=raw.get("cve"), port=raw.get("port"), extra=raw.get("fingerprint_extra"),
        )
        severity = str(raw.get("severity") or "info").strip().lower()
        title = str(raw.get("title") or category)
        src = str(raw.get("source") or raw.get("scanner") or "unknown")
        ev = {
            "source": src,
            "severity": severity,
            "title": title,
            "method": raw.get("method"),
            "confidence": raw.get("confidence"),
            **({k: v for k, v in raw.items()
                if k not in ("source", "scanner", "severity", "title", "category", "asset_id", "asset")}),
        }
        if fp in by_fp:
            cur = by_fp[fp]
            if src not in cur.sources:
                cur.sources.append(src)
                cur.evidence.append(ev)
            # raise severity if a corroborating source is worse
            if RISK_RANK.get(severity, 0) > RISK_RANK.get(cur.severity, 0):
                cur.severity = severity
        else:
            by_fp[fp] = CorrelatedFinding(
                fingerprint=fp, category=category, asset_id=asset_id,
                severity=severity, title=title, sources=[src], evidence=[ev],
            )
    # sort by severity then asset for a stable, useful ordering
    out = list(by_fp.values())
    out.sort(key=lambda f: (-RISK_RANK.get(f.severity, 0), f.asset_id, f.fingerprint))
    return [f.to_dict() for f in out]


#: contribution of each link type to a chain's severity (worst wins).
_CHAIN_LINK = {
    "weak_tls": 2, "weak_certificate": 2, "weak_crypto": 2,
    "internet_exposure": 3, "key_size": 1, "pqc_readiness": 1,
}


def build_chain(asset_id: str, findings: Iterable[dict[str, Any]],
                *,
                critical_asset: bool = False,
                business_value: str | None = None) -> dict[str, Any]:
    """Turn a set of related findings into an attack/dependency chain.

    Returns a single dict describing the chain and an overall business risk:
    ``critical`` when an asset is business-critical and has an internet-exposed,
    weak-crypto/weak-TLS compound; otherwise the worst contributing severity.
    """
    fs = list(findings)
    links: list[dict[str, Any]] = []
    worst = 0
    for f in fs:
        cat = str(f.get("category") or "").strip().lower()
        sev = str(f.get("severity") or "info").strip().lower()
        links.append({
            "category": cat,
            "severity": sev,
            "title": f.get("title") or cat,
            "evidence_sources": f.get("sources") or [f.get("source")] or [],
        })
        worst = max(worst, RISK_RANK.get(sev, 0))
        # a compound signal pushes the chain up independent of per-item severity
        if cat in _CHAIN_LINK:
            worst = max(worst, _CHAIN_LINK[cat])

    # an internet-exposed asset + weak TLS + critical value is the textbook
    # critical business risk ("crypto at risk in the path to the big thing")
    cats = {l["category"] for l in links}
    compound = {"internet_exposure"} <= cats and bool(cats & {"weak_tls", "weak_crypto"})
    if compound and (critical_asset or (business_value or "").lower() in
                     ("critical", "mission_critical", "high")):
        worst = max(worst, RISK_RANK["critical"])

    sev_name = next(k for k, v in sorted(RISK_RANK.items(), key=lambda kv: kv[1])
                    if v >= worst) if worst > 0 else "info"
    return {
        "asset_id": asset_id,
        "business_value": business_value,
        "critical_asset": critical_asset,
        "chain": links,
        "overall_severity": sev_name,
        "compound_risk": compound and (critical_asset or (business_value or "").lower()
                                       in ("critical", "mission_critical", "high")),
    }
