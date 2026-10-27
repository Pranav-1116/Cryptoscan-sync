"""Certificate-Transparency log monitoring (deterministic, no AI).

Polls a CT log source (Google's crt.sh JSON endpoint by default, but the HTTP
fetch is injectable for offline/test determinism) for certificates issued for
your monitored domains, then compares against a known/expected inventory to
flag NEW or ROGUE certificates:

- NEW    : a CA-issued cert seen in CT logs for a monitored domain that is not
           in the known-good inventory (potential unauthorised issuance).
- ROGUE  : a cert whose names cover a monitored domain but whose issuer is not
           on the approved-issuer allowlist (possible mis-issuance / MitM CA).

The CT source is treated as untrusted input: only names and issuer are used;
the fetcher is network-isolated in ``_crtsh_fetch`` and never parses untrusted
data with a cryptographic verification assumption.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

CT_CRTSH_URL = "https://crt.sh/?q={domain}&output=json&exclude=expired"


class CtMonitorError(ValueError):
    pass


@dataclass
class CtCertificate:
    id: str
    domain: str
    common_name: str | None
    names: list[str]
    issuer: str | None
    not_before: str | None
    not_after: str | None
    serial: str | None = None
    source: str = "ct"


@dataclass
class CtReport:
    domain: str
    observed: list[dict] = field(default_factory=list)
    new_certs: list[dict] = field(default_factory=list)
    rogue_certs: list[dict] = field(default_factory=list)
    known_certs: int = 0


Fetcher = Callable[[str], str]


def _default_fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "CryptoScan-CT-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=12) as resp:  # noqa: S310 (fixed https host)
        return resp.read().decode("utf-8", "replace")


def _parse_crtsh(domain: str, raw: str) -> list[CtCertificate]:
    rows = json.loads(raw) if raw.strip() else []
    out: list[CtCertificate] = []
    seen: set[str] = set()
    for row in rows:
        names = []
        nv = row.get("name_value") or row.get("common_name") or ""
        for line in str(nv).splitlines():
            line = line.strip().lower().lstrip("*.")
            if line:
                names.append(line)
        cn = (row.get("common_name") or "").lower().lstrip("*.") or (names[0] if names else None)
        cid = str(row.get("id") or row.get("min_cert_id") or f"{cn}:{row.get('not_after')}")
        issuer = (row.get("issuer_name") or row.get("issuer") or "")
        issuer_cn = None
        for part in issuer.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                issuer_cn = part[3:].strip()
        key = cid + "|" + ",".join(sorted(set(names)))
        if key in seen:
            continue
        seen.add(key)
        out.append(CtCertificate(
            id=cid, domain=domain, common_name=cn, names=sorted(set(names)),
            issuer=issuer_cn or issuer or None,
            not_before=row.get("not_before"), not_after=row.get("not_after"),
            serial=row.get("serial_number") or None,
        ))
    return out


def _name_covers(name: str, domain: str) -> bool:
    """True if a CT cert name is exactly or a wildcard-ancestor of domain."""
    n = name.lower().strip(".")
    d = domain.lower().strip(".")
    if n == d:
        return True
    if n.startswith("*."):
        base = n[2:]
        return d.endswith("." + base) or d == base
    return n.endswith("." + d)  # subdomain cert under monitored zone


def monitor_domain(
    domain: str,
    *,
    known_fingerprints: Iterable[str] = (),
    known_serials: Iterable[str] = (),
    allowed_issuers: Iterable[str] = (),
    fetcher: Fetcher | None = None,
) -> CtReport:
    """Poll CT logs for ``domain`` and classify observed certificates."""
    domain = (domain or "").strip().lower().lstrip("*.")
    if not domain or "." not in domain:
        raise CtMonitorError(f"invalid monitored domain: {domain!r}")
    fetch = fetcher or _default_fetch
    url = CT_CRTSH_URL.format(domain=urllib.parse.quote(f"%.{domain}"))
    try:
        raw = fetch(url)
        certs = _parse_crtsh(domain, raw)
    except CtMonitorError:
        raise
    except Exception as exc:  # network/parse failure — surface, don't fabricate
        raise CtMonitorError(f"CT log query failed for {domain}: {exc}") from exc

    known_fp = {f.lower().replace(":", "") for f in known_fingerprints}
    known_sn = {s.lower().replace(":", "") for s in known_serials}
    allowed = {i.lower() for i in allowed_issuers}

    report = CtReport(domain=domain)
    for c in certs:
        covers = any(_name_covers(n, domain) for n in c.names) or _name_covers(c.common_name or "", domain)
        if not covers:
            continue
        d = {"id": c.id, "common_name": c.common_name, "names": c.names,
             "issuer": c.issuer, "not_before": c.not_before, "not_after": c.not_after,
             "serial": c.serial}
        report.observed.append(d)

        is_known = bool(c.serial and c.serial.lower().replace(":", "") in known_sn) or (c.id in known_fp)
        issuer_ok = True
        if allowed:
            issuer_ok = any(a in (c.issuer or "").lower() for a in allowed)

        if not issuer_ok:
            d["reason"] = f"issuer {c.issuer!r} not on approved-issuer allowlist"
            report.rogue_certs.append(d)
        elif not is_known:
            d["reason"] = "CA-issued cert not present in known-good inventory"
            report.new_certs.append(d)
        else:
            report.known_certs += 1
    return report


def monitor_domains(domains: Iterable[str], *, fetchers: dict[str, Fetcher] | None = None,
                    **kwargs) -> list[CtReport]:
    fetchers = fetchers or {}
    reports = []
    for d in domains:
        reports.append(monitor_domain(d, fetcher=fetchers.get(d), **{
            k: v for k, v in kwargs.items() if k not in ("known_fingerprints", "known_serials", "allowed_issuers")
        }))
    return reports


def summarize(reports: list[CtReport]) -> dict[str, Any]:
    return {
        "domains_monitored": len(reports),
        "total_observed": sum(len(r.observed) for r in reports),
        "new_cert_alerts": sum(len(r.new_certs) for r in reports),
        "rogue_cert_alerts": sum(len(r.rogue_certs) for r in reports),
        "rogue_domains": [r.domain for r in reports if r.rogue_certs],
        "new_domains": [r.domain for r in reports if r.new_certs],
    }
