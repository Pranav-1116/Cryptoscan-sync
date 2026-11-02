"""Container image scanning on push (Trivy-style, deterministic).

Two deterministic, offline-capable analyses:

1. Installed-package CVE matching: given a package list extracted from an image
   (name, version, ecosystem/os) and an NVD-style feed of advisories, match by
   (ecosystem, package, version-range) — no network, no model. Version
   comparison is a small implementation of the dist/python-style ordering that
   is sufficient for security advisory bounds.
2. Dockerfile policy: parse a Dockerfile and flag deterministic anti-patterns
   (root USER, :latest tag, ADD remote, secrets in ENV, privileged build, etc.)

The NVD/advisory feed and the package inventory are supplied to the functions
(or via a fetch hook), so tests and on-push pipelines run identically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# -------------------------------------------------------------- versions --- #
def parse_version(v: str) -> tuple:
    """Split a version into a comparable tuple of ints and non-numeric tags."""
    if v is None:
        return ()
    parts = re.split(r"[.\-_+]", str(v).strip())
    out: list = []
    for p in parts:
        if p.isdigit():
            out.append((0, int(p)))
        else:
            # split leading digits e.g. 1rc2 -> 1, rc2
            m = re.match(r"^(\d+)([a-zA-Z].*)$", p)
            if m:
                out.append((0, int(m.group(1))))
                out.append((1, m.group(2)))
            else:
                out.append((1, p))
    return tuple(out)


def version_compare(a: str, b: str) -> int:
    """Compare two versions, delegating to the platform's version engine.

    The comparator that used to live here split on dots and compared segments,
    which ordered ``1.0.0-rc1`` *after* ``1.0.0`` — a prerelease read as newer
    than the release it precedes. :mod:`devsecops.version_ranges` implements the
    preview/release ordering per ecosystem, so there is one answer in the
    platform rather than two.
    """
    from devsecops.version_ranges import ConstraintError, compare

    try:
        return compare(a, b)
    except ConstraintError:
        # values outside any version grammar still have to order somehow for the
        # legacy callers, so fall back to the numeric-segment comparison
        pa, pb = parse_version(a), parse_version(b)
        for x, y in zip(pa, pb):
            if x < y:
                return -1
            if x > y:
                return 1
        return (len(pa) > len(pb)) - (len(pa) < len(pb))


def _affected(version: str, vuln: dict) -> bool:
    """True if package ``version`` is within the advisory's range."""
    intro = vuln.get("introduced") or vuln.get("vulnerable_version_range") or "0"
    fixed = vuln.get("fixed") or vuln.get("fixed_version")
    last_affected = vuln.get("last_affected")
    if version_compare(version, intro) < 0:
        return False
    if fixed is not None:
        return version_compare(version, fixed) < 0
    if last_affected is not None:
        return version_compare(version, last_affected) <= 0
    return True  # range open (no fix known) -> affected


# ----------------------------------------------------------- package CVEs -- #
@dataclass
class CveMatch:
    package: str
    version: str
    ecosystem: str
    cve_id: str
    severity: str
    fixed_version: str | None
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"package": self.package, "version": self.version,
                "ecosystem": self.ecosystem, "cve_id": self.cve_id,
                "severity": self.severity, "fixed_version": self.fixed_version,
                "summary": self.summary}


def _feed_index(feed: list[dict]) -> dict[tuple, list[dict]]:
    idx: dict[tuple, list[dict]] = {}
    for adv in feed or []:
        for aff in adv.get("affected", []):
            eco = (aff.get("ecosystem") or adv.get("ecosystem") or "").lower()
            name = (aff.get("package") or aff.get("name") or adv.get("package") or "").lower()
            ranges = aff.get("ranges") or [adv]
            for r in ranges:
                idx.setdefault((eco, name), []).append({
                    "cve_id": adv.get("cve_id") or adv.get("id"),
                    "severity": (adv.get("severity") or r.get("severity") or "UNKNOWN").upper(),
                    "fixed": r.get("fixed") or r.get("fixed_version"),
                    "introduced": r.get("introduced") or aff.get("introduced") or "0",
                    "last_affected": r.get("last_affected"),
                    "summary": adv.get("summary") or adv.get("title", ""),
                })
    return idx


def match_packages(packages: Iterable[dict], feed: list[dict]) -> list[CveMatch]:
    """Match image packages against an NVD-style advisory feed deterministically."""
    idx = _feed_index(feed)
    matches: list[CveMatch] = []
    seen: set[tuple] = set()
    for pkg in packages:
        eco = (pkg.get("ecosystem") or pkg.get("os") or "").lower()
        name = (pkg.get("name") or "").lower()
        version = pkg.get("version")
        if not name or not version:
            continue
        for vuln in idx.get((eco, name), []):
            if not _affected(version, vuln):
                continue
            cve = vuln["cve_id"]
            key = (name, version, cve)
            if key in seen:
                continue
            seen.add(key)
            matches.append(CveMatch(name, version, eco, cve, vuln["severity"],
                                    vuln["fixed"], vuln["summary"]))
    matches.sort(key=lambda m: (-SEVERITY_ORDER.get(m.severity, 0), m.package, m.cve_id))
    return matches


# --------------------------------------------------------- Dockerfile ----- #
@dataclass
class DockerfileFinding:
    code: str
    severity: str
    line: int
    instruction: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "line": self.line,
                "instruction": self.instruction, "detail": self.detail}


_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key|credential)"
    r"\s*[=:]\s*[\"\']?([^\"\'\s]{6,})")
_HAS_PKGMGR = re.compile(r"\b(apt-get|apk|yum|dnf|microdnf|pip|npm)\b")


def scan_dockerfile(text: str) -> list[DockerfileFinding]:
    findings: list[DockerfileFinding] = []
    lines = text.splitlines()
    saw_user = False
    saw_update_no_clean = False
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instr = line.split(None, 1)[0].upper()
        rest = line[len(instr):].strip()

        if instr == "FROM":
            if ":latest" in rest or ":" not in rest.split()[0]:
                findings.append(DockerfileFinding("DK-LATEST", "MEDIUM", i, "FROM",
                    "base image uses :latest or no tag — not reproducible"))
            m = re.search(r"@(sha256:[0-9a-f]+)", rest)
            if not m and ":" in rest and "latest" not in rest and " AS " not in rest.upper():
                findings.append(DockerfileFinding("DK-NO-DIGEST", "LOW", i, "FROM",
                    "base image not pinned by digest (@sha256)"))
        if instr == "USER":
            who = rest.split()[0] if rest.split() else ""
            if who in ("root", "0"):
                findings.append(DockerfileFinding("DK-ROOT-USER", "HIGH", i, "USER",
                    "container explicitly runs as root/UID 0"))
            else:
                saw_user = True
        if instr == "ADD" and re.match(r"https?://|\.tar", rest):
            findings.append(DockerfileFinding("DK-ADD-REMOTE", "MEDIUM", i, "ADD",
                "ADD fetches remote/archive — prefer COPY + checksum verification"))
        if instr in ("ENV", "ARG"):
            if _SECRET_RE.search(line):
                findings.append(DockerfileFinding("DK-SECRET-IN-ENV", "HIGH", i, instr,
                    "secret-like value set in build layer (persists in image history)"))
        if instr == "RUN":
            if re.search(r"--privileged|docker\s+run|chmod\s+777", line):
                findings.append(DockerfileFinding("DK-PRIVILEGED-RUN", "HIGH", i, "RUN",
                    "RUN grants excessive privileges (privileged/docker/chmod 777)"))
            if _HAS_PKGMGR.search(line) and "update" in line and not re.search(r"rm -rf|clean|--no-cache", line):
                saw_update_no_clean = True
    if not saw_user:
        findings.append(DockerfileFinding("DK-NO-USER", "MEDIUM", max(1, len(lines)), "USER",
            "no non-root USER instruction — image runs as root by default"))
    if saw_update_no_clean:
        findings.append(DockerfileFinding("DK-PKG-CACHE", "LOW", 0, "RUN",
            "package-manager update without cache cleanup increases image size"))
    return findings


# ------------------------------------------------------------- driver ----- #
def scan_image(*, packages: Iterable[dict] = (), feed: list[dict] | None = None,
               dockerfile: str | None = None) -> dict[str, Any]:
    cves = match_packages(packages, feed or [])
    df = scan_dockerfile(dockerfile) if dockerfile else []
    by_sev: dict[str, int] = {}
    for m in cves:
        by_sev[m.severity] = by_sev.get(m.severity, 0) + 1
    worst = max((m.severity for m in cves),
                key=lambda s: SEVERITY_ORDER.get(s, 0), default="NONE")
    fixable = sum(1 for m in cves if m.fixed_version)
    return {
        "packages_scanned": len(list(packages)) if not isinstance(packages, list) else len(packages),
        "cve_matches": [m.to_dict() for m in cves],
        "vulnerabilities": len(cves),
        "fixable": fixable,
        "by_severity": by_sev,
        "worst_severity": worst if cves else "NONE",
        "dockerfile_findings": [f.to_dict() for f in df],
    }
