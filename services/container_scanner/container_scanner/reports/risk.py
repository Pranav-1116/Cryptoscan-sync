"""Post-scan risk report: registry verdicts, deprecations, CVE severities.

Findings carry raw algorithm names; nothing answers "is this image's crypto
posture acceptable?"  This module grades a scan through the shared algorithm
registry (the same verdicts the network scanner applies) and the fingerprint
catalog's own deprecation flags:

* every algorithm in every library finding -> ALLOWED / DEPRECATED /
  DISALLOWED / RESTRICTED / UNKNOWN verdict, rolled up per algorithm and
  per library
* ``deprecated`` catalog entries (e.g. pycrypto, abandoned since 2013) and
  libraries with matching CVEs become policy issues
* hardcoded secrets headline — ``HARDCODED_PRIVATE_KEY`` outranks everything
* an overall posture verdict: FAIL (disallowed algorithm, hardcoded key, or
  CRITICAL CVE), WARN (deprecated / HIGH CVE), or PASS
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from typing import Any, Iterable

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def algorithm_verdicts(algorithms: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Registry verdict per algorithm name (deduplicated, sorted by severity)."""
    try:
        from shared_models.algorithm_registry import parse_algorithm
    except Exception:  # noqa: BLE001 — registry unavailable: degrade, don't crash
        return {}
    out: dict[str, dict[str, Any]] = {}
    for name in {str(item) for item in algorithms if item}:
        try:
            info = parse_algorithm(name)
        except Exception as _handler_exc:  # noqa: BLE001
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            continue
        out[name] = {"status": info.status, "quantum_impact": info.quantum_impact}
    return dict(sorted(out.items(), key=lambda kv: _status_rank(kv[1]["status"])))


def _status_rank(status: str) -> int:
    return {"DISALLOWED": 0, "RESTRICTED": 1, "DEPRECATED": 2, "ALLOWED": 3, "UNKNOWN": 4}.get(str(status), 4)


def build_risk_report(
    *,
    libraries: list[dict[str, Any]] | None = None,
    binaries: list[dict[str, Any]] | None = None,
    vulnerabilities: list[dict[str, Any]] | None = None,
    secrets: list[dict[str, Any]] | None = None,
    distro: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Grade one scan's outputs into a posture verdict + policy issues."""
    distro = distro or {}
    libraries = libraries or []
    binaries = binaries or []
    vulnerabilities = vulnerabilities or []
    secrets = secrets or []

    all_algorithms: set[str] = set()
    for lib in libraries:
        all_algorithms.update(str(item) for item in (lib.get("algorithms") or []) if item)
    for binary in binaries:
        all_algorithms.update(str(item) for item in (binary.get("algorithms") or []) if item)
    verdicts = algorithm_verdicts(all_algorithms)

    disallowed = sorted(name for name, v in verdicts.items() if v["status"] == "DISALLOWED")
    deprecated_algorithms = sorted(name for name, v in verdicts.items() if v["status"] == "DEPRECATED")
    restricted = sorted(name for name, v in verdicts.items() if v["status"] == "RESTRICTED")

    deprecated_libraries = sorted(
        str(lib.get("name"))
        for lib in libraries
        if lib.get("deprecated") or str(lib.get("name", "")).lower() in {"pycrypto"}
    )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity") or "UNKNOWN").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["UNKNOWN"] += 1
    vulnerable_packages = sorted({str(v.get("package")) for v in vulnerabilities if v.get("package")})

    eol = distro.get("eol") or {}
    key_secrets = [s for s in secrets if s.get("confidence") == "HIGH"]
    secret_kinds = sorted({str(s.get("kind")) for s in secrets})

    issues: list[str] = []
    if key_secrets:
        issues.append("HARDCODED_PRIVATE_KEY")
    if disallowed:
        issues.append("DISALLOWED_ALGORITHM")
    if severity_counts["CRITICAL"]:
        issues.append("CRITICAL_CVE_PRESENT")
    if distro:
        eol = distro.get("eol") or {}
        if eol.get("status") == "EOL":
            issues.append("EOL_BASE_IMAGE")
        if distro.get("manager_mismatch"):
            issues.append("DISTRO_MANAGER_MISMATCH")
    if deprecated_libraries:
        issues.append("DEPRECATED_CRYPTO_LIBRARY")
    if deprecated_algorithms or restricted:
        issues.append("DEPRECATED_ALGORITHM")
    if severity_counts["HIGH"]:
        issues.append("HIGH_CVE_PRESENT")
    if secrets and not key_secrets:
        issues.append("HARDCODED_TOKEN")

    if "HARDCODED_PRIVATE_KEY" in issues or "DISALLOWED_ALGORITHM" in issues or "CRITICAL_CVE_PRESENT" in issues:
        posture = "FAIL"
    elif issues:
        posture = "WARN"
    else:
        posture = "PASS"

    headline = None
    if issues:
        headline = {
            "HARDCODED_PRIVATE_KEY": f"{len(key_secrets)} hardcoded private key(s): {secret_kinds}",
            "DISALLOWED_ALGORITHM": f"disallowed algorithms in use: {', '.join(disallowed)}",
            "CRITICAL_CVE_PRESENT": f"{severity_counts['CRITICAL']} critical CVE(s): {', '.join(vulnerable_packages[:4])}",
            "EOL_BASE_IMAGE": (
                f"base image {distro.get('name')} {distro.get('version_id')} is EOL "
                f"({eol.get('days_past_eol')} days past end of support)"
            ),
            "DISTRO_MANAGER_MISMATCH": (
                f"os-release says {distro.get('id')} but package DBs found: "
                f"{', '.join(distro.get('package_managers_present') or []) or 'none'}"
            ),
            "DEPRECATED_CRYPTO_LIBRARY": f"deprecated/abandoned crypto libraries: {', '.join(deprecated_libraries)}",
            "DEPRECATED_ALGORITHM": f"deprecated algorithms: {', '.join(deprecated_algorithms + restricted)}",
            "HIGH_CVE_PRESENT": f"{severity_counts['HIGH']} high-severity CVE(s)",
            "HARDCODED_TOKEN": f"{len(secrets)} hardcoded token(s): {secret_kinds}",
        }[issues[0]]

    return {
        "posture": posture,
        "policy_issues": issues,
        "distro": distro,
        "headline": headline,
        "algorithm_verdicts": verdicts,
        "disallowed_algorithms": disallowed,
        "deprecated_algorithms": deprecated_algorithms,
        "restricted_algorithms": restricted,
        "deprecated_libraries": deprecated_libraries,
        "vulnerable_packages": vulnerable_packages,
        "cve_severity_counts": severity_counts,
        "secret_kinds": secret_kinds,
        "counts": {
            "libraries": len(libraries),
            "binaries": len(binaries),
            "vulnerabilities": len(vulnerabilities),
            "secrets": len(secrets),
        },
    }
