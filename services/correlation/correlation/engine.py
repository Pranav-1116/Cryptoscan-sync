"""Deterministic correlation, explanation, prioritization, and planning.

Published formulas (pinned by tests):
  priority       = revenue_impact(1-5) × severity(1-5) × agility(0-1)
                   (agility is the quick-win multiplier: easy+critical first)
  migration_effort = asset_count × complexity × (2 − agility)
                   (agility 1 halves the multiplier, agility 0 doubles it —
                   effort shrinks as the estate's agility grows)

Explanations are string.Template texts (stdlib — deterministic, no model).
Correlation is BFS over the dependency graph. Replacement guidance is a
versioned rule table, aligned with the platform's crypto catalogs.
"""

from __future__ import annotations

from collections import deque
from typing import Any
from string import Template

EXPLAIN_TEMPLATE = Template(
    "$finding_kind on ${endpoint_or_system} ($severity).\n"
    "Why: $why\n"
    "Evidence: $evidence\n"
    "Recommended fix: $fix\n"
    "Verification: $verification"
)

WHY_BY_KIND = {
    "weak_tls": "the negotiated TLS version is deprecated by policy",
    "algorithm_downgrade": "a broken algorithm appeared where a baseline had a sound one",
    "crypto_downgrade": "the endpoint regressed below its baseline TLS version",
    "mitm_indicator": "the presented certificate does not match the pinned fingerprint",
    "key_reuse": "identical key material serves multiple systems",
    "cert_near_expiry": "the certificate will expire inside the warning window",
    "revoked_cert_in_use": "the certificate is revoked at its issuer",
    "weak_entropy": "key generation material shows low entropy",
}
FIX_BY_KIND = {
    "weak_tls": "disable the legacy version; require TLS 1.2+ (1.3 preferred)",
    "algorithm_downgrade": "roll back the change and block the broken algorithm at the terminator",
    "crypto_downgrade": "restore the baseline TLS configuration on the endpoint",
    "mitm_indicator": "rotate the certificate and investigate the presenter immediately",
    "key_reuse": "issue unique key material per system; rotate the shared key",
    "cert_near_expiry": "renew the certificate before the warning window closes",
    "revoked_cert_in_use": "revoke-and-replace; check the host's OCSP stapling",
    "weak_entropy": "re-key using a vetted DRBG/HSM-backed generator",
}
VERIFICATION_BY_KIND = {
    "weak_tls": "re-scan the endpoint: offered versions must be TLS 1.2+ only",
    "algorithm_downgrade": "re-scan: offered cipher suites must exclude the broken algorithm",
    "crypto_downgrade": "re-scan: negotiated version matches the baseline again",
    "mitm_indicator": "re-scan: fingerprint matches the new pin",
    "key_reuse": "re-scan all systems: the fingerprint appears exactly once",
    "cert_near_expiry": "re-scan: notAfter beyond the warning window",
    "revoked_cert_in_use": "re-scan: OCSP GOOD and fingerprint rotated",
    "weak_entropy": "re-key and sample again: entropy above threshold",
}

# algorithm -> approved replacement rule table (post-quantum aware)
REPLACEMENTS: dict[str, dict[str, str]] = {
    "DES": {"replacement": "AES-256-GCM", "note": "broken since '05; immediate"},
    "3DES": {"replacement": "AES-256-GCM", "note": "64-bit block; Sweet32"},
    "RC4": {"replacement": "AES-256-GCM", "note": "prohibited (RFC 7465)"},
    "MD5": {"replacement": "SHA-256", "note": "collisions practical"},
    "SHA1": {"replacement": "SHA-256", "note": "chosen-prefix collisions"},
    "RSA-1024": {"replacement": "RSA-3072 or ML-DSA-65", "note": "below 112-bit floor"},
    "RSA-2048": {"replacement": "ML-KEM-768 hybrid (kex) / ML-DSA-65 (sig)", "note": "PQC migration"},
    "ECC-P256": {"replacement": "ML-KEM-768 (kex)", "note": "harvest-now-decrypt-later"},
    "DH-1024": {"replacement": "DH-3072+ or ML-KEM-768", "note": "below floor"},
    "AES-128": {"replacement": "AES-256 (CNSA 2.0 where mandated)", "note": "top-secret suites"},
    "TLSv1.0": {"replacement": "TLSv1.2+ (1.3 preferred)", "note": "deprecated"},
    "TLSv1.1": {"replacement": "TLSv1.2+ (1.3 preferred)", "note": "deprecated"},
}


def recommend_replacement(algorithm: str) -> dict[str, str] | None:
    return REPLACEMENTS.get(str(algorithm or "").upper())


def priority_score(*, revenue_impact: float, severity: float, agility: float) -> float:
    """priority = revenue × severity × agility (quick wins rise)."""
    if not (0 <= agility <= 1):
        raise ValueError("agility must be within [0, 1]")
    return round(revenue_impact * severity * agility, 4)


def migration_effort(*, asset_count: int, complexity: float, agility: float) -> float:
    """effort = assets × complexity × (2 − agility) — see module docstring."""
    if not (0 <= agility <= 1):
        raise ValueError("agility must be within [0, 1]")
    return round(asset_count * complexity * (2 - agility), 4)


def explain(kind: str, *, severity: str, endpoint_or_system: str, evidence: str) -> str:
    """Deterministic template explanation (no model, ever)."""
    return EXPLAIN_TEMPLATE.substitute(
        finding_kind=kind,
        endpoint_or_system=endpoint_or_system,
        severity=severity,
        why=WHY_BY_KIND.get(kind, "a policy or baseline rule matched"),
        evidence=evidence,
        fix=FIX_BY_KIND.get(kind, "apply the rule-table replacement and re-scan"),
        verification=VERIFICATION_BY_KIND.get(kind, "re-scan and confirm the rule clears"),
    )


def correlate(start: str, edges: dict[str, list[str]], *, max_depth: int = 4) -> list[str]:
    """Deterministic BFS reachability (dependency closure), start excluded,
    discovery order preserved, cycles safe."""
    seen: list[str] = []
    visited = {start}
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt in edges.get(node, []):
            if nxt not in visited:
                visited.add(nxt)
                seen.append(nxt)
                queue.append((nxt, depth + 1))
    return seen


# migration plan template library (per profile; deterministic, versioned)
PLAN_TEMPLATES: dict[str, dict[str, Any]] = {
    "banking": {
        "phases": [
            {"phase": 1, "goal": "inventory & baseline", "actions": [
                "run real benchmark scan; pin CBOM v1",
                "flag all DISALLOWED assets", "map PCI-relevant flows"]},
            {"phase": 2, "goal": "quick wins", "actions": [
                "retire SSLv3/TLSv1.x terminators", "replace 3DES/RC4 suites",
                "re-key <2048-bit RSA"]},
            {"phase": 3, "goal": "PQC pilot", "actions": [
                "hybrid ML-KEM-768 on one payment path",
                "HSM firmware check for ML-DSA/ML-KEM validation"]},
            {"phase": 4, "goal": "broad migration", "actions": [
                "roll hybrid kex by dependency order",
                "re-sign CAs with ML-DSA inside validated modules"]},
        ],
    },
    "telecom": {
        "phases": [
            {"phase": 1, "goal": "NF inventory", "actions": [
                "discover 5G SBA NFs; pin SEPP baseline",
                "record PQC journey baseline pass"]},
            {"phase": 2, "goal": "interface hardening", "actions": [
                "TLS 1.3 on N32/roaming", "IPsec IKEv2 profile lift (TS 33.210)"]},
            {"phase": 3, "goal": "PQC rollout", "actions": [
                "ML-KEM on SEPP N32 first", "SUPI concealment scheme review"]},
        ],
    },
    "default": {
        "phases": [
            {"phase": 1, "goal": "baseline", "actions": ["scan estate", "pin CBOM v1"]},
            {"phase": 2, "goal": "remediate", "actions": ["clear DISALLOWED", "lift TLS floors"]},
            {"phase": 3, "goal": "PQC", "actions": ["hybrid pilot", "vendor check"]},
        ],
    },
}


def migration_plan(profile: str = "default") -> dict[str, Any]:
    tpl = PLAN_TEMPLATES.get(profile)
    return {"profile": profile if tpl else "default",
            "template_version": 1, "phases": (tpl or PLAN_TEMPLATES["default"])["phases"]}


def analyze(finding: dict[str, Any], *, graph: dict[str, list[str]] | None = None,
            profile: str = "default") -> dict[str, Any]:
    """One deterministic report: explain + correlate + prioritize + plan."""
    kind = str(finding.get("kind") or "unknown")
    severity = str(finding.get("severity") or "MEDIUM")
    target = str(finding.get("endpoint") or finding.get("system") or "?")
    report = {
        "kind": kind,
        "explanation": explain(kind, severity=severity, endpoint_or_system=target,
                               evidence=str(finding.get("evidence") or "rule match")),
        "priority": priority_score(
            revenue_impact=float(finding.get("revenue_impact", 3)),
            severity=float(finding.get("severity_weight") or
                           {"CRITICAL": 5, "HIGH": 4, "ALERT": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 2)),
            agility=float(finding.get("agility", 0.5)),
        ),
        "effort": migration_effort(
            asset_count=int(finding.get("asset_count", 1)),
            complexity=float(finding.get("complexity", 1.0)),
            agility=float(finding.get("agility", 0.5)),
        ),
        "plan": migration_plan(profile),
        "replacement": recommend_replacement(str(finding.get("algorithm") or "")),
    }
    if graph:
        report["correlated"] = correlate(target, graph)
    return report
