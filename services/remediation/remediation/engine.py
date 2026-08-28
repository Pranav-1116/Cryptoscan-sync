"""Map failing findings to concrete replacement guidance.

Rule-driven and deterministic: pass/fail still comes only from the policy
engine — this service only advises. Rules match exact names or family
prefixes (RSA-2048 -> the RSA rule), so real-world algorithm strings
never silently miss the table.
"""

from __future__ import annotations

from typing import Any, Iterable

PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

# Algorithm families that are already post-quantum: never suggested against
# unless the policy engine itself flagged the finding.
PQC_PREFIXES = ("ML-", "KYBER", "DILITHIUM", "SPHINCS", "SLH-", "FALCON", "HQV")

RULES: list[dict[str, Any]] = [
    {
        "rule": "replace-des",
        "match": ("DES",),
        "replace_with": "AES-256-GCM",
        "guidance": "Replace DES with AES-256-GCM. ECB/CBC DES cannot be patched in place.",
        "category": "CLASSICALLY_BROKEN",
        "priority": "P0",
        "effort": "low",
    },
    {
        "rule": "replace-3des",
        "match": ("3DES",),
        "replace_with": "AES-256-GCM",
        "guidance": "3DES is retired. Use AES-256-GCM or ChaCha20-Poly1305.",
        "category": "CLASSICALLY_BROKEN",
        "priority": "P0",
        "effort": "low",
    },
    {
        "rule": "replace-rc4",
        "match": ("RC4",),
        "replace_with": "ChaCha20-Poly1305",
        "guidance": "RC4 is forbidden. Prefer TLS 1.3 or ChaCha20-Poly1305.",
        "category": "CLASSICALLY_BROKEN",
        "priority": "P0",
        "effort": "low",
    },
    {
        "rule": "replace-md5",
        "match": ("MD5",),
        "replace_with": "SHA-256",
        "guidance": "MD5 is collision-broken. Use SHA-256 or SHA-3.",
        "category": "CLASSICALLY_BROKEN",
        "priority": "P0",
        "effort": "low",
    },
    {
        "rule": "replace-sslv3",
        "match": ("SSLV3", "SSL-3", "SSL3"),
        "replace_with": "TLS 1.3",
        "guidance": "SSLv3 is broken (POODLE). Disable immediately.",
        "category": "CLASSICALLY_BROKEN",
        "priority": "P0",
        "effort": "medium",
    },
    {
        "rule": "replace-sha1",
        "match": ("SHA-1", "SHA1"),
        "replace_with": "SHA-256",
        "guidance": "SHA-1 is retired for signatures and integrity.",
        "category": "DEPRECATED",
        "priority": "P1",
        "effort": "low",
    },
    {
        "rule": "replace-tls10",
        "match": ("TLS1.0", "TLS1-0", "TLSV1.0", "TLSV1"),
        "replace_with": "TLS 1.3",
        "guidance": "Disable TLS 1.0/1.1. Require TLS 1.2 minimum, TLS 1.3 preferred.",
        "category": "PROTOCOL_VERSION",
        "priority": "P1",
        "effort": "medium",
    },
    {
        "rule": "replace-tls11",
        "match": ("TLS1.1", "TLS1-1", "TLSV1.1"),
        "replace_with": "TLS 1.3",
        "guidance": "Disable TLS 1.0/1.1. Require TLS 1.2 minimum, TLS 1.3 preferred.",
        "category": "PROTOCOL_VERSION",
        "priority": "P1",
        "effort": "medium",
    },
    {
        "rule": "fix-ecb-mode",
        "match": (),  # mode-driven rule, see _mode_rule
        "replace_with": "AES-256-GCM",
        "guidance": "ECB mode leaks structure; switch to an AEAD mode (GCM).",
        "category": "WEAK_MODE",
        "priority": "P1",
        "effort": "low",
    },
    {
        "rule": "plan-rsa-pqc",
        "match": ("RSA",),
        "replace_with": "ML-KEM-768 / ML-DSA-65",
        "guidance": "Plan a hybrid RSA+PQC migration. New key-exchange should be ML-KEM.",
        "category": "PQC_TRANSITION",
        "priority": "P2",
        "effort": "high",
    },
    {
        "rule": "plan-dsa-pqc",
        "match": ("DSA",),
        "replace_with": "ML-DSA-65",
        "guidance": "DSA is disallowed. Move to ECDSA-P256 only as an interim, then ML-DSA.",
        "category": "PQC_TRANSITION",
        "priority": "P2",
        "effort": "high",
    },
    {
        "rule": "plan-ecc-pqc",
        "match": ("ECDH", "ECDSA", "ED25519", "ED448", "X25519", "X448", "SECP"),
        "replace_with": "ML-KEM-768 / ML-DSA-65",
        "guidance": "ECC is Shor-vulnerable. Plan a hybrid ECC+PQC migration (ML-KEM/ML-DSA).",
        "category": "PQC_TRANSITION",
        "priority": "P2",
        "effort": "high",
    },
    {
        "rule": "plan-dh-pqc",
        "match": ("DH", "DIFFIE"),
        "replace_with": "ML-KEM-768",
        "guidance": "Finite-field DH is Shor-vulnerable. Migrate key exchange to ML-KEM.",
        "category": "PQC_TRANSITION",
        "priority": "P2",
        "effort": "high",
    },
    {
        "rule": "resize-aes128",
        "match": ("AES-128", "AES128"),
        "replace_with": "AES-256",
        "guidance": "Grover halves AES-128's margin; resize to AES-256 at the next key rotation.",
        "category": "QUANTUM_MARGINAL",
        "priority": "P3",
        "effort": "low",
    },
]

MANUAL_REVIEW = {
    "rule": "manual-review",
    "replace_with": "review",
    "guidance": "Review this primitive against the current policy pack.",
    "category": "UNKNOWN",
    "priority": "P3",
    "effort": "low",
}

LABEL = "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION"


def _normalize(algorithm: str | None) -> str:
    return str(algorithm or "UNKNOWN").upper().replace("_", "-")


def _mode_rule(finding: dict[str, Any]) -> dict[str, Any] | None:
    mode = str(finding.get("mode") or "").upper()
    if mode == "ECB":
        return next(rule for rule in RULES if rule["rule"] == "fix-ecb-mode")
    return None


def _match_rule(algo: str) -> dict[str, Any] | None:
    # longest-prefix-first so e.g. TLS1.1 is not swallowed by a shorter key
    candidates = [
        (len(key), index, rule)
        for index, rule in enumerate(RULES)
        for key in rule["match"]
        if algo == key or algo.startswith(key)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][2]


def _rule_for(finding: dict[str, Any]) -> dict[str, Any] | None:
    algo = _normalize(finding.get("algorithm"))
    if algo.startswith(PQC_PREFIXES):
        return None  # already post-quantum; only a policy FAIL would flag it
    mode_hit = _mode_rule(finding)
    if mode_hit is not None:
        return mode_hit
    return _match_rule(algo)


def suggest_remediations(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    suggestions: list[dict[str, Any]] = []
    for finding in findings:
        status = str(finding.get("compliance_status") or "").upper()
        flagged = status in {"FAIL", "WARN"}
        rule = _rule_for(finding)
        if not flagged and rule is None:
            continue  # healthy finding on a healthy algorithm
        if rule is None:
            rule = MANUAL_REVIEW  # the policy engine flagged something we don't model
        suggestions.append(
            {
                "evidence_id": finding.get("evidence_id") or finding.get("id"),
                "algorithm": _normalize(finding.get("algorithm")) if finding.get("algorithm") else finding.get("algorithm"),
                "purpose": finding.get("purpose"),
                "file_path": finding.get("file_path"),
                "line_number": finding.get("line_number"),
                "replace_with": rule["replace_with"],
                "guidance": rule["guidance"],
                "effort": rule["effort"],
                "label": LABEL,
                "rule": rule["rule"],
                "category": rule["category"],
                "priority": rule["priority"],
            }
        )
    suggestions.sort(
        key=lambda row: (
            PRIORITY_RANK.get(row["priority"], 99),
            str(row.get("file_path") or ""),
            int(row.get("line_number") or 0),
            str(row.get("evidence_id") or ""),
        )
    )
    rule_counts: dict[str, int] = {}
    by_priority = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for row in suggestions:
        rule_counts[row["rule"]] = rule_counts.get(row["rule"], 0) + 1
        by_priority[row["priority"]] = by_priority.get(row["priority"], 0) + 1
    from remediation.backlog import build_backlog

    return {
        "count": len(suggestions),
        "suggestions": suggestions,
        "rule_counts": dict(sorted(rule_counts.items())),
        "by_priority": by_priority,
        "backlog": build_backlog(suggestions),
        "disclaimer": "Remediation text is advisory. Pass/fail comes only from the policy engine.",
    }
