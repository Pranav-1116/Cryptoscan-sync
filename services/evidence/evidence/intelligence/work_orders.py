"""
Migration work-orders: group failing (or weak) crypto sites by
algorithm + purpose and attach a concrete replacement plus the
policy rule that failed.

These are engineering tickets, not a policy decision. The policy
engine already decided FAIL/PASS; this just turns FAILs into a
backlog a team can schedule.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping


# (algorithm, purpose) -> (replacement, primary rule, effort)
_REPLACEMENTS: dict[tuple[str, str], tuple[str, str, str]] = {
    ("DES", "ENCRYPTION"): ("AES-256-GCM", "BASELINE-001", "medium"),
    ("3DES", "ENCRYPTION"): ("AES-256-GCM", "BASELINE-001", "medium"),
    ("DESEDE", "ENCRYPTION"): ("AES-256-GCM", "BASELINE-001", "medium"),
    ("RC2", "ENCRYPTION"): ("AES-256-GCM", "BASELINE-001", "medium"),
    ("RC4", "ENCRYPTION"): ("AES-256-GCM or ChaCha20-Poly1305", "BASELINE-001", "medium"),
    ("BLOWFISH", "ENCRYPTION"): ("AES-256-GCM", "BASELINE-001", "medium"),
    ("AES", "ENCRYPTION"): ("AES-256-GCM (avoid ECB/CBC-without-HMAC)", "NIST131A-003", "low"),
    ("RSA", "ENCRYPTION"): ("RSA-OAEP or hybrid AES-GCM + ECDH", "NIST131A-001", "high"),
    ("RSA", "KEY_EXCHANGE"): ("ECDH P-256/P-384 or ML-KEM", "NIST131A-001", "high"),
    ("RSA", "KEY_AGREEMENT"): ("ECDH or ML-KEM (FIPS 203)", "NIST131A-005", "high"),
    ("RSA", "SIGNING"): ("RSA-PSS (2048+) or ECDSA P-256 / ML-DSA", "NIST131A-001", "medium"),
    ("DSA", "SIGNING"): ("ECDSA P-256 or ML-DSA", "NIST131A-001", "medium"),
    ("ECDSA", "SIGNING"): ("ECDSA P-256+ or ML-DSA (FIPS 204)", "NIST131A-001", "low"),
    ("MD5", "HASHING"): ("SHA-256", "NIST131A-002", "low"),
    ("SHA-1", "HASHING"): ("SHA-256", "NIST131A-002", "low"),
    ("SHA1", "HASHING"): ("SHA-256", "NIST131A-002", "low"),
    ("ECB", "ENCRYPTION"): ("GCM or CTR-then-HMAC", "NIST131A-003", "medium"),
}


_DEFAULT = ("Review against current NIST SP 800-131A guidance", "BASELINE-001", "medium")


def _failed_rules(finding: Mapping[str, Any]) -> list[str]:
    evaluation = finding.get("policy_evaluation") or {}
    ids = []
    for rule in evaluation.get("rules_evaluated") or []:
        if str(rule.get("evaluation_result") or "").upper() == "FAIL":
            if rule.get("rule_id"):
                ids.append(str(rule["rule_id"]))
    return ids


def _include(finding: Mapping[str, Any]) -> bool:
    status = str(finding.get("compliance_status") or "").upper()
    if status == "FAIL":
        return True
    if finding.get("is_hardcoded_key"):
        return True
    algorithm = str(finding.get("algorithm") or "").upper()
    return algorithm in {"DES", "3DES", "DESEDE", "RC4", "RC2", "MD5", "SHA-1", "SHA1"}


def build_work_orders(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for finding in findings:
        if not _include(finding):
            continue
        algorithm = str(finding.get("algorithm") or "UNKNOWN").upper()
        purpose = str(finding.get("purpose") or "UNKNOWN").upper()
        groups[(algorithm, purpose)].append(finding)

    orders = []
    for index, ((algorithm, purpose), members) in enumerate(sorted(groups.items()), start=1):
        replacement, default_rule, effort = _REPLACEMENTS.get((algorithm, purpose), _DEFAULT)
        if algorithm == "AES" and any(str(m.get("mode") or "").upper() == "ECB" for m in members):
            replacement, default_rule, effort = _REPLACEMENTS[("ECB", "ENCRYPTION")]
        rules = sorted({rid for member in members for rid in _failed_rules(member)} or {default_rule})
        sites = [
            {
                "evidence_id": m.get("evidence_id") or m.get("id"),
                "file_path": m.get("file_path"),
                "line_number": m.get("line_number"),
                "mode": m.get("mode"),
                "key_size": m.get("key_size"),
            }
            for m in members
        ]
        orders.append(
            {
                "work_order_id": f"WO-{index:03d}",
                "algorithm": algorithm,
                "purpose": purpose,
                "sites": len(members),
                "replacement": replacement,
                "effort": effort,
                "failed_rules": rules,
                "locations": sites,
                "title": f"Replace {algorithm} {purpose.lower()} ({len(members)} site{'s' if len(members) != 1 else ''})",
            }
        )

    effort_rank = {"low": 1, "medium": 2, "high": 3}
    return {
        "total_orders": len(orders),
        "total_sites": sum(o["sites"] for o in orders),
        "orders": sorted(orders, key=lambda o: (-effort_rank.get(o["effort"], 0), -o["sites"])),
    }
