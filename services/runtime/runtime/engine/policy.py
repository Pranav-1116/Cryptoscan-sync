"""Runtime crypto policy, risk and PQC readiness (spec 92 §11, §31).

Rules apply to *observed* operations only. A process with no event is a blind
spot, not a compliant one, and a Level 4 network observation is judged as a
transport fact — never as the application's bulk cipher choice.

The pack is deliberately small and explicit: each rule names the algorithm
family it judges and the parameter it needs. When the parameter was not
reported, the rule returns ``UNKNOWN`` with its own reason instead of a verdict.
"""

from __future__ import annotations

from typing import Any, Iterable

MODEL = "cryptoscan.runtime-risk/1"
POLICY_ID = "cryptoscan.bank-runtime-crypto-baseline"
POLICY_VERSION = "1.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DEFAULT_RUNTIME_POLICY: dict[str, Any] = {
    "policy_id": POLICY_ID,
    "version": POLICY_VERSION,
    "forbidden_algorithms": ["DES", "3DES", "RC4", "RC2", "MD5", "MD4", "SHA1", "SHA-1", "BLOWFISH", "IDEA"],
    "forbidden_modes": ["ECB"],
    "min_rsa_bits": 2048,
    "min_dh_bits": 2048,
    "min_ecc_bits": 224,
    "require_aead_for_encryption": False,
    "forbidden_tls_versions": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"],
}

#: families whose weak members are judged by key size
_RSA_TOKENS = ("RSA",)
_ECC_TOKENS = ("ECDSA", "ECDH", "ECIES", "ED25519", "ED448", "X25519", "ECDHE")

#: post-quantum / hybrid names observable at runtime
PQC_TOKENS = ("MLKEM", "KYBER", "ML_DSA", "DILITHIUM", "FALCON", "SPHINCS", "HYBRID")

CLASSICAL_PUBLIC_KEY = ("RSA", "ECDSA", "ECDH", "ED25519", "ED448", "X25519", "ECDHE", "DSA")


def _norm(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", "").replace("_", "")


def merge_policy(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    merged = dict(DEFAULT_RUNTIME_POLICY)
    for key, value in (policy or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _finding(
    rule_id: str,
    severity: str,
    status: str,
    event: dict[str, Any],
    message: str,
    *,
    observed: Any = None,
    expected: Any = None,
    reference: str | None = None,
) -> dict[str, Any]:
    identity = event.get("identity") or {}
    return {
        "rule_id": rule_id,
        "severity": severity,
        "status": status,
        "layer": "RUNTIME",
        "attribution_level": event.get("attribution_level"),
        "source": event.get("source"),
        "application": identity.get("application"),
        "process": identity.get("process"),
        "host": identity.get("host"),
        "event_id": event.get("event_id"),
        "algorithm": event.get("algorithm"),
        "operation": event.get("operation"),
        "observed": observed,
        "expected": expected,
        "message": message,
        "reference": reference,
        "observed_at": event.get("observed_at"),
    }


def _weak_algorithm_rules(event: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    algorithm = _norm(event.get("algorithm"))
    forbidden = [_norm(item) for item in policy.get("forbidden_algorithms") or []]
    hit = next((item for item in forbidden if item and item in algorithm), None)
    if algorithm:
        if hit:
            findings.append(
                _finding(
                    "RT-ALGORITHM-FORBIDDEN",
                    "critical" if hit in {"DES", "3DES", "RC4", "RC2", "MD5", "MD4"} else "high",
                    "FAIL",
                    event,
                    f"{event.get('algorithm')} is on the forbidden list",
                    observed=event.get("algorithm"),
                    expected="AES-GCM / SHA-256 or stronger",
                    reference="NIST SP 800-131A",
                )
            )
        else:
            findings.append(
                _finding(
                    "RT-ALGORITHM-FORBIDDEN",
                    "high",
                    "PASS",
                    event,
                    f"{event.get('algorithm')} is not on the forbidden list",
                    observed=event.get("algorithm"),
                    expected="AES-GCM / SHA-256 or stronger",
                )
            )

    mode = _norm((event.get("decomposition") or {}).get("mode"))
    forbidden_modes = [_norm(item) for item in policy.get("forbidden_modes") or []]
    if mode and mode in forbidden_modes:
        findings.append(
            _finding(
                "RT-MODE-ECB",
                "high",
                "FAIL",
                event,
                f"{event.get('algorithm')} runs in {mode} mode: identical blocks produce identical "
                "ciphertext, so structure leaks",
                observed=mode,
                expected="GCM / CBC-with-MAC",
                reference="NIST SP 800-38A",
            )
        )
    return findings


def _key_size_rules(event: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    algorithm = _norm(event.get("algorithm"))
    key_size = event.get("key_size")
    if not algorithm:
        return findings
    family = (
        "RSA" if any(token in algorithm for token in _RSA_TOKENS)
        else "ECC" if any(token in algorithm for token in _ECC_TOKENS)
        else None
    )
    if family is None:
        return findings
    if key_size in (None, "UNKNOWN"):
        findings.append(
            _finding(
                "RT-KEY-SIZE",
                "medium",
                "UNKNOWN",
                event,
                f"{event.get('algorithm')} was observed but its key size was not reported; the size is "
                "NOT inferred from the algorithm name",
                observed="UNKNOWN",
                expected=f">= {policy['min_rsa_bits']} bits",
            )
        )
        return findings
    floor = int(policy["min_rsa_bits"] if family == "RSA" else policy["min_ecc_bits"])
    try:
        bits = int(key_size)
    except (TypeError, ValueError):
        return findings
    if bits < floor:
        findings.append(
            _finding(
                "RT-KEY-SIZE",
                "critical" if bits < 2048 else "high",
                "FAIL",
                event,
                f"{event.get('algorithm')} runs with a {bits}-bit key: below the {floor}-bit floor",
                observed=bits,
                expected=f">= {floor} bits",
                reference="NIST SP 800-57 Part 1",
            )
        )
    return findings


def _aead_rule(event: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    if not policy.get("require_aead_for_encryption"):
        return []
    if str(event.get("operation")) not in {"ENCRYPT", "DECRYPT"}:
        return []
    mode = _norm((event.get("decomposition") or {}).get("mode"))
    if not mode or mode == "UNKNOWN":
        return [
            _finding(
                "RT-AEAD",
                "medium",
                "UNKNOWN",
                event,
                "the mode was not reported, so authenticated encryption cannot be confirmed",
                observed="UNKNOWN",
                expected="GCM / CCM / ChaCha20-Poly1305",
            )
        ]
    if mode in {"GCM", "CCM", "POLY1305", "CHACHA20POLY1305"}:
        return [
            _finding("RT-AEAD", "high", "PASS", event, f"{mode} is authenticated encryption",
                     observed=mode, expected="GCM / CCM / ChaCha20-Poly1305")
        ]
    return [
        _finding(
            "RT-AEAD",
            "high",
            "FAIL",
            event,
            f"{mode} is not authenticated encryption: integrity must be added by a separate MAC",
            observed=mode,
            expected="GCM / CCM / ChaCha20-Poly1305",
        )
    ]


def evaluate_runtime(
    events: Iterable[dict[str, Any]],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score observed runtime operations; blind spots stay blind spots."""
    effective = merge_policy(policy)
    events = list(events)
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    applications: set[str] = set()

    for event in events:
        identity = event.get("identity") or {}
        if identity.get("application"):
            applications.add(str(identity["application"]))
        if int(event.get("attribution_level") or 6) == 6 or not event.get("algorithm"):
            gaps.append(
                {
                    "rule_id": "RT-OBSERVATION-GAP",
                    "severity": "info",
                    "status": "UNKNOWN",
                    "layer": "RUNTIME",
                    "application": identity.get("application"),
                    "process": identity.get("process"),
                    "host": identity.get("host"),
                    "event_id": event.get("event_id"),
                    "attribution_level": event.get("attribution_level"),
                    "message": "Level 6 or algorithm-less observation: this code path is a blind spot, "
                    "not a clean result",
                    "observed_at": event.get("observed_at"),
                }
            )
            continue
        findings.extend(_weak_algorithm_rules(event, effective))
        findings.extend(_key_size_rules(event, effective))
        findings.extend(_aead_rule(event, effective))

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in findings + gaps:
        by_status[finding["status"]] = by_status.get(finding["status"], 0) + 1
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
    failed = sorted(
        [item for item in findings if item["status"] == "FAIL"],
        key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["rule_id"]),
    )
    verdict = (
        "NO_EVIDENCE"
        if not events
        else "FAIL"
        if failed
        else "NOT_ASSESSABLE"
        if gaps and not [item for item in findings if item["status"] == "PASS"]
        else "PASS_WITH_UNKNOWN"
        if [item for item in findings if item["status"] == "UNKNOWN"] or gaps
        else "PASS"
    )
    return {
        "model": MODEL,
        "policy": {"policy_id": effective["policy_id"], "version": effective["version"]},
        "layer": "RUNTIME",
        "verdict": verdict,
        "findings": findings + gaps,
        "failed": failed,
        "coverage_gaps": gaps,
        "summary": {
            "events": len(events),
            "applications": len(applications),
            "by_status": by_status,
            "by_severity": by_severity,
            "failed": len(failed),
            "unknown": len(gaps) + len([item for item in findings if item["status"] == "UNKNOWN"]),
            "rules": sorted({item["rule_id"] for item in findings + gaps}),
        },
        "limitations": [
            "only observed operations are judged — a process with no event is NOT_OBSERVED, not compliant",
            "a Level 4 network observation is a transport fact and is never scored as application crypto",
            "key size, padding and mode are never inferred; an unreported parameter stays UNKNOWN",
        ],
    }


def runtime_pqc_readiness(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Which public-key operations are quantum-vulnerable, from runtime facts."""
    rows: list[dict[str, Any]] = []
    signature_counts: dict[str, int] = {}
    key_agreement_counts: dict[str, int] = {}
    pqc_count = 0
    unknown = 0

    for event in events:
        algorithm = _norm(event.get("algorithm"))
        operation = str(event.get("operation"))
        if not algorithm:
            unknown += 1
            rows.append(
                {
                    "event_id": event.get("event_id"),
                    "application": (event.get("identity") or {}).get("application"),
                    "operation": operation,
                    "readiness": "NOT_OBSERVED",
                    "note": "algorithm not reported — readiness is unknown",
                }
            )
            continue
        hybrid = any(token in algorithm for token in PQC_TOKENS)
        classical = any(token in algorithm for token in CLASSICAL_PUBLIC_KEY)
        if hybrid:
            readiness = "POST_QUANTUM_OR_HYBRID"
            pqc_count += 1
        elif classical:
            readiness = "QUANTUM_VULNERABLE"
        elif event.get("algorithm"):
            readiness = "SYMMETRIC_NOT_AT_RISK"
        else:
            readiness = "NOT_OBSERVED"
        if operation in {"SIGN", "VERIFY"}:
            signature_counts[str(event.get("algorithm"))] = signature_counts.get(str(event.get("algorithm")), 0) + 1
        if operation in {"KEY_AGREEMENT", "KEY_GENERATION", "TLS_HANDSHAKE"}:
            key_agreement_counts[str(event.get("algorithm"))] = (
                key_agreement_counts.get(str(event.get("algorithm")), 0) + 1
            )
        rows.append(
            {
                "event_id": event.get("event_id"),
                "application": (event.get("identity") or {}).get("application"),
                "operation": operation,
                "algorithm": event.get("algorithm"),
                "key_size": event.get("key_size"),
                "readiness": readiness,
                "note": (
                    "classical public-key operation: harvest-now-decrypt-later exposed"
                    if readiness == "QUANTUM_VULNERABLE"
                    else "symmetric primitive — the quantum risk sits in the key agreement that protects it"
                    if readiness == "SYMMETRIC_NOT_AT_RISK"
                    else "hybrid/PQ operation observed"
                    if readiness == "POST_QUANTUM_OR_HYBRID"
                    else "not observed"
                ),
            }
        )

    vulnerable = len([row for row in rows if row["readiness"] == "QUANTUM_VULNERABLE"])
    return {
        "model": "cryptoscan.runtime-pqc-readiness/1",
        "layer": "RUNTIME",
        "events": rows,
        "summary": {
            "events": len(rows),
            "quantum_vulnerable": vulnerable,
            "post_quantum_or_hybrid": pqc_count,
            "symmetric": len([row for row in rows if row["readiness"] == "SYMMETRIC_NOT_AT_RISK"]),
            "not_observed": unknown,
            "signature_algorithms": signature_counts,
            "key_agreement": key_agreement_counts,
        },
        "verdict": (
            "NOT_OBSERVED"
            if not rows
            else "HYBRID_PRESENT"
            if pqc_count and not vulnerable
            else "PARTIAL"
            if pqc_count
            else "CLASSICAL_ONLY"
            if vulnerable
            else "SYMMETRIC_ONLY"
        ),
        "limitations": [
            "runtime observation shows the operation, not the library's migration roadmap",
            "symmetric encryption is not quantum-broken, but the key agreement that protected it is",
            "a process that ran no public-key operation proves nothing about its future behaviour",
        ],
    }
