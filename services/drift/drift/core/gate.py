"""
Purpose-aware CI / PR drift gate.

A new MD5 in a comment-hash is a warning. A new DES in a payment
encryptor is a merge blocker. Same detector, different verdict.

This never sets overall_status to CRITICAL_FAIL — it returns a
CI decision (PASS / WARN / FAIL) plus optional SARIF for GitHub.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional


BLOCKING_PURPOSES = {
    "ENCRYPTION",
    "KEY_EXCHANGE",
    "KEY_AGREEMENT",
    "SIGNING",
    "KEY_STORAGE",
}

WEAK_ALGORITHMS = {
    "DES",
    "3DES",
    "DESEDE",
    "RC2",
    "RC4",
    "BLOWFISH",
    "MD5",
    "SHA-1",
    "SHA1",
}

WEAK_HASH_ONLY = {"MD5", "SHA-1", "SHA1"}

BLOCKING_DRIFT = {"NEW", "CHANGED", "ADDED", "MODIFIED"}
UPGRADE_TOKENS = {"UPGRADED", "UPGRADE", "STRENGTHENED"}


def _algo(item: Mapping[str, Any]) -> str:
    return str(item.get("algorithm") or item.get("affected_algorithm") or "").upper()


def _purpose(item: Mapping[str, Any]) -> str:
    return str(item.get("purpose") or "").upper()


def _status(item: Mapping[str, Any]) -> str:
    return str(item.get("compliance_status") or "").upper()


def _drift_type(event: Mapping[str, Any]) -> str:
    return str(event.get("drift_type") or event.get("change_type") or "").upper()


def _reason(event: Mapping[str, Any]) -> str:
    details = event.get("drift_details") if isinstance(event.get("drift_details"), dict) else {}
    return str(event.get("reason") or (details or {}).get("reason") or "").upper()


def _is_upgrade(event: Mapping[str, Any]) -> bool:
    blob = _reason(event) + " " + _drift_type(event)
    return any(token in blob for token in UPGRADE_TOKENS)


def _location(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "file_path": item.get("file_path") or (item.get("drift_details") or {}).get("file_path"),
        "line_number": item.get("line_number") or (item.get("drift_details") or {}).get("line_number") or 0,
        "algorithm": _algo(item) or None,
        "purpose": _purpose(item) or None,
    }


def evaluate_gate(
    findings: Iterable[Mapping[str, Any]],
    drift_events: Optional[Iterable[Mapping[str, Any]]] = None,
    *,
    require_baseline: bool = False,
) -> dict[str, Any]:
    findings = list(findings)
    events = list(drift_events or [])
    blocking: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for finding in findings:
        algo = _algo(finding)
        purpose = _purpose(finding)
        failed = _status(finding) == "FAIL"
        weak = algo in WEAK_ALGORITHMS
        if finding.get("is_hardcoded_key") and purpose in BLOCKING_PURPOSES:
            blocking.append(
                {
                    "code": "HARDCODED_KEY",
                    "message": f"Hardcoded key material in {purpose or 'crypto'} site",
                    **_location(finding),
                }
            )
            continue
        if failed and purpose in BLOCKING_PURPOSES and (weak or algo == "AES" and str(finding.get("mode") or "").upper() == "ECB"):
            blocking.append(
                {
                    "code": "WEAK_CRYPTO",
                    "message": f"{algo} {purpose} fails policy",
                    **_location(finding),
                }
            )
        elif failed and (purpose == "HASHING" or algo in WEAK_HASH_ONLY):
            warnings.append(
                {
                    "code": "WEAK_HASH",
                    "message": f"{algo} hashing fails policy",
                    **_location(finding),
                }
            )
        elif failed:
            warnings.append(
                {
                    "code": "POLICY_FAIL",
                    "message": f"{algo or 'finding'} compliance FAIL",
                    **_location(finding),
                }
            )

    if require_baseline and not events:
        warnings.append(
            {
                "code": "NO_BASELINE",
                "message": "No approved baseline — drift not compared",
                "file_path": None,
                "line_number": 0,
                "algorithm": None,
                "purpose": None,
            }
        )

    for event in events:
        dtype = _drift_type(event)
        algo = _algo(event)
        purpose = _purpose(event) or str((event.get("drift_details") or {}).get("purpose") or "").upper()
        loc = _location(event)
        if _is_upgrade(event):
            warnings.append(
                {
                    "code": "UPGRADE",
                    "message": event.get("reason") or "Cryptographic upgrade detected",
                    **loc,
                }
            )
            continue
        if dtype in BLOCKING_DRIFT and (purpose in BLOCKING_PURPOSES or algo in WEAK_ALGORITHMS - WEAK_HASH_ONLY):
            blocking.append(
                {
                    "code": f"DRIFT_{dtype}",
                    "message": event.get("reason") or f"{dtype} {algo} {purpose}".strip(),
                    **loc,
                }
            )
        elif dtype in BLOCKING_DRIFT:
            warnings.append(
                {
                    "code": f"DRIFT_{dtype}",
                    "message": event.get("reason") or f"{dtype} {algo}".strip(),
                    **loc,
                }
            )
        elif dtype in {"REMOVED", "DELETED"}:
            warnings.append(
                {
                    "code": "DRIFT_REMOVED",
                    "message": event.get("reason") or f"Removed {algo}",
                    **loc,
                }
            )

    if blocking:
        decision = "FAIL"
    elif warnings:
        decision = "WARN"
    else:
        decision = "PASS"

    summary = (
        f"{decision}: {len(blocking)} blocking, {len(warnings)} warning"
        f"{'' if decision != 'FAIL' else ' — do not merge'}"
    )
    return {
        "decision": decision,
        "summary": summary,
        "blocking": blocking,
        "warnings": warnings,
        "counts": {
            "findings": len(findings),
            "drift_events": len(events),
            "blocking": len(blocking),
            "warnings": len(warnings),
        },
    }


def gate_to_sarif(gate: Mapping[str, Any], *, scan_id: str = "") -> dict[str, Any]:
    results = []
    for item in list(gate.get("blocking") or []):
        results.append(_sarif_result(item, level="error"))
    for item in list(gate.get("warnings") or []):
        results.append(_sarif_result(item, level="warning"))
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CryptoScan",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/ZKChainForge/CryproScan",
                        "rules": [
                            {
                                "id": "CRYPTOSCAN-GATE",
                                "shortDescription": {"text": "Purpose-aware cryptographic drift gate"},
                            }
                        ],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": gate.get("decision") != "FAIL",
                        "properties": {"scan_id": scan_id, "decision": gate.get("decision")},
                    }
                ],
            }
        ],
    }


def _sarif_result(item: Mapping[str, Any], *, level: str) -> dict[str, Any]:
    uri = item.get("file_path") or "unknown"
    line = int(item.get("line_number") or 1) or 1
    return {
        "ruleId": item.get("code") or "CRYPTOSCAN-GATE",
        "level": level,
        "message": {"text": item.get("message") or "cryptographic gate finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
