"""Finding -> policy -> compliance pipeline (real data flow).

Turns live scanner findings into policy-as-code targets, evaluates the merged
policy stack, classifies each finding via the crypto knowledge base, and maps
gaps to compliance controls. This is the bridge between the universal engine
output and the P1 policy/compliance layer — deterministic, no AI in the loop.
"""

from __future__ import annotations

from control_plane.compliance import framework_posture
from control_plane.knowledge import is_deprecated_or_worse, lookup
from control_plane.policy_as_code import evaluate_policy, merge_policy_layers


def finding_to_target(finding: dict) -> dict:
    """Map a runtime/scan finding onto the attribute shape policies read."""
    tls_version = finding.get("tls_version")
    return {
        "algorithm": finding.get("algorithm"),
        "key_size": finding.get("key_size") or finding.get("key_bits"),
        "cipher": finding.get("cipher_suite") or finding.get("cipher"),
        "tls": {"version": _tls_float(tls_version)},
        "tls_version_raw": tls_version,
        "status": (finding.get("status") or "").upper(),
        "weak": bool(finding.get("weak_tls") or finding.get("weak")),
        "asset": finding.get("hostname") or finding.get("asset_id") or finding.get("asset"),
        "asset_id": finding.get("asset_id") or finding.get("asset") or finding.get("hostname"),
        "sector": finding.get("sector"),
        "environment": finding.get("environment"),
        "region": finding.get("region"),
    }


def _tls_float(v) -> float | None:
    if v is None:
        return None
    try:
        s = str(v).lower().replace("tls", "").replace("v", "").strip()
        return float(s)
    except (ValueError, TypeError):
        return None


def classify_finding(finding: dict) -> dict:
    """Deterministic classification of a finding using the crypto KB."""
    algo = finding.get("algorithm")
    key_size = finding.get("key_size") or finding.get("key_bits")
    entry = lookup(algo, key_size) if algo else None
    is_risk = bool(
        finding.get("weak_tls") or finding.get("weak")
        or (finding.get("status") or "").upper() in {"DISALLOWED", "DEPRECATED", "WEAK"}
        or (entry is not None and is_deprecated_or_worse(algo, key_size))
    )
    return {
        "is_risk": is_risk,
        "kb_status": entry.get("status") if entry else "unknown",
        "migration": entry.get("migration") if entry else None,
        "pqc": bool(entry.get("pqc")) if entry else False,
    }


#: crypto-risk finding attributes -> the compliance control they violate.
#: Mirrors sector_profiles.compliance keyword mapping at the control level.
_CONTROL_FOR_KEYWORD = {
    "tls1.0": ("NIST-CSF", "SC-8"), "tls1.1": ("NIST-CSF", "SC-8"),
    "sslv3": ("NIST-CSF", "SC-8"), "rc4": ("PCI-DSS", "PCI-DSS-4.2.1"),
    "3des": ("PCI-DSS", "PCI-DSS-4.2.1"),
    "rsa-1024": ("NIST-CSF", "SC-12"), "rsa-1024-": ("NIST-CSF", "SC-12"),
    "sha-1": ("FIPS-140-3", "FIPS-140-3"), "md5": ("FIPS-140-3", "FIPS-140-3"),
    "weak": ("NIST-CSF", "SC-8"), "disallowed": ("NIST-CSF", "SC-8"),
    "deprecated": ("NIST-CSF", "SC-13"),
}


def _control_for_finding(finding: dict, classification: dict) -> tuple[str, str] | None:
    algo = str(finding.get("algorithm") or "").lower()
    status = str(finding.get("status") or "").lower()
    tls = str(finding.get("tls_version") or "").lower()
    cipher = str(finding.get("cipher_suite") or "").lower()
    blob = f"{algo} {status} {tls} {cipher}"
    if "1.0" in tls or "tls1.0" in blob.replace(" ", ""):
        return _CONTROL_FOR_KEYWORD["tls1.0"]
    if "1.1" in tls:
        return _CONTROL_FOR_KEYWORD["tls1.1"]
    if "rsa" in blob and ("1024" in blob or classification.get("kb_status") == "broken"):
        return _CONTROL_FOR_KEYWORD["rsa-1024"]
    if "3des" in blob:
        return _CONTROL_FOR_KEYWORD["3des"]
    if "rc4" in blob:
        return _CONTROL_FOR_KEYWORD["rc4"]
    if "sha-1" in blob or "sha1" in blob:
        return _CONTROL_FOR_KEYWORD["sha-1"]
    if "md5" in blob:
        return _CONTROL_FOR_KEYWORD["md5"]
    if "disallow" in blob:
        return _CONTROL_FOR_KEYWORD["disallowed"]
    if "deprecat" in blob:
        return _CONTROL_FOR_KEYWORD["deprecated"]
    if classification.get("is_risk"):
        return ("NIST-CSF", "SC-13")
    return None


def run_pipeline(findings: list[dict], policy_layers: list[dict],
                 controls: list[dict] | None = None) -> dict:
    """Evaluate findings against the merged policy stack and compute
    compliance posture + per-finding verdicts in one deterministic pass."""
    merged = merge_policy_layers(*policy_layers)
    results, compliance_findings = [], []
    risks = 0
    for f in findings:
        target = finding_to_target(f)
        verdict = evaluate_policy(merged, target)
        classification = classify_finding(f)
        is_risk = verdict.verdict in {"FAIL", "WARN"} or classification["is_risk"]
        if is_risk:
            risks += 1
            mapping = _control_for_finding(f, classification)
            if mapping:
                framework, control_id = mapping
                compliance_findings.append({
                    "framework": framework, "control_id": control_id,
                    "asset_id": target.get("asset_id"), "status": "open",
                    "severity": "high" if verdict.verdict == "FAIL" else "medium",
                })
        results.append({
            "asset": target.get("asset"), "asset_id": target.get("asset_id"),
            "verdict": verdict.verdict, "is_risk": is_risk,
            "kb_status": classification["kb_status"],
            "migration": classification["migration"], "pqc": classification["pqc"],
            "rules": [r for r in verdict.to_dict()["rules"] if r["verdict"] in {"FAIL", "WARN"}],
        })

    posture = None
    if controls is not None:
        control_dicts = [{"id": c.control_id if hasattr(c, "control_id") else c.get("control_id") or c.get("id"),
                          "framework": c.framework if hasattr(c, "framework") else c.get("framework"),
                          "assets": c.assets if hasattr(c, "assets") else c.get("assets", [])}
                         for c in controls]
        mapped = [{"control_id": cf["control_id"], "asset_id": cf["asset_id"], "status": cf["status"]}
                  for cf in compliance_findings]
        posture = framework_posture(control_dicts, mapped, [])

    return {
        "total_findings": len(findings),
        "risks": risks,
        "policy_version": merged.get("version"),
        "verdicts": results,
        "compliance_findings": compliance_findings,
        "posture": posture,
    }
