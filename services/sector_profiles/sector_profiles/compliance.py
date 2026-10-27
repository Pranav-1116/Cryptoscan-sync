"""Map crypto findings onto a sector's compliance frameworks.

The universal engine produces policy results (PASS/FAIL/WARN against policy
packs). This module deterministically maps those results onto the sector's
compliance frameworks — e.g. a failed TLS/payment finding in banking is a
PCI-DSS control gap; a SCADA crypto finding in energy maps to NERC-CIP.

It does NOT decide compliance (the YAML policy engine does that). It only
attributes a failing/weak finding to the framework controls the sector cares
about, so reports can show "findings mapped per framework" honestly.
"""

from __future__ import annotations

from typing import Any

from sector_profiles.catalog import get_profile

#: keyword (from algorithm/protocol/policy id/detail) -> framework controls.
#: Each control tuple is (framework, control_id, control_text).
_CONTROL_RULES: tuple[tuple[tuple[str, ...], tuple[tuple[str, str, str], ...]], ...] = (
    (("tls1.0", "tls1.1", "sslv3", "ssl3", "3des", "rc4"), (
        ("PCI-DSS", "PCI-DSS-4.2.1", "Strong cryptography for cardholder data in transit"),
        ("NIST-CSF", "SC-8", "Transmission confidentiality (TLS 1.2+)"),
        ("NERC-CIP", "CIP-007-6 R1.3", "Encrypt interactive remote access"),
        ("HIPAA", "164.312(e)(1)", "Transmission security"),
        ("IEC-62443", "SR 4.1", "Communication confidentiality"),
    )),
    (("rsa", "key-1024", "1024", "sha-1", "sha1", "md5"), (
        ("PCI-DSS", "PCI-DSS-4.2.1", "Strong cryptographic keys (>=2048-bit RSA / SHA-256)"),
        ("NIST-CSF", "SC-12", "Cryptographic key strength"),
        ("FIPS-140-3", "FIPS-140-3", "Approved algorithm/module use"),
        ("SWIFT-CSCF", "SWIFT-CSCF-2.3", "HSM / strong key management"),
        ("FedRAMP", "SC-13", "Use of FIPS-validated cryptography"),
    )),
    (("payment", "pos", "hsm", "swift", "card"), (
        ("PCI-DSS", "PCI-DSS-3.5.1", "Key management / HSM protection of stored keys"),
        ("SWIFT-CSCF", "SWIFT-CSCF-2.x", "HSM and key ceremony controls"),
        ("GLBA", "501(b)", "Safeguards for financial customer data"),
    )),
    (("scada", "ics", "plc", "rtu", "substation", "ot"), (
        ("NERC-CIP", "CIP-007-6", "System security management (ports/services/crypto)"),
        ("NIST-800-82", "6.3", "OT cryptographic protection"),
        ("IEC-62443", "SR 4.1", "OT communication security"),
    )),
    (("medical", "ehr", "patient", "phi", "imaging"), (
        ("HIPAA", "164.312(a)(2)(iv)", "Encryption/decryption of ePHI"),
        ("HIPAA", "164.312(e)(2)(ii)", "Encryption of ePHI in transit"),
        ("ISO-27799", "9.4.4", "Health data cryptographic controls"),
    )),
    (("v2x", "ecu", "firmware", "ota", "vehicle"), (
        ("ISO-21434", "7.5", "Cybersecurity risk treatment (crypto)"),
        ("UNECE-R155/R156", "R155-7.3", "Vehicle cybersecurity / secure update"),
    )),
    (("kms", "key_vault", "keyvault", "cloud_key", "secrets"), (
        ("SOC2", "CC6.1", "Logical access — key management controls"),
        ("CSA-CCM", "EKM-03", "Key management throughout lifecycle"),
        ("FedRAMP", "SC-12/SC-13", "Key establishment / FIPS cryptography"),
    )),
)


def _finding_text(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("algorithm") or ""),
        str(finding.get("protocol") or ""),
        str(finding.get("rule_id") or finding.get("policy_id") or ""),
        str(finding.get("detail") or finding.get("message") or ""),
        str(finding.get("library") or ""),
        str(finding.get("asset_type") or finding.get("system_name") or ""),
    ]
    return " ".join(parts).lower()


def _finding_is_gap(finding: dict[str, Any]) -> bool:
    """A finding is a control gap when its policy status is FAIL/WARN or the
    engine already flagged it as vulnerable/weak."""
    status = str(finding.get("status") or finding.get("compliance_status") or "").upper()
    if status in {"FAIL", "FAILED", "WARN", "WARNING", "NON_COMPLIANT"}:
        return True
    if finding.get("vulnerable") is True or finding.get("weak") is True:
        return True
    severity = str(finding.get("severity") or "").upper()
    return severity in {"HIGH", "CRITICAL", "MEDIUM"}


def map_findings_to_frameworks(sector: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Attribute failing findings to the sector's compliance frameworks.

    Returns a per-framework breakdown: framework -> {framework, applicable,
    gaps, mapped_findings, status}. Only frameworks in the sector profile are
    reported; status is FAIL if any gap maps to it, else PASS.
    """
    profile = get_profile(sector)
    frameworks = set(profile.compliance_frameworks)

    per_framework: dict[str, dict[str, Any]] = {
        fw: {"framework": fw, "applicable": True, "gaps": 0, "mapped_findings": []}
        for fw in frameworks
    }

    mapped_gap_count = 0
    for finding in findings:
        if not _finding_is_gap(finding):
            continue
        text = _finding_text(finding)
        hit_controls: set[tuple[str, str]] = set()
        for keywords, controls in _CONTROL_RULES:
            if any(k in text for k in keywords):
                for fw, control_id, control_text in controls:
                    if fw in frameworks:
                        hit_controls.add((fw, control_id))
                        per_framework.setdefault(
                            fw, {"framework": fw, "applicable": True, "gaps": 0, "mapped_findings": []}
                        )
                        per_framework[fw]["mapped_findings"].append(
                            {
                                "control": control_id,
                                "control_text": control_text,
                                "algorithm": finding.get("algorithm"),
                                "protocol": finding.get("protocol"),
                                "asset": finding.get("asset_type") or finding.get("system_name"),
                                "severity": str(finding.get("severity") or finding.get("risk_category") or "MEDIUM").upper(),
                            }
                        )
        if hit_controls:
            mapped_gap_count += 1

    # aggregate gaps per framework
    for fw, data in per_framework.items():
        data["gaps"] = len(data["mapped_findings"])
        data["status"] = "FAIL" if data["gaps"] else "PASS"

    framework_rows = sorted(per_framework.values(), key=lambda d: d["framework"])
    failing = [d["framework"] for d in framework_rows if d["status"] == "FAIL"]
    return {
        "sector": profile.id,
        "sector_name": profile.name,
        "frameworks": framework_rows,
        "framework_count": len(framework_rows),
        "frameworks_with_gaps": failing,
        "findings_evaluated": len(findings),
        "findings_mapped_to_gaps": mapped_gap_count,
        "note": "Attribution of policy results to sector frameworks; compliance "
                "status is decided by the deterministic policy engine, not AI.",
    }
