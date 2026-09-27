"""Deterministic checks for 5G user-plane N3/N9 evidence.

N3 (gNB to UPF) and N9 (UPF to UPF) carry GTP-U, normally UDP/2152. This
module deliberately does not emit GTP packets or claim to have observed a
carrier network. It classifies an operator-side probe/capture summary supplied
through the telecom ingest path. Missing evidence is ``UNKNOWN`` rather than a
fabricated pass or failure.

The checks cover the controls that can be proven from a bounded evidence
record: GTP-U identity/port, presence of IPsec or an explicitly equivalent
protected transport, IKE version, DH floor, encryption and integrity. Raw
packets and keys are never accepted or persisted by this classifier.
"""

from __future__ import annotations

from typing import Any, Mapping

_REF_33501 = "3GPP TS 33.501 (5G security)"
_REF_33210 = "3GPP TS 33.210 (NDS/IP)"

_WEAK = ("DES", "3DES", "RC4", "NULL", "ECB", "MD5", "SHA1", "SHA-1")
_ALLOWED_ENCRYPTION = ("AES-GCM", "AES-CCM", "CHACHA20-POLY1305")


def is_user_plane_target(target: Mapping[str, Any]) -> bool:
    """Whether a registered target declares an N3/N9 user-plane interface."""
    interface = str(
        target.get("interface") or target.get("reference_point") or target.get("n_interface") or ""
    ).strip().upper()
    return interface in {"N3", "N9"} or bool(target.get("user_plane"))


def _finding(code: str, severity: str, message: str, ref: str = _REF_33501) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message, "ref": ref}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _ipsec_findings(ipsec: Mapping[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    ike_version = _text(ipsec.get("ike_version") or ipsec.get("version"))
    if ike_version and ike_version.lower() not in {"ikev2", "2"}:
        findings.append(_finding(
            "user_plane.ike_version_weak", "critical",
            f"{ike_version} reported on an N3/N9 protection association; IKEv2 is required",
            _REF_33210,
        ))
    encryption = _text(ipsec.get("encryption") or ipsec.get("cipher")).upper()
    if encryption and any(token in encryption for token in _WEAK):
        findings.append(_finding(
            "user_plane.ipsec_encryption_weak", "critical",
            f"Weak or unauthenticated IPsec encryption reported ({encryption})",
            _REF_33210,
        ))
    elif encryption and not any(token in encryption for token in _ALLOWED_ENCRYPTION):
        findings.append(_finding(
            "user_plane.ipsec_encryption_unapproved", "high",
            f"IPsec encryption is not in the approved AEAD set ({encryption})",
            _REF_33210,
        ))
    integrity = _text(ipsec.get("integrity") or ipsec.get("auth")).upper()
    if any(token in integrity for token in ("MD5", "SHA1", "SHA-1", "NULL")):
        findings.append(_finding(
            "user_plane.ipsec_integrity_weak", "critical",
            f"Weak or null IPsec integrity reported ({integrity})",
            _REF_33210,
        ))
    groups = ipsec.get("dh_groups") or ipsec.get("dh_group") or []
    if isinstance(groups, (str, int)):
        groups = [groups]
    weak_groups: list[str] = []
    for group in groups:
        digits = "".join(ch for ch in str(group) if ch.isdigit())
        if digits and int(digits) < 14:
            weak_groups.append(str(group))
    if weak_groups:
        findings.append(_finding(
            "user_plane.ipsec_dh_weak", "critical",
            f"DH group(s) below the 2048-bit floor: {', '.join(weak_groups)}",
            _REF_33210,
        ))
    return findings


def assess_user_plane(
    target: Mapping[str, Any],
    evidence: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Assess one N3/N9 evidence record without active probing.

    Accepted evidence is a summary shape, for example::

        {"status": "OBSERVED", "protocol": "GTP-U", "port": 2152,
         "ipsec": {"enabled": True, "ike_version": "IKEv2",
                   "encryption": "AES-GCM-256", "integrity": "SHA-256",
                   "dh_groups": [19]}}

    ``ipsec.enabled=false`` is a real cleartext observation and is critical;
    an absent ``ipsec`` block is unknown and requests operator evidence.
    """
    interface = _text(
        target.get("interface") or target.get("reference_point") or target.get("n_interface")
    ).upper() or "N3/N9"
    if interface not in {"N3", "N9", "N3/N9"}:
        interface = "N3/N9"
    if not evidence:
        return {
            "interface": interface,
            "protocol": "GTP-U",
            "status": "USER_PLANE_UNKNOWN",
            "protected": None,
            "findings": [_finding(
                "user_plane.ingest_required", "info",
                f"{interface} requires an operator-side GTP-U/IPsec evidence record; no active user-plane probe was performed",
            )],
        }

    data = dict(evidence)
    status = _text(data.get("status") or "OBSERVED").upper()
    findings: list[dict[str, str]] = []
    protocol = _text(data.get("protocol") or data.get("transport") or "").upper()
    if protocol and protocol not in {"GTP-U", "GTPU", "GTP"}:
        findings.append(_finding(
            "user_plane.protocol_unexpected", "high",
            f"Expected GTP-U on {interface}; evidence identifies {protocol}",
        ))
    elif not protocol:
        findings.append(_finding(
            "user_plane.protocol_unverified", "info",
            f"GTP-U protocol identity was not included in the {interface} evidence",
        ))

    port = data.get("port") or data.get("udp_port")
    if port is not None:
        try:
            if int(port) != 2152:
                findings.append(_finding(
                    "user_plane.port_unexpected", "medium",
                    f"GTP-U evidence uses UDP/{port}; the standard user-plane port is UDP/2152",
                ))
        except (TypeError, ValueError):
            findings.append(_finding("user_plane.port_invalid", "medium", f"Invalid user-plane port value: {port}"))

    ipsec = data.get("ipsec")
    if ipsec is None:
        # ``protected=false`` is an explicit observation; absent protection
        # metadata is not silently treated as cleartext.
        if data.get("protected") is False or data.get("encrypted") is False:
            protected: bool | None = False
            findings.append(_finding(
                "user_plane.gtp_u_cleartext", "critical",
                f"GTP-U on {interface} was observed without IPsec/equivalent protection",
            ))
        else:
            protected = None
            findings.append(_finding(
                "user_plane.protection_unverified", "info",
                f"No IPsec/equivalent protection result was supplied for {interface}; posture is unknown",
            ))
    else:
        if not isinstance(ipsec, Mapping):
            ipsec = {"enabled": bool(ipsec)}
        protected = bool(ipsec.get("enabled") or ipsec.get("protected"))
        if not protected:
            findings.append(_finding(
                "user_plane.gtp_u_cleartext", "critical",
                f"GTP-U on {interface} was observed without IPsec protection",
            ))
        else:
            findings.extend(_ipsec_findings(ipsec))
            if not findings or all(item["severity"] in {"info"} for item in findings):
                findings.append(_finding(
                    "user_plane.ipsec_present", "info",
                    f"IPsec protection is present on {interface}; supplied parameters meet the checked floors",
                    _REF_33210,
                ))

    severity_order = {"info": 0, "medium": 1, "high": 2, "critical": 3}
    severity = max((item["severity"] for item in findings), key=lambda value: severity_order[value], default="info")
    return {
        "interface": interface,
        "protocol": "GTP-U" if protocol in {"GTP-U", "GTPU", "GTP"} else protocol or None,
        "status": "USER_PLANE_OBSERVED" if status not in {"TIMEOUT", "UNREACHABLE", "ERROR"} else "USER_PLANE_UNKNOWN",
        "protected": protected,
        "severity": severity,
        "findings": findings,
        "evidence_status": status,
    }
