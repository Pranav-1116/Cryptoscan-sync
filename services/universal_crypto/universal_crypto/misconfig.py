"""§23 Crypto misconfiguration detection.

Checks (deterministic catalog): TLS 1.0, weak cipher, RSA key too small,
SHA-1 certificate, expired certificate, weak DH group, unsafe curve, CBC
where policy prohibits it, non-PFS configuration, weak SSH algorithm,
legacy VPN configuration.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_crypto.protocol_engine import _IPSEC_DH

#: safe curves (everything else is flagged when used for key exchange)
_SAFE_CURVES = {"P-256", "P-384", "P-521", "X25519", "X448", "Curve25519",
                "BrainpoolP256r1", "BrainpoolP384r1"}

#: weak SSH algorithms (deprecated ciphers/KEX/MACs)
_WEAK_SSH = {
    "arcfour", "arcfour128", "arcfour256", "3des-cbc", "aes128-cbc",
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "hmac-md5", "hmac-sha1",
}


class MisconfigurationDetector:
    """§23 detection over structured inputs."""

    def check_tls(self, *, tls_version: str = "", cipher_suite: str = "",
                  pfs: Optional[bool] = None,
                  curve: str = "") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if tls_version in ("TLS 1.0", "TLS 1.1"):
            findings.append({"type": "obsolete_tls", "detail": tls_version,
                             "severity": "high"})
        if "RC4" in cipher_suite:
            findings.append({"type": "weak_cipher", "detail": cipher_suite,
                             "severity": "critical"})
        if "_3DES_" in cipher_suite or "_DES_" in cipher_suite:
            findings.append({"type": "weak_cipher", "detail": cipher_suite,
                             "severity": "high"})
        if pfs is False:
            findings.append({"type": "non_pfs", "detail": cipher_suite,
                             "severity": "medium"})
        if curve and curve not in _SAFE_CURVES:
            findings.append({"type": "unsafe_curve", "detail": curve,
                             "severity": "high"})
        return findings

    def check_certificate(self, *, signature_hash: str = "",
                          expired: bool = False,
                          key_algorithm: str = "",
                          key_size: Optional[int] = None) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if signature_hash == "SHA-1":
            findings.append({"type": "sha1_certificate", "detail": "SHA-1 signature",
                             "severity": "high"})
        if signature_hash == "MD5":
            findings.append({"type": "md5_certificate", "detail": "MD5 signature",
                             "severity": "critical"})
        if expired:
            findings.append({"type": "expired_certificate", "detail": "",
                             "severity": "critical"})
        if key_algorithm == "RSA" and key_size and key_size < 2048:
            findings.append({"type": "rsa_key_too_small", "detail": str(key_size),
                             "severity": "high"})
        return findings

    def check_dh(self, *, dh_group: str = "") -> list[dict[str, Any]]:
        if not dh_group:
            return []
        alg = _IPSEC_DH.get(str(dh_group), "")
        weak = str(dh_group) in {"1", "2", "5", "14"} or alg in ("DH-768", "DH-1024", "DH-1536", "DH-2048")
        return [{"type": "weak_dh_group", "detail": f"group {dh_group} ({alg})",
                 "severity": "high"}] if weak else []

    def check_ssh(self, *, ciphers: Optional[list[str]] = None,
                  kex: Optional[list[str]] = None,
                  macs: Optional[list[str]] = None) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for name in list(ciphers or []) + list(kex or []) + list(macs or []):
            if name.lower() in _WEAK_SSH or name.lower() in ("hmac-sha1",):
                findings.append({"type": "weak_ssh_algorithm", "detail": name,
                                 "severity": "medium"})
        return findings

    def check_vpn(self, *, ike_version: str = "", encryption: str = "",
                  pfs: bool = False) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if ike_version == "IKEv1":
            findings.append({"type": "legacy_vpn", "detail": "IKEv1",
                             "severity": "medium"})
        if "3DES" in encryption or "DES" in encryption:
            findings.append({"type": "weak_vpn_cipher", "detail": encryption,
                             "severity": "high"})
        if not pfs:
            findings.append({"type": "vpn_no_pfs", "detail": "",
                             "severity": "medium"})
        return findings

    def check_mode(self, *, mode: str = "", policy: str = "NIST") -> list[dict[str, Any]]:
        if mode.upper() == "ECB":
            return [{"type": "unsafe_mode", "detail": "ECB (patterns leak)",
                     "severity": "high"}]
        if mode.upper() == "CBC" and policy == "FIPS":
            return [{"type": "cbc_prohibited", "detail": "CBC under FIPS policy",
                     "severity": "medium"}]
        return []
