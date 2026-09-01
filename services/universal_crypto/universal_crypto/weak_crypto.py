"""§22 Deprecated / weak crypto detection — policy-driven, never universal.

The *same* algorithm can be weak under one policy and accepted under another,
so classification is a pure function of (algorithm, parameters, policy).
Built-in policies: NIST, FIPS, PCI DSS, EU, UAE, ORGANIZATION, plus arbitrary
CUSTOM policies. There is no single hard-coded "weak/strong" judgment.
"""

from __future__ import annotations

from typing import Any, Optional

#: policy → rules. Rules: min key size per family, banned algorithms,
#: banned modes, minimum TLS version, banned hashes for signatures.
POLICIES: dict[str, dict[str, Any]] = {
    "NIST": {
        "min_rsa": 2048, "min_dh": 2048, "min_ecc": 256,
        "banned_algorithms": ["MD5", "MD4", "DES", "RC4", "SHA-1", "3DES"],
        "banned_modes": ["ECB"],
        "min_tls": "TLS 1.2",
        "banned_tls_suites": ["_RC4_", "_3DES_", "_CBC_SHA\""],
    },
    "FIPS": {
        "min_rsa": 2048, "min_dh": 2048, "min_ecc": 256,
        "banned_algorithms": ["MD5", "MD4", "DES", "RC4", "SHA-1", "3DES",
                              "Blowfish", "Twofish", "RIPEMD160", "BLAKE2", "BLAKE3"],
        "banned_modes": ["ECB"],
        "min_tls": "TLS 1.2",
        "banned_tls_suites": [],
    },
    "PCI_DSS": {
        "min_rsa": 2048, "min_dh": 2048, "min_ecc": 224,
        "banned_algorithms": ["MD5", "DES", "RC4", "SHA-1"],
        "banned_modes": ["ECB"],
        "min_tls": "TLS 1.2",
        "banned_tls_suites": [],
    },
    "EU": {
        "min_rsa": 3072, "min_dh": 3072, "min_ecc": 256,
        "banned_algorithms": ["MD5", "DES", "RC4", "SHA-1", "3DES"],
        "banned_modes": [],
        "min_tls": "TLS 1.2",
        "banned_tls_suites": [],
    },
    "UAE": {
        "min_rsa": 2048, "min_dh": 2048, "min_ecc": 256,
        "banned_algorithms": ["MD5", "DES", "RC4", "SHA-1"],
        "banned_modes": ["ECB"],
        "min_tls": "TLS 1.2",
        "banned_tls_suites": [],
    },
    "ORGANIZATION": {
        "min_rsa": 2048, "min_dh": 2048, "min_ecc": 256,
        "banned_algorithms": ["MD5", "SHA-1", "DES", "RC4"],
        "banned_modes": ["ECB"],
        "min_tls": "TLS 1.2",
        "banned_tls_suites": [],
    },
}

POLICY_NAMES = tuple(POLICIES)


class WeakCryptoClassifier:
    """§22 policy-driven weak/deprecated classification."""

    def policies(self) -> list[str]:
        return list(POLICY_NAMES)

    def classify(
        self,
        *,
        algorithm: str,
        policy: str = "NIST",
        key_size: Optional[int] = None,
        mode: str = "",
        tls_version: str = "",
        curve: str = "",
        custom_rules: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Classify one (algorithm, parameters) under one policy."""
        rules = custom_rules if policy == "CUSTOM" else POLICIES.get(policy)
        if rules is None:
            raise ValueError(f"unknown policy {policy!r}")
        verdict = "ALLOWED"
        reasons: list[str] = []
        alg = algorithm.upper()
        if alg in {a.upper() for a in rules["banned_algorithms"]}:
            verdict = "DEPRECATED"
            reasons.append(f"{algorithm} is deprecated under {policy}")
        if mode.upper() in {m.upper() for m in rules["banned_modes"]}:
            verdict = "DEPRECATED"
            reasons.append(f"mode {mode} is prohibited under {policy}")
        if key_size is not None and key_size > 0:
            if alg == "RSA" and key_size < rules["min_rsa"]:
                verdict = "DEPRECATED"
                reasons.append(f"RSA {key_size} < {rules['min_rsa']} (min under {policy})")
            if alg in ("DH", "DSA") and key_size < rules["min_dh"]:
                verdict = "DEPRECATED"
                reasons.append(f"{alg} {key_size} < {rules['min_dh']} (min under {policy})")
        if curve:
            approved = _approved_curves(policy, rules)
            if _canonical_curve(curve) not in approved:
                verdict = "DEPRECATED"
                reasons.append(f"curve {curve} not approved under {policy}")
        if tls_version:
            if _tls_lt(tls_version, rules["min_tls"]):
                verdict = "DEPRECATED"
                reasons.append(f"{tls_version} < {rules['min_tls']} (min under {policy})")
        return {
            "algorithm": algorithm,
            "policy": policy,
            "verdict": verdict,
            "reasons": reasons,
            "key_size": key_size,
            "mode": mode,
            "tls_version": tls_version,
            "curve": curve,
        }


#: curve-name aliases (same curve, different spelling)
_CURVE_ALIASES = {
    "secp256r1": "P-256", "prime256v1": "P-256", "secp384r1": "P-384",
    "secp521r1": "P-521",
}

#: curves approved per policy (§22 — no universal weak/strong judgment)
_APPROVED_CURVES: dict[str, set[str]] = {
    "FIPS": {"P-256", "P-384", "P-521"},
    "NIST": {"P-256", "P-384", "P-521", "X25519", "X448",
             "Curve25519", "Curve448"},
    "PCI_DSS": {"P-256", "P-384", "P-521", "X25519", "X448",
                "Curve25519", "Curve448"},
    "EU": {"P-256", "P-384", "P-521", "X25519", "X448", "Curve25519",
           "Curve448", "BrainpoolP256r1", "BrainpoolP384r1",
           "BrainpoolP512r1"},
    "UAE": {"P-256", "P-384", "P-521", "X25519", "X448", "Curve25519",
            "Curve448", "BrainpoolP256r1", "BrainpoolP384r1",
            "BrainpoolP512r1"},
    "ORG": {"P-256", "P-384", "P-521", "X25519", "X448", "Curve25519",
            "Curve448", "BrainpoolP256r1", "BrainpoolP384r1",
            "BrainpoolP512r1"},
    "BANK": {"P-256", "P-384", "P-521", "X25519", "X448", "Curve25519",
             "Curve448", "BrainpoolP256r1", "BrainpoolP384r1",
             "BrainpoolP512r1"},
}


def _canonical_curve(curve: str) -> str:
    return _CURVE_ALIASES.get(curve, curve)


def _approved_curves(policy: str, rules: dict[str, Any]) -> set[str]:
    if policy == "CUSTOM" and rules.get("approved_curves"):
        return set(rules["approved_curves"])
    return _APPROVED_CURVES.get(policy, _APPROVED_CURVES["NIST"])


def _tls_lt(a: str, b: str) -> bool:
    order = {"TLS 1.0": 10, "TLS 1.1": 11, "TLS 1.2": 12, "TLS 1.3": 13}
    return order.get(a, 0) < order.get(b, 0)
