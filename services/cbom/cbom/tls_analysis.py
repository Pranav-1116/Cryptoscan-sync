"""TLS observation analysis for CBOM exports.

A protocol version is not a verdict. "TLS 1.2" with ECDHE + AES-GCM and a
2048-bit RSA certificate is an approved configuration (NIST SP 800-52 Rev. 2);
"TLS 1.2" with RSA key transport + 3DES-CBC is not. This module evaluates what
was actually observed — version, cipher suite, key exchange (and its group when
recorded), certificate public key, certificate signature algorithm, validity
and chain — and says which of those facts were missing, instead of blanket
labelling a version DEPRECATED.

Pure functions; no database, no network. Inputs are what a collector recorded.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

TLS_MODEL_VERSION = "cryptoscan-tls-assessment/1.0.0"

_LEVEL = {"NONE": 0, "LOW": 1, "REVIEW": 1.5, "MEDIUM": 2, "HIGH": 3}

#: TLS 1.3 suites (RFC 8446 §B.4). Key exchange is negotiated separately.
_TLS13_SUITES = {
    "TLS_AES_128_GCM_SHA256": ("AES", 128, "GCM", "SHA256"),
    "TLS_AES_256_GCM_SHA384": ("AES", 256, "GCM", "SHA384"),
    "TLS_CHACHA20_POLY1305_SHA256": ("CHACHA20", 256, "POLY1305", "SHA256"),
    "TLS_AES_128_CCM_SHA256": ("AES", 128, "CCM", "SHA256"),
    "TLS_AES_128_CCM_8_SHA256": ("AES", 128, "CCM_8", "SHA256"),
}
#: Hybrid / pure post-quantum TLS key-exchange groups (IANA TLS Supported Groups).
PQC_GROUPS = {"X25519MLKEM768", "SECP256R1MLKEM768", "SECP384R1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024",
              "X25519KYBER768DRAFT00"}
_CURVE_GROUPS = {"X25519": "X25519", "X448": "X448", "SECP256R1": "P-256", "PRIME256V1": "P-256", "P-256": "P-256",
                 "SECP384R1": "P-384", "P-384": "P-384", "SECP521R1": "P-521", "P-521": "P-521"}
_KX = {"ECDHE", "DHE", "ECDH", "DH", "RSA", "PSK", "ECDHE_PSK", "DHE_PSK", "RSA_PSK", "SRP"}


def _norm_version(version: Any) -> str | None:
    text = str(version or "").upper().replace(" ", "").replace("V", "")
    match = re.search(r"(SSL|TLS)(\d(?:\.\d)?)", text)
    if not match:
        return None
    proto, number = match.groups()
    number = number if "." in number else f"{number}.0"
    return f"{proto} {number}"


def parse_suite(name: Any) -> dict[str, Any]:
    """Decompose an IANA (``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256``) or OpenSSL
    (``ECDHE-RSA-AES128-GCM-SHA256``) cipher-suite name. Unknown → ``recognized``
    False; nothing is guessed."""
    raw = str(name or "").strip()
    out: dict[str, Any] = {"suite": raw or None, "recognized": False, "tls13": False, "key_exchange": None,
                           "authentication": None, "cipher": None, "cipher_bits": None, "mode": None, "mac": None,
                           "aead": None, "forward_secrecy": None}
    if not raw:
        return out
    upper = raw.upper()
    if upper in _TLS13_SUITES:
        cipher, bits, mode, mac = _TLS13_SUITES[upper]
        out.update(recognized=True, tls13=True, key_exchange="(EC)DHE_OR_PSK_NEGOTIATED_SEPARATELY", cipher=cipher,
                   cipher_bits=bits, mode=mode, mac=f"AEAD (PRF {mac})", aead=True, forward_secrecy=True)
        return out
    if upper.startswith("TLS_") and "_WITH_" in upper:
        head, tail = upper[4:].split("_WITH_", 1)
        parts = head.split("_")
        kx, auth = parts[0], (parts[1] if len(parts) > 1 else None)
        if kx in {"ECDHE", "DHE", "ECDH", "DH"} and auth in {"RSA", "ECDSA", "DSS", "ANON", "PSK"}:
            pass
        elif kx == "RSA" and auth in {None, "PSK", "EXPORT"}:
            auth = "RSA"
        tokens = tail.split("_")
    else:
        tokens = [t for t in upper.replace("_", "-").split("-") if t]
        kx = tokens[0] if tokens and tokens[0] in _KX else "RSA"  # OpenSSL omits kRSA: "AES128-SHA"
        if tokens and tokens[0] in _KX:
            tokens = tokens[1:]
        auth = tokens[0] if tokens and tokens[0] in {"RSA", "ECDSA", "DSS", "PSK", "ANON"} else ("RSA" if kx == "RSA" else None)
        if tokens and tokens[0] in {"RSA", "ECDSA", "DSS", "PSK", "ANON"}:
            tokens = tokens[1:]
        joined = "_".join(tokens)
        joined = re.sub(r"^(AES|CAMELLIA|ARIA)(\d+)", r"\1_\2", joined)
        tokens = joined.split("_")
    joined = "_".join(tokens)
    cipher = bits = mode = mac = None
    m = re.match(r"(AES|CAMELLIA|ARIA)_(\d+)_?(GCM|CCM_8|CCM|CBC)?_?(.*)$", joined)
    if m:
        cipher, bits, mode, mac = m.group(1), int(m.group(2)), m.group(3) or "CBC", m.group(4) or None
    elif joined.startswith(("CHACHA20_POLY1305", "CHACHA20")):
        cipher, bits, mode, mac = "CHACHA20", 256, "POLY1305", joined.split("_")[-1]
    elif joined.startswith(("3DES", "DES_CBC3", "DES-CBC3")) or "3DES" in joined:
        cipher, bits, mode, mac = "3DES", 112, "CBC", joined.split("_")[-1]
    elif joined.startswith("DES"):
        cipher, bits, mode, mac = "DES", 56, "CBC", joined.split("_")[-1]
    elif joined.startswith("RC4"):
        cipher, bits, mode, mac = "RC4", 128, "STREAM", joined.split("_")[-1]
    elif joined.startswith("NULL"):
        cipher, bits, mode, mac = "NULL", 0, None, joined.split("_")[-1]
    if cipher is None:
        return out
    if mac in {"", None}:
        mac = None
    aead = mode in {"GCM", "CCM", "CCM_8", "POLY1305"}
    if aead:
        mac = f"AEAD (PRF {mac})" if mac and mac != "POLY1305" else "AEAD"
    out.update(recognized=True, key_exchange=kx, authentication=auth, cipher=cipher, cipher_bits=bits, mode=mode,
               mac=mac, aead=aead, forward_secrecy=kx in {"ECDHE", "DHE", "ECDHE_PSK", "DHE_PSK"})
    if "EXPORT" in upper:
        out["export_grade"] = True
    return out


def normalize_group(group: Any) -> dict[str, Any]:
    """Key-exchange group as recorded. Absent → explicitly not recorded."""
    raw = str(group or "").strip()
    if not raw:
        return {"group": None, "recorded": False, "pqc_hybrid": False, "curve": None}
    pqc = raw.upper().replace("-", "").replace("_", "") in PQC_GROUPS
    return {"group": raw, "recorded": True, "pqc_hybrid": pqc, "curve": _CURVE_GROUPS.get(raw.upper())}


def _signature_parts(sig: Any) -> tuple[str | None, str | None]:
    text = str(sig or "").lower().replace("-", "").replace("_", "")
    if not text:
        return None, None
    digest = next((d for d in ("sha512", "sha384", "sha256", "sha224", "sha1", "md5") if d in text), None)
    if "ecdsa" in text:
        key = "ECDSA"
    elif "ed25519" in text:
        key, digest = "Ed25519", digest or "intrinsic"
    elif "rsassapss" in text or "pss" in text:
        key = "RSASSA-PSS"
    elif "rsa" in text:
        key = "RSA"
    elif "dsa" in text:
        key = "DSA"
    elif "mldsa" in text or "dilithium" in text:
        key = "ML-DSA"
    else:
        key = None
    return key, (digest.upper().replace("SHA", "SHA-") if digest and digest.startswith("sha") else digest.upper() if digest else None)


def _as_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def assess(*, version: Any = None, cipher_suite: Any = None, key_exchange: Any = None, group: Any = None,
           cert_public_key_algorithm: Any = None, cert_public_key_bits: Any = None, cert_curve: Any = None,
           cert_signature_algorithm: Any = None, not_before: Any = None, not_after: Any = None,
           self_signed: Any = None, chain_status: Any = None, trust_status: Any = None,
           now: datetime | None = None) -> dict[str, Any]:
    """Evaluate one TLS observation.

    Returns per-aspect findings (version, suite, key exchange, certificate) plus
    configuration and quantum levels with reasons, and the list of facts that
    were not recorded. The configuration level never comes from the version
    alone when a suite is known.
    """
    now = now or datetime.now(timezone.utc)
    ver = _norm_version(version)
    suite = parse_suite(cipher_suite)
    grp = normalize_group(group)
    reasons: list[str] = []
    level = "NONE"
    missing: list[str] = []

    def raise_to(new: str, why: str) -> None:
        nonlocal level
        reasons.append(why)
        if _LEVEL[new] > _LEVEL[level]:
            level = new

    # ── protocol version ────────────────────────────────────────────────────
    if ver is None:
        version_status = "NOT_RECORDED"
        missing.append("protocol_version")
    elif ver.startswith("SSL") or ver in {"TLS 1.0", "TLS 1.1"}:
        version_status = "PROHIBITED"
        raise_to("HIGH", f"{ver} is prohibited (RFC 8996; NIST SP 800-52 Rev. 2)")
    elif ver == "TLS 1.2":
        version_status = "PERMITTED_WITH_APPROVED_SUITES"
    elif ver == "TLS 1.3":
        version_status = "PREFERRED"
    else:
        version_status = "UNRECOGNIZED"
        raise_to("REVIEW", f"protocol version {version!r} not recognized")
    if suite["tls13"] and ver not in {None, "TLS 1.3"}:
        raise_to("REVIEW", f"TLS 1.3 suite recorded with protocol version {ver}; observation is inconsistent")

    # ── cipher suite ────────────────────────────────────────────────────────
    kx = suite.get("key_exchange") or (str(key_exchange).upper() if key_exchange else None)
    if not suite["suite"]:
        missing.append("cipher_suite")
        if ver == "TLS 1.2":
            raise_to("REVIEW", "TLS 1.2 posture depends on the negotiated cipher suite, which was not recorded; "
                               "the version alone is neither approved nor deprecated")
    elif not suite["recognized"]:
        raise_to("REVIEW", f"cipher suite {suite['suite']} not recognized by the TLS analyser")
    else:
        cipher = suite["cipher"]
        if cipher in {"NULL", "RC4", "DES"} or suite.get("export_grade") or suite.get("authentication") == "ANON":
            raise_to("HIGH", f"{suite['suite']}: {cipher or 'anonymous/export'} suites are prohibited "
                             "(RFC 7465 / SP 800-52 Rev. 2)")
        elif cipher == "3DES":
            raise_to("HIGH", f"{suite['suite']}: 3DES (TDEA) encryption is disallowed after 2023 (SP 800-131A Rev. 2)")
        elif not suite["tls13"]:
            if kx in {"RSA", "RSA_PSK"}:
                raise_to("MEDIUM", f"{suite['suite']}: RSA key transport has no forward secrecy — compromise of the "
                                   "certificate key decrypts every recorded session; prefer ECDHE")
            elif kx in {"ECDH", "DH"}:
                raise_to("MEDIUM", f"{suite['suite']}: static (EC)DH has no forward secrecy")
            if suite["aead"]:
                if kx in {"ECDHE", "DHE"}:
                    reasons.append(f"{suite['suite']}: {kx} + {cipher}-{suite['cipher_bits']}-{suite['mode']} "
                                   "(AEAD, forward secret) is an approved TLS 1.2 suite (SP 800-52 Rev. 2 §3.3.1)")
            else:
                raise_to("LOW", f"{suite['suite']}: CBC with HMAC is permitted by SP 800-52 Rev. 2, but AEAD suites "
                                "are preferred (CBC padding-oracle history)")
            if kx == "DHE":
                raise_to("REVIEW", "DHE group size not recorded; finite-field groups below 2048 bits are disallowed")
        else:
            if suite["mode"] == "CCM_8":
                raise_to("LOW", "TLS_AES_128_CCM_8_SHA256 uses a truncated 8-byte tag; not in the SP 800-52 Rev. 2 "
                                "recommended TLS 1.3 set")
            else:
                reasons.append(f"{suite['suite']}: TLS 1.3 AEAD suite (RFC 8446)")

    # ── key exchange group (where post-quantum protection actually lives) ──
    if not grp["recorded"]:
        missing.append("key_exchange_group")
    if grp["pqc_hybrid"]:
        kx_quantum, kx_reason = "NONE", f"key exchange group {grp['group']} is a hybrid/post-quantum ML-KEM group"
    elif kx in {"RSA", "RSA_PSK"}:
        kx_quantum, kx_reason = "HIGH", ("RSA key transport is Shor-vulnerable and not forward secret: recorded traffic "
                                         "is exposed to harvest-now-decrypt-later")
    elif kx in {"ECDHE", "DHE", "ECDH", "DH"} or suite["tls13"]:
        if grp["recorded"]:
            kx_quantum = "HIGH"
            kx_reason = (f"key exchange group {grp['group']} is Shor-vulnerable; session secrets of recorded traffic "
                         "are exposed to harvest-now-decrypt-later")
        else:
            kx_quantum = "HIGH"
            kx_reason = ("(EC)DHE group not recorded by the collector: treated as Shor-vulnerable (harvest-now-decrypt-"
                         "later) unless a hybrid ML-KEM group is shown to be negotiated")
    else:
        kx_quantum, kx_reason = "REVIEW", "key exchange not recorded; quantum exposure of the session not established"

    # ── certificate ─────────────────────────────────────────────────────────
    cert: dict[str, Any] = {}
    pk = str(cert_public_key_algorithm or "").upper() or None
    try:
        bits = int(cert_public_key_bits) if cert_public_key_bits not in (None, "") else None
    except (TypeError, ValueError):
        bits = None
    sig_key, sig_digest = _signature_parts(cert_signature_algorithm)
    if pk is None:
        missing.append("certificate_public_key_algorithm")
    else:
        cert["public_key_algorithm"] = pk
        cert["public_key_bits"] = bits
        if pk in {"RSA", "DSA"} and bits is not None and bits < 2048:
            raise_to("HIGH", f"certificate {pk}-{bits} key is below the 2048-bit minimum (SP 800-131A Rev. 2)")
        elif pk in {"EC", "ECDSA"}:
            cert["curve"] = cert_curve or None
            cert["curve_basis"] = "RECORDED_IN_CERTIFICATE" if cert_curve else "NAMED_CURVE_NOT_RECORDED"
            if bits is not None and bits < 224:
                raise_to("HIGH", f"certificate EC key on a {bits}-bit curve is below the 224-bit minimum")
    if sig_key is None:
        missing.append("certificate_signature_algorithm")
    else:
        cert["signature_algorithm"] = str(cert_signature_algorithm)
        cert["signature_key_type"] = sig_key
        cert["signature_digest"] = sig_digest
        if sig_digest in {"SHA-1", "MD5"}:
            raise_to("HIGH", f"certificate is signed with {cert_signature_algorithm} — collision-broken digest, "
                             "disallowed for signatures (SP 800-131A Rev. 2)")
    start, end = _as_dt(not_before), _as_dt(not_after)
    if end is None:
        missing.append("certificate_validity")
        validity = "NOT_RECORDED"
    elif end < now:
        validity = "EXPIRED"
        raise_to("HIGH", f"certificate expired {end.date().isoformat()}")
    elif start is not None and start > now:
        validity = "NOT_YET_VALID"
        raise_to("HIGH", f"certificate not valid before {start.date().isoformat()}")
    elif (end - now).days < 30:
        validity = "EXPIRING_WITHIN_30_DAYS"
        raise_to("MEDIUM", f"certificate expires {end.date().isoformat()} ({(end - now).days} days)")
    else:
        validity = "VALID"
    cert["validity"] = validity
    if self_signed is True:
        raise_to("MEDIUM", "self-signed certificate: no third-party trust anchor")
    chain = str(chain_status or "").upper() or None
    trust = str(trust_status or "").upper() or None
    cert["chain_status"] = chain or "NOT_RECORDED"
    cert["trust_status"] = trust or "NOT_RECORDED"
    if chain is None:
        missing.append("certificate_chain_status")
    elif chain in {"INCOMPLETE", "BROKEN", "INVALID"}:
        raise_to("MEDIUM", f"certificate chain {chain.lower()}")
    if sig_key in {"RSA", "RSASSA-PSS", "ECDSA", "DSA", "Ed25519"} or pk in {"RSA", "EC", "ECDSA", "DSA", "ED25519"}:
        auth_quantum, auth_reason = "MEDIUM", ("certificate authentication (public key and issuer signature) is "
                                               "Shor-vulnerable: forgeable once a CRQC exists, no retroactive exposure")
    elif sig_key == "ML-DSA":
        auth_quantum, auth_reason = "NONE", "certificate signed with ML-DSA (FIPS 204)"
    else:
        auth_quantum, auth_reason = "REVIEW", "certificate algorithms not recorded"

    quantum = max((kx_quantum, auth_quantum), key=lambda x: _LEVEL[x])
    if level == "NONE" and not reasons:
        reasons.append("no configuration weakness in the recorded facts")
    return {
        "model": TLS_MODEL_VERSION,
        "protocol_version": ver,
        "version_status": version_status,
        "cipher_suite": suite,
        "key_exchange": {"method": kx, "group": grp["group"], "group_recorded": grp["recorded"],
                         "pqc_hybrid": grp["pqc_hybrid"], "curve": grp["curve"]},
        "certificate": cert,
        "configuration_level": level,
        "configuration_reasons": reasons,
        "quantum_level": quantum,
        "quantum_reasons": [kx_reason, auth_reason],
        "facts_not_recorded": sorted(set(missing)),
        "assessment_basis": ("evaluated from the recorded version, suite, key exchange and certificate; a version "
                             "label alone is never treated as approved or deprecated"),
    }
