"""§10/§11/§12 Protocol analysis — TLS, SSH, IPsec/VPN.

Deterministic catalogs turn raw protocol data into structured crypto
observations:

  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      -> TLS 1.2+ / ECDHE / ECDSA / AES-256-GCM / SHA-384 / PFS: yes

  ssh-rsa, curve25519-sha256, chacha20-poly1305@openssh.com, hmac-sha2-256
      -> SSH host-key/KEX/cipher/MAC observations

  IKEv2, AES-GCM, DH group 14, PFS
      -> IPsec/VPN observation, mapped to gateway → application policy
"""

from __future__ import annotations

import re
import struct
from typing import Any, Iterable, Optional

# --------------------------------------------------------------------------- #
# TLS cipher-suite catalog: IANA name -> structured crypto observation
# --------------------------------------------------------------------------- #

_TLS_KE = {
    "RSA": "RSA", "DHE_RSA": "DH", "DHE_DSS": "DH", "ECDHE_RSA": "ECDH",
    "ECDHE_ECDSA": "ECDH", "ECDH_RSA": "ECDH", "ECDH_ECDSA": "ECDH",
    "PSK": "PSK", "DHE_PSK": "DH", "ECDHE_PSK": "ECDH", "GOST": "GOST",
    "SRP": "SRP", "TLS13": "TLS1.3-KE",
}

_TLS_SIG = {
    "RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA", "PSK": "PSK",
    "GOST": "GOST", "TLS13": "TLS1.3-sig",
}

_TLS_CIPHER_TO_ALG = {
    "AES_128_GCM": "AES-GCM", "AES_256_GCM": "AES-GCM", "AES_128_CCM": "AES-CCM",
    "AES_256_CCM": "AES-CCM", "AES_128_CBC": "AES-CBC", "AES_256_CBC": "AES-CBC",
    "CHACHA20_POLY1305": "ChaCha20-Poly1305", "ARIA_128_GCM": "ARIA",
    "ARIA_256_GCM": "ARIA", "CAMELLIA_128_GCM": "Camellia", "CAMELLIA_256_GCM": "Camellia",
    "CAMELLIA_128_CBC": "Camellia", "CAMELLIA_256_CBC": "Camellia",
    "3DES_EDE_CBC": "3DES", "DES_CBC": "DES", "RC4_128": "RC4",
    "GOST": "GOST", "SEED_CBC": "SEED", "NULL": "NULL",
}

_TLS_HASH = {
    "MD5": "MD5", "SHA": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384",
    "GOST": "GOST", "TLS13": "TLS1.3-hash",
}

_TLS13_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
}

# IANA suite name -> (key_exchange, signature, cipher, hash, pfs)
IANA_SUITES: dict[str, tuple[str, str, str, str, bool]] = {}


def _build_iana() -> None:
    for name in [
        "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_RSA_WITH_SEED_CBC_SHA", "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_D",
    ]:
        parts = name.split("_WITH_")
        if len(parts) != 2:
            continue
        ke_part = parts[0].replace("TLS_", "")
        cipher_hash = parts[1]
        ke = _TLS_KE.get(ke_part, "RSA")
        sig = _TLS_SIG.get(ke_part, "RSA")
        pfs = ke_part.startswith(("DHE", "ECDHE"))
        cipher = "NULL"
        hash_alg = "SHA-1"
        # exact match first (AES_128_GCM), then strip the hash suffix
        if cipher_hash in _TLS_CIPHER_TO_ALG:
            cipher = _TLS_CIPHER_TO_ALG[cipher_hash]
        else:
            for hash_name in ("SHA384", "SHA256", "SHA", "MD5"):
                if cipher_hash.endswith("_" + hash_name):
                    core = cipher_hash[: -(len(hash_name) + 1)]
                    if core in _TLS_CIPHER_TO_ALG:
                        cipher = _TLS_CIPHER_TO_ALG[core]
                    break
            else:
                for token in re.findall(r"[A-Z0-9]+", cipher_hash):
                    if token in _TLS_CIPHER_TO_ALG:
                        cipher = _TLS_CIPHER_TO_ALG[token]
                        break
        for token in re.findall(r"[A-Z0-9]+", cipher_hash):
            if token in _TLS_HASH:
                hash_alg = _TLS_HASH[token]
        IANA_SUITES[name] = (ke, sig, cipher, hash_alg, pfs)


_build_iana()

#: TLS version → name
# wire values: 0x0301 = TLS 1.0 ... 0x0304 = TLS 1.3 (RFC 8446 legacy_version)
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2", 0x0304: "TLS 1.3", 0x0305: "TLS 1.4-draft"}


class TlsAnalysis:
    """§10 deep TLS analysis (from suites, versions, groups, certs)."""

    def analyze_suite(self, suite: str) -> dict[str, Any]:
        if suite in _TLS13_SUITES.values():
            version = "TLS 1.3"
            ke, sig, cipher, hash_alg, pfs = "TLS1.3-KE", "TLS1.3-sig", "", "SHA-256", True
            for token in ("AES_256_GCM", "AES_128_GCM", "AES_128_CCM",
                          "CHACHA20_POLY1305"):
                if token in suite:
                    cipher = _TLS_CIPHER_TO_ALG[token]
            for token in ("SHA256", "SHA384"):
                if token in suite:
                    hash_alg = token.replace("SHA", "SHA-")
        else:
            version = "TLS 1.2 or earlier"
            if suite not in IANA_SUITES:
                return {"suite": suite, "known": False}
            ke, sig, cipher, hash_alg, pfs = IANA_SUITES[suite]
        return {
            "suite": suite,
            "known": True,
            "protocol_version": version,
            "key_exchange": ke,
            "signature_algorithm": sig,
            "cipher": cipher,
            "hash": hash_alg,
            "pfs": pfs,
            "observation": {
                "algorithm": cipher if cipher != "NULL" else ke,
                "operation": "encrypt" if cipher != "NULL" else "key_exchange",
                "protocol": "TLS",
            },
        }

    def parse_server_hello(self, data: bytes) -> dict[str, Any]:
        """Minimal TLS record-layer ServerHello parse (deterministic)."""
        if len(data) < 5:
            return {"error": "too short"}
        content_type = data[0]
        if content_type not in (0x16, 0x15):
            return {"error": "not a handshake record"}
        try:
            version_bytes = struct.unpack_from(">H", data, 1)[0]
            handshake_type = data[5] if len(data) > 5 else None
            offset = 6
            legacy_version = struct.unpack_from(">H", data, offset)[0] if len(data) >= offset + 2 else 0
            offset += 2
            if len(data) < offset + 32:
                return {"legacy_version": TLS_VERSIONS.get(legacy_version, f"0x{legacy_version:04x}"),
                        "error": "server hello too short for full parse"}
            offset += 32  # random
            sid_len = data[offset]
            offset += 1 + sid_len
            suite_bytes = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            suite = _TLS13_SUITES.get(suite_bytes, f"TLS 0x{suite_bytes:04x}")
            comp = data[offset]
            offset += 1 + comp
            # extensions
            if len(data) >= offset + 2:
                (ext_total,) = struct.unpack_from(">H", data, offset)
                offset += 2
                groups = []
                supported_versions = []
                end = min(offset + ext_total, len(data))
                while offset + 4 <= end:
                    ext_type, ext_len = struct.unpack_from(">HH", data, offset)
                    offset += 4
                    payload = data[offset:offset + ext_len]
                    offset += ext_len
                    if ext_type == 0x002b and len(payload) >= 2:  # supported_versions
                        supported_versions = [TLS_VERSIONS.get(
                            struct.unpack_from(">H", payload, i)[0],
                            f"0x{struct.unpack_from('>H', payload, i)[0]:04x}")
                            for i in range(0, len(payload) - 1, 2)]
                    if ext_type == 0x000a and len(payload) >= 2:  # supported_groups
                        groups = [f"0x{struct.unpack_from('>H', payload, i)[0]:x}"
                                  for i in range(0, len(payload) - 1, 2)]
            return {
                "record": TLS_VERSIONS.get(version_bytes, f"0x{version_bytes:04x}"),
                "handshake_type": handshake_type,
                "legacy_version": TLS_VERSIONS.get(legacy_version, f"0x{legacy_version:04x}"),
                "cipher_suite": suite,
                "compression": comp,
                "supported_groups": groups,
                "supported_versions": supported_versions,
                "analysis": self.analyze_suite(suite) if suite in IANA_SUITES
                            or suite in _TLS13_SUITES.values() else None,
            }
        except Exception as exc:  # pragma: no cover
            return {"error": str(exc)}


# --------------------------------------------------------------------------- #
# SSH catalogs (§11)
# --------------------------------------------------------------------------- #

_SSH_HOST_KEY = {
    "ssh-rsa": "RSA", "rsa-sha2-256": "RSA", "rsa-sha2-512": "RSA",
    "ecdsa-sha2-nistp256": "ECDSA", "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA", "ssh-ed25519": "Ed25519",
    "ssh-dss": "DSA", "sk-ssh-ed25519@openssh.com": "Ed25519",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA",
}

_SSH_KEX = {
    "curve25519-sha256": "X25519", "curve25519-sha256@libssh.org": "X25519",
    "ecdh-sha2-nistp256": "ECDH", "ecdh-sha2-nistp384": "ECDH",
    "ecdh-sha2-nistp521": "ECDH", "diffie-hellman-group14-sha256": "DH",
    "diffie-hellman-group16-sha512": "DH", "diffie-hellman-group18-sha512": "DH",
    "diffie-hellman-group-exchange-sha256": "DH", "diffie-hellman-group1-sha1": "DH",
    "diffie-hellman-group14-sha1": "DH", "sntrup761x25519-sha512": "X25519",
    "mlkem768x25519-sha256": "ML-KEM-768",
}

_SSH_CIPHERS = {
    "aes128-ctr": "AES-CTR", "aes192-ctr": "AES-CTR", "aes256-ctr": "AES-CTR",
    "aes128-cbc": "AES-CBC", "aes256-cbc": "AES-CBC", "aes128-gcm@openssh.com": "AES-GCM",
    "aes256-gcm@openssh.com": "AES-GCM", "chacha20-poly1305@openssh.com": "ChaCha20-Poly1305",
    "3des-cbc": "3DES", "arcfour": "RC4", "arcfour128": "RC4", "arcfour256": "RC4",
}

_SSH_MACS = {
    "hmac-sha2-256": "HMAC-SHA256", "hmac-sha2-512": "HMAC-SHA512",
    "hmac-sha1": "HMAC-SHA1", "hmac-md5": "HMAC-MD5",
    "hmac-sha2-256-etm@openssh.com": "HMAC-SHA256", "hmac-sha1-etm@openssh.com": "HMAC-SHA1",
}

_SSH_SIG = {
    "ssh-rsa": "RSA", "rsa-sha2-256": "RSA", "rsa-sha2-512": "RSA",
    "ssh-ed25519": "Ed25519", "ecdsa-sha2-nistp256": "ECDSA", "ssh-dss": "DSA",
}


class SshAnalysis:
    """§11 SSH crypto analysis."""

    def analyze(self, *, host_key: str = "", kex: str = "",
                ciphers: Optional[Iterable[str]] = None,
                macs: Optional[Iterable[str]] = None,
                signature_algorithms: Optional[Iterable[str]] = None,
                protocol_version: str = "SSH-2.0") -> dict[str, Any]:
        observations = []
        if host_key:
            observations.append({"algorithm": _SSH_HOST_KEY.get(host_key, "UNKNOWN"),
                                 "role": "host_key", "value": host_key})
        if kex:
            observations.append({"algorithm": _SSH_KEX.get(kex, "UNKNOWN"),
                                 "role": "kex", "value": kex})
        for c in ciphers or []:
            observations.append({"algorithm": _SSH_CIPHERS.get(c, "UNKNOWN"),
                                 "role": "cipher", "value": c})
        for m in macs or []:
            observations.append({"algorithm": _SSH_MACS.get(m, "UNKNOWN"),
                                 "role": "mac", "value": m})
        for s in signature_algorithms or []:
            observations.append({"algorithm": _SSH_SIG.get(s, "UNKNOWN"),
                                 "role": "signature_algorithm", "value": s})
        return {"protocol": "SSH", "protocol_version": protocol_version,
                "observations": observations}


# --------------------------------------------------------------------------- #
# IPsec / VPN catalogs (§12)
# --------------------------------------------------------------------------- #

_IPSEC_ENCRYPTION = {
    "AES_GCM_16": "AES-GCM", "AES_CBC": "AES-CBC", "AES_CTR": "AES-CTR",
    "CHACHA20_POLY1305": "ChaCha20-Poly1305", "3DES": "3DES", "DES": "DES",
    "NULL": "NULL",
}

_IPSEC_INTEGRITY = {
    "HMAC_SHA2_256_128": "HMAC-SHA256", "HMAC_SHA2_512_256": "HMAC-SHA512",
    "HMAC_SHA1_96": "HMAC-SHA1", "AES_XCBC_96": "AES-XCBC", "AES_GMAC": "AES-GMAC",
}

_IPSEC_DH = {
    "1": "DH-768", "2": "DH-1024", "5": "DH-1536", "14": "DH-2048",
    "15": "DH-3072", "16": "DH-4096", "17": "DH-6144", "18": "DH-8192",
    "19": "ECDH-P-256", "20": "ECDH-P-384", "21": "ECDH-P-521",
    "24": "ECDH-P-256", "25": "ECDH-P-384", "26": "ECDH-P-521",
    "27": "X25519", "28": "X448", "31": "Curve25519",
}

_IPSEC_AUTH = {
    "PSK": "PSK", "RSA_SIG": "RSA", "ECDSA_SIG": "ECDSA",
    "DSA_SIG": "DSA", "X509": "X509",
}


class IpsecAnalysis:
    """§12 IPsec/VPN crypto policy analysis → gateway → applications."""

    def analyze(self, *, ike_version: str = "IKEv2", encryption: str = "",
                integrity: str = "", dh_group: str = "", authentication: str = "",
                pfs: bool = False) -> dict[str, Any]:
        return {
            "protocol": "IPsec",
            "ike_version": ike_version,
            "encryption": {"algorithm": _IPSEC_ENCRYPTION.get(encryption, "UNKNOWN"),
                           "value": encryption},
            "integrity": {"algorithm": _IPSEC_INTEGRITY.get(integrity, "UNKNOWN"),
                          "value": integrity},
            "dh_group": {"algorithm": _IPSEC_DH.get(str(dh_group), f"DH group {dh_group}"),
                         "value": dh_group},
            "authentication": {"algorithm": _IPSEC_AUTH.get(authentication, "UNKNOWN"),
                               "value": authentication},
            "pfs": pfs,
            "quantum_status": "QUANTUM_VULNERABLE" if str(dh_group) in
                              ("1", "2", "5", "14", "15", "16", "17", "18", "19", "20", "21")
                              else "QUANTUM_SAFE",
        }

    def map_policy(self, *, vpn: str, gateway: str,
                   applications: Iterable[str]) -> dict[str, Any]:
        """VPN → crypto policy → gateway → applications."""
        return {
            "vpn": vpn,
            "gateway": gateway,
            "applications": list(applications),
            "policy": self,
        }
