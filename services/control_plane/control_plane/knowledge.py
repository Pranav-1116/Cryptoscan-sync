"""Crypto & vendor knowledge base — deterministic catalogs.

Maintained independently of the scanner core (updatable like a signature
pack). Each algorithm/version carries a security status, usage context, key
size, PQC status and migration candidate. No AI — the table is the truth.
"""

from __future__ import annotations

#: algorithm catalog keyed by canonical name. status:
#:   broken / weak / deprecated / acceptable / recommended / pqc
CRYPTO_KB: dict[str, dict] = {
    "rsa-1024": {"category": "asymmetric", "status": "broken", "min_key_size": 1024,
                 "pqc": False, "migration": "ml-dsa-65 (hybrid with RSA-3072)", "contexts": ["tls", "signing"]},
    "rsa-2048": {"category": "asymmetric", "status": "acceptable", "min_key_size": 2048,
                 "pqc": False, "migration": "ml-dsa-65 hybrid", "contexts": ["tls", "signing", "hsm"]},
    "rsa-3072": {"category": "asymmetric", "status": "recommended", "min_key_size": 3072,
                 "pqc": False, "migration": "ml-dsa-87 hybrid", "contexts": ["tls", "signing", "hsm"]},
    "ecdsa-p256": {"category": "asymmetric", "status": "acceptable", "min_key_size": 256,
                   "pqc": False, "migration": "ml-dsa-65 hybrid", "contexts": ["tls", "signing"]},
    "ecdh-p256": {"category": "key_exchange", "status": "acceptable", "min_key_size": 256,
                  "pqc": False, "migration": "ml-kem-768 hybrid", "contexts": ["tls", "vpn"]},
    "sha-1": {"category": "hash", "status": "broken", "min_key_size": 0,
              "pqc": False, "migration": "sha-256+", "contexts": ["signature", "certificate"]},
    "md5": {"category": "hash", "status": "broken", "min_key_size": 0,
            "pqc": False, "migration": "sha-256+", "contexts": ["signature", "integrity"]},
    "3des": {"category": "symmetric", "status": "deprecated", "min_key_size": 112,
             "pqc": False, "migration": "aes-256-gcm", "contexts": ["tls", "payment"]},
    "rc4": {"category": "symmetric", "status": "broken", "min_key_size": 0,
            "pqc": False, "migration": "aes-256-gcm", "contexts": ["tls"]},
    "aes-128": {"category": "symmetric", "status": "acceptable", "min_key_size": 128,
                "pqc": True, "migration": "aes-256-gcm (quantum-resistant symmetric)", "contexts": ["tls", "data", "hsm"]},
    "aes-256": {"category": "symmetric", "status": "recommended", "min_key_size": 256,
                "pqc": True, "migration": "aes-256-gcm", "contexts": ["tls", "data", "hsm"]},
    "aes-256-gcm": {"category": "symmetric", "status": "recommended", "min_key_size": 256,
                    "pqc": True, "migration": "aes-256-gcm", "contexts": ["tls", "data"]},
    "tls-1.0": {"category": "protocol", "status": "deprecated", "min_key_size": 0,
                "pqc": False, "migration": "tls-1.3", "contexts": ["tls"]},
    "tls-1.1": {"category": "protocol", "status": "deprecated", "min_key_size": 0,
                "pqc": False, "migration": "tls-1.3", "contexts": ["tls"]},
    "tls-1.2": {"category": "protocol", "status": "acceptable", "min_key_size": 0,
                "pqc": False, "migration": "tls-1.3 + pqc-hybrid", "contexts": ["tls"]},
    "tls-1.3": {"category": "protocol", "status": "recommended", "min_key_size": 0,
                "pqc": False, "migration": "tls-1.3 + ml-kem hybrid key share", "contexts": ["tls"]},
    "ssh-rsa": {"category": "protocol", "status": "weak", "min_key_size": 0,
                "pqc": False, "migration": "ssh-ed25519 -> ml-dsa hybrid", "contexts": ["ssh"]},
    # --- PQC / hybrid ---
    "ml-kem-768": {"category": "key_encapsulation", "status": "pqc", "min_key_size": 0,
                   "pqc": True, "migration": "n/a (FIPS 203)", "contexts": ["key_exchange", "tls"]},
    "ml-dsa-65": {"category": "asymmetric", "status": "pqc", "min_key_size": 0,
                  "pqc": True, "migration": "n/a (FIPS 204)", "contexts": ["signing"]},
    "hybrid-mlkem-ecdhe": {"category": "key_exchange", "status": "recommended", "min_key_size": 0,
                           "pqc": True, "migration": "n/a", "contexts": ["tls", "vpn"]},
}

STATUS_RANK = {"broken": 0, "weak": 1, "deprecated": 2, "acceptable": 3,
               "recommended": 4, "pqc": 5}


def lookup(algorithm: str, key_size: int | None = None) -> dict | None:
    """Look up an algorithm by name (normalized) with optional key-size
    resolution for RSA (rsa-2048 vs rsa-1024)."""
    key = _normalize(algorithm)
    if key in CRYPTO_KB:
        entry = dict(CRYPTO_KB[key])
        entry["algorithm"] = key
        return entry
    # RSA key-size family resolution
    if key in {"rsa", "rsa-sha256", "rsaes"} and key_size:
        fam = f"rsa-{key_size}"
        if fam in CRYPTO_KB:
            entry = dict(CRYPTO_KB[fam]); entry["algorithm"] = fam
            return entry
        entry = dict(CRYPTO_KB["rsa-1024"] if key_size < 2048 else CRYPTO_KB["rsa-2048"])
        entry["algorithm"] = key
        return entry
    return None


def _normalize(algorithm: str) -> str:
    a = str(algorithm).strip().lower().replace("_", "-").replace(" ", "")
    # insert a separator between protocol name and version: tls1.3 -> tls-1.3
    for name in ("tls", "ssh", "ipsec", "ikev"):
        if a.startswith(name) and len(a) > len(name) and a[len(name)].isdigit():
            a = f"{name}-{a[len(name):]}"
    return a


def is_deprecated_or_worse(algorithm: str, key_size: int | None = None) -> bool:
    entry = lookup(algorithm, key_size)
    if entry is None:
        return False  # unknown is handled by the confidence layer, not here
    return STATUS_RANK.get(entry["status"], 3) <= STATUS_RANK["deprecated"]


def migration_target(algorithm: str, key_size: int | None = None) -> str | None:
    entry = lookup(algorithm, key_size)
    return entry.get("migration") if entry else None


# vendor knowledge (lightweight): product -> crypto capability flags
VENDOR_KB: dict[str, dict] = {
    "cisco-asa": {"vendor": "cisco", "product": "ASA", "firmware_min_pqc": "9.20",
                  "ssh_pqc": False, "ipsec_pqc": False, "notes": "legacy IKE; passive inventory only"},
    "f5-bigip": {"vendor": "f5", "product": "BIG-IP", "firmware_min_pqc": "17.1",
                 "ssh_pqc": False, "ipsec_pqc": False, "notes": "TLS offload; track HSM integration"},
    "thalas-luna-hsm": {"vendor": "thalas", "product": "Luna HSM", "firmware_min_pqc": "7.13",
                        "ssh_pqc": False, "ipsec_pqc": False, "notes": "PQC via firmware roadmap"},
}


def lookup_vendor(model: str) -> dict | None:
    return VENDOR_KB.get(str(model).strip().lower())
