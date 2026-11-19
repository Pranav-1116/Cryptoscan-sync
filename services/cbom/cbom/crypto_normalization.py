"""CBOM cryptographic normalization registry — one place that decides what a
recorded algorithm *is* before it becomes a CycloneDX component.

Discovery engines report strings ("AES" + mode "GCM", "ML-KEM" + 768, "TLS",
"DHE" + 1024, "MARKER"). Before this module each export path turned those into
CycloneDX fields on its own, which produced the defects an external audit
found in the estate CBOM:

* AES-GCM exported as ``ae`` but AES + GCM as ``block-cipher`` — the same
  configuration with two primitives;
* RSA used for signing exported as ``pke``;
* "TLS" exported as an *algorithm* with primitive ``unknown``;
* "ML-KEM" + 768 exported as if 768 were a key length;
* a seed placeholder row (``MARKER``) exported as a cryptographic asset.

Everything here is a pure function of the recorded fields. Facts that are
intrinsic to a fully-identified algorithm (ML-KEM-768 public keys are 1184
bytes; AES-256 has a 256-bit classical strength) are stated, with their basis.
Facts about *this* deployment that the record does not carry (named curve,
padding, execution environment, FIPS certification) are never invented — they
stay absent and the reason is recorded instead.

The algorithm vocabulary itself still comes from the shared registry
(:mod:`shared_models.algorithm_registry`); this module adds the CBOM-level
identity: family, primitive, variant name, mode, parameter set, security
levels, OID and the asset/candidate classification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from shared_models.algorithm_registry import parse_algorithm

NORMALIZER_VERSION = "cryptoscan-cbom-normalizer/2.0.0"

#: CycloneDX 1.6 enumerations (bom-1.6.schema.json, cryptoProperties).
CDX_PRIMITIVES = frozenset({
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof",
    "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"})
CDX_MODES = frozenset({"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"})
CDX_PADDINGS = frozenset({"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"})

# --------------------------------------------------------------------------- #
# classification — is this record a cryptographic asset at all?
# --------------------------------------------------------------------------- #

ASSET = "CRYPTOGRAPHIC_ASSET"                     # recognized algorithm/protocol, scanner observation
CONFIGURATION = "CONFIGURATION_FINDING"            # recognized, found in configuration (not code)
UNRECOGNIZED = "UNRECOGNIZED_CANDIDATE"            # kept, flagged: the registry cannot identify it
EXCLUDED = "EXCLUDED_NOT_CRYPTOGRAPHIC"            # never exported as a component

#: Bookkeeping strings that are not cryptography. A row whose algorithm is one
#: of these is a placeholder (idempotency markers, test fixtures), not a finding.
_PLACEHOLDERS = frozenset({
    "MARKER", "PLACEHOLDER", "DUMMY", "TODO", "TBD", "TEST", "FIXTURE", "SEED", "SENTINEL",
    "NONE", "NULL", "N/A", "NA", "EXAMPLE"})
_PLACEHOLDER_PURPOSES = frozenset({"SEED", "MARKER", "PLACEHOLDER", "TEST", "FIXTURE"})

_CONFIG_SUFFIXES = (".yml", ".yaml", ".conf", ".cnf", ".cfg", ".ini", ".hcl", ".toml", ".properties",
                    ".json", ".xml", ".env", ".config", ".tf")
_BINARY_SUFFIXES = (".jar", ".war", ".ear", ".so", ".dll", ".exe", ".dylib", ".a", ".o", ".class", ".bin")
_RUNTIME_SCHEMES = ("tls://", "dtls://", "ssh://", "ipsec://", "runtime://")


def is_placeholder(algorithm: Any, purpose: Any = None) -> bool:
    token = str(algorithm or "").strip().upper()
    return token in _PLACEHOLDERS or str(purpose or "").strip().upper() in _PLACEHOLDER_PURPOSES


# --------------------------------------------------------------------------- #
# deployment stage — how far the evidence actually reaches
# --------------------------------------------------------------------------- #

#: Ordered ladder. An asset is placed on the highest rung its *own evidence*
#: supports and is never advanced automatically.
DEPLOYMENT_STAGES = (
    "DETECTED_IN_SOURCE",       # found in source code
    "CONFIGURED",               # found in an application/infrastructure configuration
    "PRESENT_IN_BINARY",        # found in a built artifact
    "PRESENT_ON_HOST",          # present on a collected host (host collection; not proof of use)
    "RUNTIME_OBSERVED",         # observed on the wire (live handshake / probe)
)


def deployment_stage(location: Any, *, host_evidence: bool = False) -> str:
    loc = str(location or "").strip().lower()
    if loc.startswith(_RUNTIME_SCHEMES):
        return "RUNTIME_OBSERVED"
    if host_evidence:
        return "PRESENT_ON_HOST"
    if loc.endswith(_BINARY_SUFFIXES):
        return "PRESENT_IN_BINARY"
    if loc.endswith(_CONFIG_SUFFIXES):
        return "CONFIGURED"
    return "DETECTED_IN_SOURCE"


def detection_technique(stage: str) -> str:
    """CycloneDX ``evidence.identity.methods.technique`` for a stage."""
    return {
        "RUNTIME_OBSERVED": "dynamic-analysis",
        "PRESENT_ON_HOST": "other",
        "PRESENT_IN_BINARY": "binary-analysis",
        "CONFIGURED": "manifest-analysis",
    }.get(stage, "source-code-analysis")


# --------------------------------------------------------------------------- #
# reference data — intrinsic properties of fully-identified algorithms
# --------------------------------------------------------------------------- #

#: FIPS 203 / 204 / 205 parameter sets. Sizes in bytes. ``category`` is the
#: NIST PQC security category the standard assigns to the parameter set.
ML_KEM = {
    "512": {"category": 1, "public_key_bytes": 800, "ciphertext_bytes": 768, "shared_secret_bytes": 32},
    "768": {"category": 3, "public_key_bytes": 1184, "ciphertext_bytes": 1088, "shared_secret_bytes": 32},
    "1024": {"category": 5, "public_key_bytes": 1568, "ciphertext_bytes": 1568, "shared_secret_bytes": 32},
}
ML_DSA = {
    "44": {"category": 2, "public_key_bytes": 1312, "signature_bytes": 2420},
    "65": {"category": 3, "public_key_bytes": 1952, "signature_bytes": 3309},
    "87": {"category": 5, "public_key_bytes": 2592, "signature_bytes": 4627},
}
SLH_DSA_CATEGORY = {"128": 1, "192": 3, "256": 5}

#: Exact object identifiers, used only when the variant is fully determined
#: (family + key size + mode). A family name alone never gets an OID.
_OIDS = {
    "AES-128-ECB": "2.16.840.1.101.3.4.1.1", "AES-128-CBC": "2.16.840.1.101.3.4.1.2",
    "AES-128-GCM": "2.16.840.1.101.3.4.1.6", "AES-128-CCM": "2.16.840.1.101.3.4.1.7",
    "AES-192-CBC": "2.16.840.1.101.3.4.1.22", "AES-192-GCM": "2.16.840.1.101.3.4.1.26",
    "AES-256-ECB": "2.16.840.1.101.3.4.1.41", "AES-256-CBC": "2.16.840.1.101.3.4.1.42",
    "AES-256-GCM": "2.16.840.1.101.3.4.1.46", "AES-256-CCM": "2.16.840.1.101.3.4.1.47",
    "SHA-224": "2.16.840.1.101.3.4.2.4", "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2", "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-256": "2.16.840.1.101.3.4.2.8", "SHA3-384": "2.16.840.1.101.3.4.2.9",
    "SHA3-512": "2.16.840.1.101.3.4.2.10", "SHA-1": "1.3.14.3.2.26", "MD5": "1.2.840.113549.2.5",
    "HMAC-SHA-1": "1.2.840.113549.2.7", "HMAC-SHA-256": "1.2.840.113549.2.9",
    "HMAC-SHA-384": "1.2.840.113549.2.10", "HMAC-SHA-512": "1.2.840.113549.2.11",
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1", "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3", "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18", "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
    "DES-CBC": "1.3.14.3.2.7", "3DES-168-CBC": "1.2.840.113549.3.7", "RC4": "1.2.840.113549.3.4",
    "Ed25519": "1.3.101.112", "X25519": "1.3.101.110",
}
#: RSA key-type OID (rsaEncryption). Identifies the key, valid for any modulus.
_RSA_OID = "1.2.840.113549.1.1.1"

#: NIST SP 800-57 Part 1 Rev. 5, Table 2 — comparable classical strengths.
#: A modulus between two rows gets the lower row (never rounded up).
_FFC_IFC_STRENGTH = ((15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80))
_ECC_STRENGTH = ((512, 256), (384, 192), (256, 128), (224, 112), (160, 80))
_HASH_COLLISION_STRENGTH = {
    "SHA-224": 112, "SHA-256": 128, "SHA-384": 192, "SHA-512": 256, "SHA-512/256": 128,
    "SHA3-224": 112, "SHA3-256": 128, "SHA3-384": 192, "SHA3-512": 256}
#: NIST PQC categories for the symmetric/hash reference primitives.
_HASH_QUANTUM_CATEGORY = {"SHA-256": 2, "SHA3-256": 2, "SHA-384": 4, "SHA3-384": 4, "SHA-512": 4, "SHA3-512": 4}
_AES_QUANTUM_CATEGORY = {128: 1, 192: 3, 256: 5}
#: Shor's algorithm breaks these outright (category 0 against a CRQC).
_SHOR_FAMILIES = {"RSA", "RSA-PSS", "RSA-OAEP", "DSA", "DH", "DHE", "ECDH", "ECDHE", "ECDSA", "EDDSA",
                  "ED25519", "ED448", "X25519", "X448", "ECIES"}
#: Classically broken: no meaningful security level is stated for them.
_BROKEN = {"MD5", "MD4", "MD2", "SHA-1", "RC4", "DES", "RC2", "HMAC-MD5"}

_STANDARDS = {
    "AES": "FIPS 197", "SHA-224": "FIPS 180-4", "SHA-256": "FIPS 180-4", "SHA-384": "FIPS 180-4",
    "SHA-512": "FIPS 180-4", "SHA-1": "FIPS 180-4 (collision-broken)", "SHA3-256": "FIPS 202",
    "SHA3-384": "FIPS 202", "SHA3-512": "FIPS 202", "HMAC": "FIPS 198-1", "RSA": "FIPS 186-5 / SP 800-56B",
    "ECDSA": "FIPS 186-5", "ECDH": "SP 800-56A Rev. 3", "DH": "SP 800-56A Rev. 3", "DHE": "SP 800-56A Rev. 3",
    "3DES": "SP 800-67 Rev. 2 (withdrawn 2024-01-01)", "DES": "FIPS 46-3 (withdrawn 2005)",
    "ML-KEM": "FIPS 203", "ML-DSA": "FIPS 204", "SLH-DSA": "FIPS 205", "MD5": "RFC 1321 (collision-broken)",
    "RC4": "RFC 7465 prohibits RC4 in TLS", "ChaCha20-Poly1305": "RFC 8439",
    "Ed25519": "RFC 8032 / FIPS 186-5", "X25519": "RFC 7748",
}

_SIGNING_PURPOSES = ("SIGN", "SIGNATURE", "SIGNING", "CODE_SIGNING", "AUTH", "AUTHENTICATION", "ATTEST")
_TRANSPORT_PURPOSES = ("KEY_EXCHANGE", "KEY_TRANSPORT", "KEY_WRAP", "KEY_ENCAPSULATION", "ENCRYPTION",
                       "PQC_PILOT", "KEY_AGREEMENT")
_ENCRYPT_PURPOSES = ("STORAGE", "ENCRYPTION", "DATA_AT_REST", "DISK", "DISK_ENCRYPTION", "TDE",
                     "FIELD_ENCRYPTION", "PIN_CRYPTO", "LEGACY", "TRANSPORT", "SESSION")
_AEAD_MODES = {"GCM", "CCM", "CCM8", "SIV", "GCM-SIV", "OCB", "EAX"}


# --------------------------------------------------------------------------- #
# result
# --------------------------------------------------------------------------- #


@dataclass
class Normalized:
    raw: str
    classification: str
    asset_type: str = "algorithm"                 # algorithm | protocol
    family: str = "UNKNOWN"                       # AES, RSA, ML-KEM, TLS …
    name: str = "UNKNOWN"                         # variant: AES-256-GCM, ML-KEM-768, TLS 1.3
    primitive: str = "unknown"
    primitive_basis: str = "SHARED_ALGORITHM_REGISTRY"
    mode: str | None = None                       # CycloneDX enum value
    mode_reported: str | None = None
    padding: str | None = None
    padding_reported: str | None = None
    key_size_bits: int | None = None
    parameter_set: str | None = None              # CycloneDX parameterSetIdentifier
    parameter_set_basis: str | None = None
    curve: str | None = None
    curve_basis: str | None = None
    oid: str | None = None
    classical_level: int | None = None
    quantum_level: int | None = None
    security_level_basis: str | None = None
    crypto_functions: list[str] = field(default_factory=list)
    crypto_functions_basis: str | None = None
    registry_status: str = "UNKNOWN"
    registry_notes: str = ""
    standard: str | None = None
    parameter_facts: dict[str, Any] = field(default_factory=dict)
    protocol_type: str | None = None
    protocol_version: str | None = None
    exclusion_reason: str | None = None
    quantum_impact: str | None = None             # shor | grover | None
    notes: list[str] = field(default_factory=list)

    @property
    def exported(self) -> bool:
        return self.classification != EXCLUDED

    def identity_key(self) -> str:
        """Algorithm identity: the same string for every occurrence of the same
        fully-identified algorithm configuration, independent of where it was found."""
        parts = [self.name]
        if self.padding:
            parts.append(f"padding={self.padding}")
        if self.curve:
            parts.append(f"curve={self.curve}")
        return "|".join(parts).lower()


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #

_PROTOCOL = re.compile(r"^(?P<proto>D?TLS|SSL|SSH|IPSEC|IKE)(?:\s*V?(?P<version>\d+(?:\.\d+)?))?$", re.IGNORECASE)


def _int(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _purpose(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(value or "").upper()).strip("_")


def _lower_strength(size: int | None, table: tuple[tuple[int, int], ...]) -> int | None:
    if not size:
        return None
    for floor, strength in table:
        if size >= floor:
            return strength
    return None


def normalize(algorithm: Any, **kwargs: Any) -> Normalized:
    """Normalize one recorded observation. Never raises on odd input.

    Classification stage: a recognized name found in a configuration file is a
    configuration-backed finding, not a proven code invocation; unrecognized
    names stay candidates; placeholder/bookkeeping rows are excluded."""
    n = _normalize(algorithm, **kwargs)
    if n.classification == ASSET and str(kwargs.get("location") or "").lower().endswith(_CONFIG_SUFFIXES):
        n.classification = CONFIGURATION
    return n


def _normalize(
    algorithm: Any,
    *,
    key_size: Any = None,
    mode: Any = None,
    padding: Any = None,
    purpose: Any = None,
    curve: Any = None,
    location: Any = None,
    confidence: Any = None,
) -> Normalized:
    """Normalize one recorded observation. Never raises on odd input."""
    raw = str(algorithm or "").strip()
    purpose_key = _purpose(purpose)
    if not raw or is_placeholder(raw, purpose):
        return Normalized(raw=raw, classification=EXCLUDED, name=raw or "UNKNOWN",
                          exclusion_reason=("placeholder or bookkeeping value, not cryptography"
                                            if raw else "no algorithm recorded"))

    proto = _PROTOCOL.match(raw.replace("_", " ").replace("-", " ").strip())
    if proto:
        return _normalize_protocol(raw, proto.group("proto").upper(), proto.group("version"), location)

    info = parse_algorithm(raw)
    if info.family == "tls-suite":
        return _normalize_suite(raw, info, location)

    reported_bits = _int(key_size)
    reported_mode = str(mode).strip().upper() if mode else None
    reported_padding = str(padding).strip() if padding else None

    if not info.recognized:
        # ephemeral finite-field DH is reported as "DHE" by several scanners
        if raw.upper().startswith(("DHE", "FFDHE", "EDH")):
            info = parse_algorithm("DH")
        else:
            n = Normalized(raw=raw, classification=UNRECOGNIZED, name=raw, family="UNKNOWN",
                           primitive="unknown", primitive_basis="NOT_IN_ALGORITHM_REGISTRY",
                           key_size_bits=reported_bits)
            n.notes.append("the algorithm registry cannot identify this name; review before treating it as cryptography")
            if reported_mode:
                n.mode_reported = reported_mode
                n.mode = reported_mode.lower() if reported_mode.lower() in CDX_MODES else "other"
            return n

    canonical = info.canonical
    family_token = canonical.upper()
    n = Normalized(raw=raw, classification=ASSET, family=canonical, name=canonical,
                   registry_status=info.status, registry_notes=info.notes,
                   quantum_impact=info.quantum_impact)

    mode_token = (info.mode or reported_mode or "").upper() or None
    if reported_mode and info.mode and reported_mode != info.mode.upper():
        n.notes.append(f"recorded mode {reported_mode} conflicts with the algorithm name ({info.mode}); name wins")
    if mode_token:
        n.mode_reported = reported_mode or info.mode
        n.mode = mode_token.lower() if mode_token.lower() in CDX_MODES else "other"
    if reported_padding:
        n.padding_reported = reported_padding
        p = reported_padding.lower().replace("-", "").replace("_", "").replace(" ", "")
        n.padding = {"pkcs1": "pkcs1v15", "pkcs1v15": "pkcs1v15", "pkcs1v1.5": "pkcs1v15", "oaep": "oaep",
                     "pkcs5": "pkcs5", "pkcs7": "pkcs7", "nopadding": "raw", "none": "raw", "raw": "raw",
                     "pss": "other"}.get(p, p if p in CDX_PADDINGS else "other")

    # key size: a size written in the name wins over a separately reported
    # number; a registry *default* size (3DES -> 168) never overrides a
    # recorded one (3DES + 112 is two-key TDEA, not 168).
    named_size = bool(re.search(r"\d{2,}", raw))
    bits = None
    if info.key_size and info.parameter_kind in {"key_bits", "curve_bits"} and named_size:
        bits = info.key_size
    if bits is None and reported_bits and info.parameter_kind not in {"public_key_bytes", "digest_bits"}:
        bits = reported_bits
    if bits is None and info.key_size and info.parameter_kind in {"key_bits", "curve_bits"} \
            and (len(info.allowed_key_sizes) <= 1 and info.canonical.upper() != "3DES"):
        bits = info.key_size   # single fixed size (DES = 56); 3DES keying option is never assumed
    if bits:
        sized = parse_algorithm(f"{info.canonical.split('-')[0] if info.canonical.upper().startswith('AES') else info.canonical}-{bits}")
        if sized.recognized and sized.canonical.split("-")[0] == info.canonical.split("-")[0]:
            n.registry_status, n.registry_notes = sized.status, sized.notes or n.registry_notes
        if info.min_key_size and bits < info.min_key_size and info.parameter_kind != "digest_bits":
            n.registry_status = "DISALLOWED"
            n.notes.append(f"{bits}-bit key is below the {info.min_key_size}-bit minimum (NIST SP 800-131A Rev. 2)")

    is_dhe = raw.upper().startswith(("DHE", "FFDHE", "EDH"))
    base = family_token.split("-")[0] if family_token.startswith(("AES", "SM4", "CAMELLIA", "ARIA")) else family_token

    # ── symmetric block ciphers: identity = family + key size + mode ──────────
    if base in {"AES", "SM4", "CAMELLIA", "ARIA"} or family_token in {"3DES", "DES", "BLOWFISH", "IDEA", "SEED", "RC2"}:
        fam = base if base in {"AES", "SM4", "CAMELLIA", "ARIA"} else family_token
        n.family = fam
        n.key_size_bits = bits
        parts = [fam] + ([str(bits)] if bits and fam not in {"DES"} else []) + ([mode_token] if mode_token else [])
        n.name = "-".join(parts)
        n.parameter_set = str(bits) if bits else None
        n.parameter_set_basis = "KEY_LENGTH_BITS" if bits else None
        n.primitive = "ae" if mode_token in _AEAD_MODES else "block-cipher"
        n.primitive_basis = ("AUTHENTICATED_MODE" if n.primitive == "ae" else
                             "BLOCK_CIPHER_UNAUTHENTICATED_MODE" if mode_token else "BLOCK_CIPHER_MODE_NOT_RECORDED")
        if mode_token == "XTS":
            n.notes.append("XTS is a confidentiality-only storage mode: no integrity protection (SP 800-38E)")
        if fam == "3DES":
            n.name = "3DES" + (f"-{bits}" if bits else "") + (f"-{mode_token}" if mode_token else "")
            n.notes.append({112: "two-key TDEA", 168: "three-key TDEA"}.get(bits or 0, "TDEA keying option not recorded"))
        n.oid = _OIDS.get(n.name)
        n.standard = _STANDARDS.get(fam)
        if fam == "AES" and bits in _AES_QUANTUM_CATEGORY:
            n.classical_level, n.quantum_level = bits, _AES_QUANTUM_CATEGORY[bits]
        elif fam == "3DES" and bits:
            n.classical_level, n.quantum_level = (112 if bits >= 168 else 80), 0
        elif fam == "DES":
            n.classical_level, n.quantum_level = 56, 0
        n.security_level_basis = "NIST SP 800-57 Pt1 Rev5 Table 2; NIST PQC categories" if n.classical_level else None
        _functions(n, purpose_key)
        return n

    # ── stream ciphers / AEAD constructions named as a whole ───────────────────
    if info.family in {"stream-cipher", "aead"}:
        n.primitive = "ae" if info.family == "aead" else "stream-cipher"
        n.key_size_bits = bits
        n.parameter_set = str(bits) if bits else None
        n.parameter_set_basis = "KEY_LENGTH_BITS" if bits else None
        n.oid = _OIDS.get(canonical)
        n.standard = _STANDARDS.get(canonical)
        if canonical.upper() == "CHACHA20-POLY1305":
            n.classical_level = 256
            n.security_level_basis = "256-bit key"
        if family_token in _BROKEN:
            n.quantum_level = 0
        _functions(n, purpose_key)
        return n

    # ── hashes and MACs: identity is the name ──────────────────────────────────
    if info.family in {"hash", "xof"}:
        n.primitive = info.family
        n.primitive_basis = "SHARED_ALGORITHM_REGISTRY"
        n.oid = _OIDS.get(canonical)
        n.standard = _STANDARDS.get(canonical)
        if canonical in _HASH_COLLISION_STRENGTH:
            n.classical_level = _HASH_COLLISION_STRENGTH[canonical]
            n.quantum_level = _HASH_QUANTUM_CATEGORY.get(canonical)
            n.security_level_basis = "collision resistance, NIST SP 800-57 Pt1 Rev5 Table 3; NIST PQC categories"
        elif family_token in _BROKEN:
            n.quantum_level = 0
            n.security_level_basis = "classically collision-broken; no security level stated"
        _functions(n, purpose_key)
        return n
    if info.family == "mac":
        n.primitive = "mac"
        n.oid = _OIDS.get(canonical)
        n.standard = _STANDARDS.get("HMAC") if canonical.upper().startswith("HMAC") else None
        if family_token in _BROKEN:
            n.quantum_level = 0
        _functions(n, purpose_key)
        return n

    # ── post-quantum: parameter sets are not key lengths ───────────────────────
    if info.family in {"kem-pqc", "signature-pqc", "kem-hybrid-pqc"}:
        return _normalize_pqc(n, info, reported_bits, purpose_key)

    # ── public-key algorithms ──────────────────────────────────────────────────
    if family_token in {"RSA", "RSA-PSS", "RSA-OAEP"}:
        n.family = "RSA"
        n.key_size_bits = bits
        n.name = f"RSA-{bits}" if bits else "RSA"
        if family_token == "RSA-PSS":
            n.name += "-PSS"
        if family_token == "RSA-OAEP":
            n.name += "-OAEP"
            n.padding = n.padding or "oaep"
        n.parameter_set = str(bits) if bits else None
        n.parameter_set_basis = "MODULUS_BITS" if bits else None
        if family_token == "RSA-PSS" or any(purpose_key.startswith(p) for p in _SIGNING_PURPOSES):
            n.primitive, n.primitive_basis = "signature", "RECORDED_PURPOSE_SIGNING"
        elif any(purpose_key.startswith(p) for p in _TRANSPORT_PURPOSES) or n.padding == "oaep":
            n.primitive, n.primitive_basis = "pke", "RECORDED_PURPOSE_KEY_TRANSPORT_OR_ENCRYPTION"
        else:
            n.primitive, n.primitive_basis = "pke", "RSA_DEFAULT_PURPOSE_NOT_RECORDED"
        n.oid = _RSA_OID
        n.standard = _STANDARDS["RSA"]
        n.classical_level = _lower_strength(bits, _FFC_IFC_STRENGTH)
        n.quantum_level = 0
        n.security_level_basis = "NIST SP 800-57 Pt1 Rev5 Table 2 (IFC); Shor-vulnerable"
        _functions(n, purpose_key)
        return n

    if family_token in {"DH", "DHE", "FFDH"}:
        n.family = "DHE" if is_dhe else "DH"
        n.key_size_bits = bits
        n.name = f"{n.family}-{bits}" if bits else n.family
        n.parameter_set = str(bits) if bits else None
        n.parameter_set_basis = "GROUP_MODULUS_BITS" if bits else None
        n.primitive = "key-agree"
        n.standard = _STANDARDS["DH"]
        n.classical_level = _lower_strength(bits, _FFC_IFC_STRENGTH)
        n.quantum_level = 0
        n.security_level_basis = "NIST SP 800-57 Pt1 Rev5 Table 2 (FFC); Shor-vulnerable"
        _functions(n, purpose_key)
        return n

    if info.family in {"signature", "key-agree"} or family_token in {"ECDSA", "ECDH", "EDDSA"}:
        n.primitive = "signature" if info.family == "signature" else "key-agree"
        n.key_size_bits = bits
        named_curve = str(curve).strip() if curve else None
        if family_token in {"ED25519", "X25519"}:
            named_curve, bits = "Curve25519", 256
        elif family_token in {"ED448", "X448"}:
            named_curve, bits = "Curve448", 448
        if named_curve:
            n.curve, n.curve_basis = named_curve, "RECORDED_IN_EVIDENCE" if curve else "IMPLIED_BY_ALGORITHM_NAME"
            n.name = canonical if family_token in {"ED25519", "X25519", "ED448", "X448"} else f"{canonical}-{named_curve}"
        elif bits:
            n.name = f"{canonical}-{bits}"
            n.curve_basis = f"NAMED_CURVE_NOT_RECORDED ({bits}-bit field)"
            n.parameter_set = str(bits)
            n.parameter_set_basis = "CURVE_FIELD_BITS"
        n.oid = _OIDS.get(canonical)
        n.standard = _STANDARDS.get(canonical)
        n.classical_level = _lower_strength(bits, _ECC_STRENGTH) if bits else None
        n.quantum_level = 0 if family_token in _SHOR_FAMILIES or info.quantum_impact == "shor" else None
        n.security_level_basis = "NIST SP 800-57 Pt1 Rev5 Table 2 (ECC); Shor-vulnerable" if n.classical_level else (
            "Shor-vulnerable" if n.quantum_level == 0 else None)
        _functions(n, purpose_key)
        return n

    if info.family == "kdf":
        n.primitive = "kdf"
        n.crypto_functions, n.crypto_functions_basis = ["keyderive"], "INHERENT_TO_PRIMITIVE"
        return n

    # anything else the registry knows but CycloneDX has no closer primitive for
    n.primitive = info.family if info.family in CDX_PRIMITIVES else "other"
    n.primitive_basis = "SHARED_ALGORITHM_REGISTRY" if n.primitive != "other" else f"REGISTRY_FAMILY_{info.family.upper()}"
    n.key_size_bits = bits
    _functions(n, purpose_key)
    return n


def _functions(n: Normalized, purpose_key: str) -> None:
    """``cryptoFunctions`` only where the primitive or the recorded purpose
    determines them. Unknown stays absent — never a guessed list."""
    if n.primitive == "hash":
        n.crypto_functions, n.crypto_functions_basis = ["digest"], "INHERENT_TO_PRIMITIVE"
    elif n.primitive == "mac":
        n.crypto_functions, n.crypto_functions_basis = ["tag"], "INHERENT_TO_PRIMITIVE"
    elif n.primitive == "key-agree":
        n.crypto_functions, n.crypto_functions_basis = ["keygen", "keyderive"], "INHERENT_TO_PRIMITIVE"
    elif n.primitive == "kem":
        n.crypto_functions, n.crypto_functions_basis = ["keygen", "encapsulate", "decapsulate"], "INHERENT_TO_PRIMITIVE"
    elif n.primitive == "signature" and any(purpose_key.startswith(p) for p in _SIGNING_PURPOSES):
        n.crypto_functions, n.crypto_functions_basis = ["sign"], "RECORDED_PURPOSE"
    elif n.primitive == "pke" and any(purpose_key.startswith(p) for p in _TRANSPORT_PURPOSES):
        n.crypto_functions, n.crypto_functions_basis = ["encrypt", "decrypt"], "RECORDED_PURPOSE"
    elif n.primitive in {"ae", "block-cipher", "stream-cipher"} and any(purpose_key.startswith(p) for p in _ENCRYPT_PURPOSES):
        n.crypto_functions, n.crypto_functions_basis = ["encrypt", "decrypt"], "RECORDED_PURPOSE"
    else:
        n.crypto_functions_basis = "NOT_ESTABLISHED_BY_EVIDENCE"


def _normalize_pqc(n: Normalized, info: Any, reported_bits: int | None, purpose_key: str) -> Normalized:
    canonical = info.canonical
    n.quantum_impact = None
    if info.family == "kem-hybrid-pqc":
        n.primitive, n.primitive_basis = "combiner", "HYBRID_KEY_EXCHANGE"
        n.family = canonical
        match = re.search(r"MLKEM(\d+)", canonical.upper().replace("-", ""))
        if match and match.group(1) in ML_KEM:
            n.quantum_level = ML_KEM[match.group(1)]["category"]
            n.security_level_basis = "ML-KEM component category (FIPS 203); classical component Shor-vulnerable"
        n.crypto_functions, n.crypto_functions_basis = ["keygen", "encapsulate", "decapsulate"], "INHERENT_TO_PRIMITIVE"
        n.parameter_facts = {"construction": "hybrid (classical + ML-KEM)"}
        return n

    kem = info.family == "kem-pqc"
    n.primitive = "kem" if kem else "signature"
    upper = canonical.upper()
    ml_kem = re.fullmatch(r"ML-KEM(?:-(\d+))?", upper)
    ml_dsa = re.fullmatch(r"ML-DSA(?:-(\d+))?", upper)
    slh = re.fullmatch(r"SLH-DSA-(SHA2|SHAKE)-(128|192|256)([SF])", upper)
    if ml_kem:
        n.family, n.standard = "ML-KEM", _STANDARDS["ML-KEM"]
        pset = ml_kem.group(1)
        if pset is None and reported_bits and str(reported_bits) in ML_KEM:
            pset = str(reported_bits)
            n.parameter_set_basis = "REPORTED_NUMBER_IS_FIPS_203_PARAMETER_SET_NOT_KEY_LENGTH"
        elif pset is not None:
            n.parameter_set_basis = "ALGORITHM_NAME"
        if pset in ML_KEM:
            facts = ML_KEM[pset]
            n.name, n.parameter_set = f"ML-KEM-{pset}", pset
            n.quantum_level = facts["category"]
            n.parameter_facts = {"parameter_set": f"ML-KEM-{pset}", "standard": "FIPS 203",
                                 "public_key_bytes": facts["public_key_bytes"],
                                 "ciphertext_bytes": facts["ciphertext_bytes"],
                                 "shared_secret_bytes": facts["shared_secret_bytes"],
                                 "nist_security_category": facts["category"]}
            n.security_level_basis = "FIPS 203 parameter-set security category"
        else:
            n.parameter_set_basis = "PARAMETER_SET_NOT_RECORDED"
    elif ml_dsa:
        n.family, n.standard = "ML-DSA", _STANDARDS["ML-DSA"]
        pset = ml_dsa.group(1)
        if pset is None and reported_bits and str(reported_bits) in ML_DSA:
            pset = str(reported_bits)
            n.parameter_set_basis = "REPORTED_NUMBER_IS_FIPS_204_PARAMETER_SET_NOT_KEY_LENGTH"
        elif pset is not None:
            n.parameter_set_basis = "ALGORITHM_NAME"
        if pset in ML_DSA:
            facts = ML_DSA[pset]
            n.name, n.parameter_set = f"ML-DSA-{pset}", pset
            n.quantum_level = facts["category"]
            n.parameter_facts = {"parameter_set": f"ML-DSA-{pset}", "standard": "FIPS 204",
                                 "public_key_bytes": facts["public_key_bytes"],
                                 "signature_bytes": facts["signature_bytes"],
                                 "nist_security_category": facts["category"]}
            n.security_level_basis = "FIPS 204 parameter-set security category"
        else:
            n.parameter_set_basis = "PARAMETER_SET_NOT_RECORDED"
    elif slh:
        n.family, n.standard = "SLH-DSA", _STANDARDS["SLH-DSA"]
        n.parameter_set = f"{slh.group(1)}-{slh.group(2)}{slh.group(3).lower()}"
        n.parameter_set_basis = "ALGORITHM_NAME"
        n.name = canonical
        n.quantum_level = SLH_DSA_CATEGORY[slh.group(2)]
        n.parameter_facts = {"parameter_set": canonical, "standard": "FIPS 205",
                             "nist_security_category": n.quantum_level}
        n.security_level_basis = "FIPS 205 parameter-set security category"
    n.oid = _OIDS.get(n.name)
    if kem:
        n.crypto_functions, n.crypto_functions_basis = ["keygen", "encapsulate", "decapsulate"], "INHERENT_TO_PRIMITIVE"
    elif any(purpose_key.startswith(p) for p in _SIGNING_PURPOSES):
        n.crypto_functions, n.crypto_functions_basis = ["sign"], "RECORDED_PURPOSE"
    else:
        n.crypto_functions_basis = "NOT_ESTABLISHED_BY_EVIDENCE"
    return n


def _normalize_protocol(raw: str, proto: str, version: str | None, location: Any) -> Normalized:
    version = version if version and "." in version else (f"{version}.0" if version else None)
    if proto in {"TLS", "DTLS", "SSL"}:
        ptype = "tls"
    else:
        ptype = {"SSH": "ssh", "IPSEC": "ipsec", "IKE": "ike"}[proto]
    label = {"TLS": "TLS", "DTLS": "DTLS", "SSL": "SSL", "SSH": "SSH", "IPSEC": "IPsec", "IKE": "IKE"}[proto]
    status, notes = "UNKNOWN", ""
    if version and proto in {"TLS", "DTLS"}:
        info = parse_algorithm(f"{label} {version}")
        if info.recognized:
            status, notes = info.status, info.notes
    elif proto == "SSL":
        status, notes = "DISALLOWED", "SSL is prohibited (RFC 6176 / RFC 7568)"
    n = Normalized(raw=raw, classification=ASSET, asset_type="protocol", family=label,
                   name=f"{label} {version}" if version else f"{label} (version not established)",
                   primitive="other", primitive_basis="PROTOCOL_NOT_AN_ALGORITHM",
                   registry_status=status, registry_notes=notes,
                   protocol_type=ptype, protocol_version=version)
    if not version:
        n.notes.append("protocol recorded without a version; negotiated versions and cipher suites not established")
    return n


def _normalize_suite(raw: str, info: Any, location: Any) -> Normalized:
    n = Normalized(raw=raw, classification=ASSET, asset_type="protocol", family="TLS",
                   name=f"TLS cipher suite {info.canonical}", primitive="other",
                   primitive_basis="PROTOCOL_NOT_AN_ALGORITHM", registry_status=info.status,
                   registry_notes=info.notes, protocol_type="tls")
    n.parameter_facts = {"cipher_suite": info.canonical}
    return n


def suite_algorithms(suite: str) -> list[tuple[str, str]]:
    """``[(role, algorithm name)]`` for a TLS cipher suite name, via the shared
    registry's suite breakdown. Empty when the suite is not recognized."""
    info = parse_algorithm(suite)
    if info.family != "tls-suite":
        return []
    out: list[tuple[str, str]] = []
    for comp in info.components:
        name = comp.get("algorithm") or comp.get("name")
        role = str(comp.get("role") or comp.get("kind") or "component")
        if name:
            out.append((role, str(name)))
    return out
