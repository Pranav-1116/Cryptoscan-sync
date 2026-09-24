"""Precision-first crypto rule pack for configuration files.

Complements ``config_crypto_parser`` (nginx/apache/openssl/terraform/haproxy
directives) with the remaining high-signal config idioms:

* OpenSSH ``sshd_config``/``ssh_config`` directives (Ciphers, MACs,
  KexAlgorithms, HostKeyAlgorithms, HostKey) with per-item algorithm emission
* TLS version keys in env/yaml/properties (``TLS_MIN_VERSION=1.0``,
  ``ssl.protocol: TLSv1``) and IANA/OpenSSL cipher-suite names
* JWT algorithm keys (``JWT_ALGORITHM=HS256``, ``jwt.algorithm: RS256``)
* JCA transformation strings in properties (``AES/GCM/NoPadding``)
* Password-hash / cipher-name keys and verification kill-switches
  (``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``StrictHostKeyChecking no``)
* PEM key/cert blocks embedded in config

Every rule is anchored at a line start and requires an explicit key/value
separator so that prose, image tags and unrelated words never match.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Iterable

from scanner.extractors.cipher_suites import suite_components
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

# ---------------------------------------------------------------------------
# OpenSSH token tables
# ---------------------------------------------------------------------------
_SSH_CIPHER = [
    (re.compile(r"^3des"), "3DES"),
    (re.compile(r"^aes\d{3}"), "AES"),
    (re.compile(r"^chacha20-poly1305"), "ChaCha20-Poly1305"),
    (re.compile(r"^arcfour|^rc4"), "RC4"),
    (re.compile(r"^blowfish"), "Blowfish"),
    (re.compile(r"^cast128"), "CAST5"),
    (re.compile(r"^des-cbc$"), "DES"),
]
_SSH_MAC_DIGEST = [
    (re.compile(r"md5"), "MD5"),
    (re.compile(r"sha1"), "SHA-1"),
    (re.compile(r"sha2-256|sha256"), "SHA-256"),
    (re.compile(r"sha2-512|sha512"), "SHA-512"),
    (re.compile(r"ripemd160"), "RIPEMD-160"),
]
_SSH_KEX = [
    (re.compile(r"^diffie-hellman-"), "DH"),
    (re.compile(r"^ecdh-sha2-"), "ECDH"),
    (re.compile(r"^curve25519-|^sntrup761x25519"), "X25519"),
]
_SSH_HOSTKEY = [
    (re.compile(r"ssh-rsa|rsa-sha2|_rsa_key|ssh_host_rsa"), "RSA"),
    (re.compile(r"ssh-dss|_dsa_key|ssh_host_dsa"), "DSA"),
    (re.compile(r"ecdsa-sha2|_ecdsa_key|ssh_host_ecdsa"), "ECDSA"),
    (re.compile(r"ssh-ed25519|_ed25519_key|ssh_host_ed25519"), "Ed25519"),
]

_SSH_DIRECTIVE = re.compile(
    r"(?im)^\s*(Ciphers|MACs|KexAlgorithms|HostKeyAlgorithms|HostKey|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|CASignatureAlgorithms)\s+([^#\n]+)"
)

_WEAK_SSH = {"3DES", "RC4", "Blowfish", "CAST5", "DES", "MD5", "SHA-1", "DSA", "RIPEMD-160"}


def _ssh_items(directive: str, value: str) -> Iterable[tuple[str, str, str]]:
    """Yield (algorithm, api_type, token) for one OpenSSH directive line."""
    tokens = [t.strip().lstrip("+-^") for t in value.split(",") if t.strip()]
    d = directive.lower()
    for tok in tokens:
        low = tok.lower()
        if d == "ciphers":
            for rx, algo in _SSH_CIPHER:
                if rx.search(low):
                    yield algo, "CIPHER_INSTANCE", tok
                    break
        elif d == "macs":
            if low.startswith("hmac-") or low.startswith("umac-"):
                yield "HMAC", "MAC", tok
            for rx, algo in _SSH_MAC_DIGEST:
                if rx.search(low):
                    yield algo, "HASH", tok
                    break
        elif d == "kexalgorithms":
            for rx, algo in _SSH_KEX:
                if rx.search(low):
                    yield algo, "KEY_AGREEMENT", tok
                    break
            if low.endswith("-sha1"):
                yield "SHA-1", "HASH", tok
            elif "sha256" in low:
                yield "SHA-256", "HASH", tok
            elif "sha512" in low:
                yield "SHA-512", "HASH", tok
        else:  # HostKey / HostKeyAlgorithms / PubkeyAccepted* / CASignatureAlgorithms
            for rx, algo in _SSH_HOSTKEY:
                if rx.search(low):
                    yield algo, "SIGNATURE", tok
                    break


# ---------------------------------------------------------------------------
# Generic key = value rules
# ---------------------------------------------------------------------------
_SEP = r"\s*[=:]\s*['\"]?"  # mandatory separator (env / yaml / ini / properties)
_LIST = r"^\s*(?:-\s*|(?:ENV|ARG|export|SET|setenv)\s+)?"  # yaml list dash / Dockerfile ENV / shell export

_TLSV = {
    "1.0": "TLS1.0", "1": "TLS1.0", "10": "TLS1.0", "1.1": "TLS1.1", "11": "TLS1.1",
    "1.2": "TLS1.2", "12": "TLS1.2", "1.3": "TLS1.3", "13": "TLS1.3",
    "tlsv1": "TLS1.0", "tlsv1.0": "TLS1.0", "tlsv1_0": "TLS1.0", "tlsv1.1": "TLS1.1",
    "tlsv1_1": "TLS1.1", "tlsv1.2": "TLS1.2", "tlsv1_2": "TLS1.2", "tlsv1.3": "TLS1.3",
    "tlsv1_3": "TLS1.3", "tls1": "TLS1.0", "tls1.0": "TLS1.0", "tls1.1": "TLS1.1",
    "tls1.2": "TLS1.2", "tls1.3": "TLS1.3", "sslv3": "SSLv3", "ssl3": "SSLv3",
    "sslv2": "SSLv2", "ssl2": "SSLv2", "tls": "TLS", "ssl": "TLS",
}

_TLS_VERSION_KEY = re.compile(
    _LIST
    + r"(?:[A-Za-z0-9_.\-]*?(?:tls|ssl)[_.\-]?(?:min|max|minimum|maximum)?[_.\-]?(?:version|protocols?|protocol[_.\-]version)|"
    r"(?:min|max|minimum|maximum)[_.\-]?(?:tls|ssl)[_.\-]?version|enabled[_.\-]protocols|ssl[_.\-]?protocol)"
    + r"(?:" + _SEP + r"|\s+['\"]?(?=[TtSs][LlSs][SsLl]))"
    + r"([A-Za-z0-9._,\s+\-]+?)['\"]?\s*(?:#.*)?$",
    re.I | re.M,
)

_JWT_ALG_KEY = re.compile(
    _LIST + r"(?:[A-Za-z0-9_.\-]*?jwt[_.\-]?(?:alg|algorithm|signing[_.\-]?alg(?:orithm)?)|"
    r"(?:token|oauth2?|oidc)[_.\-]?(?:signing[_.\-]?)?alg(?:orithm)?|jws[_.\-]?alg(?:orithm)?s?|signing[_.\-]?algorithm|id[_.\-]token[_.\-]signing[_.\-]alg(?:orithm)?)" + _SEP
    + r"((?:HS|RS|PS|ES)(?:256|384|512)|EdDSA|none)\b",
    re.I | re.M,
)

_CIPHER_SUITE_KEY = re.compile(
    _LIST + r"[A-Za-z0-9_.\-]*?(?:cipher[_.\-]?suites?|ciphers|ssl[_.\-]?cipher(?:[_.\-]?list)?)" + _SEP
    + r"([A-Za-z0-9_:+!@\-,\s]+?)['\"]?\s*(?:#.*)?$",
    re.I | re.M,
)

_JCA_TRANSFORMATION_KEY = re.compile(
    _LIST + r"[A-Za-z0-9_.\-]*?(?:algorithm|transformation|cipher)" + _SEP
    + r"((?:AES|DES|DESede|TripleDES|Blowfish|RC2|RC4|ARCFOUR|ChaCha20)(?:[_-]\d{3})?(?:/[A-Za-z0-9]+/[A-Za-z0-9]+)?|"
    r"(?:HmacSHA(?:1|224|256|384|512)|HmacMD5)|PBKDF2WithHmacSHA(?:1|256|512)|PBEWith[A-Za-z0-9]+|"
    r"RSA/[A-Za-z0-9]+/[A-Za-z0-9\-]+|SHA-?(?:1|224|256|384|512)|MD5|SHA3-(?:256|512))(?![A-Za-z0-9/])",
    re.M,
)

_PASSWORD_HASH_KEY = re.compile(
    _LIST + r"[A-Za-z0-9_.\-]*?(?:password[_.\-]?(?:hash(?:er|ing)?|encoder|algorithm|scheme|encryption)|hash[_.\-]?(?:algorithm|scheme|method))" + _SEP
    + r"(bcrypt|scrypt|argon2(?:id?|d)?|pbkdf2(?:[_-]?sha(?:1|256|512))?|md5(?:[_-]?crypt)?|sha[_-]?(?:1|256|512)(?:[_-]?crypt)?|plaintext|noop|clear(?:text)?|crypt)\b",
    re.I | re.M,
)
_PW_MAP = {
    "bcrypt": "BCRYPT", "scrypt": "SCRYPT", "argon2": "ARGON2", "pbkdf2": "PBKDF2",
    "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512",
    "plaintext": "PLAINTEXT", "noop": "PLAINTEXT", "clear": "PLAINTEXT", "cleartext": "PLAINTEXT", "crypt": "DES",
}

_VERIFY_OFF = re.compile(
    _LIST + r"(NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY|GIT_SSL_NO_VERIFY|CURL_INSECURE|"
    r"[A-Za-z0-9_.\-]*?(?:ssl|tls)[_.\-]?verify(?:[_.\-]?(?:peer|host|ssl))?|[A-Za-z0-9_.\-]*?(?:insecure[_.\-]?skip[_.\-]?verify|skip[_.\-]?(?:tls|ssl)[_.\-]?verify)|"
    r"[A-Za-z0-9_.\-]*?(?:verify[_.\-]?(?:ssl|tls|certs?|certificate|peer))|StrictHostKeyChecking|rejectUnauthorized|sslmode|ssl-mode|ssl[_.\-]?insecure)"
    r"(?:\s*[=:]\s*|\s+)['\"]?(0|false|no|off|none|disable|disabled|true|yes|1|on|skip|allow|prefer|require|verify-ca|verify-full|accept-new|ask)\b",
    re.I | re.M,
)

_PEM_BLOCK = re.compile(r"^-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|CERTIFICATE|PUBLIC KEY|(?:RSA |EC |DSA )?PUBLIC KEY)-----", re.M)
_PEM_DEK = re.compile(r"^DEK-Info:\s*([A-Z0-9-]+)", re.M)
_CURVE_KEY = re.compile(
    _LIST + r"(?![A-Za-z0-9_.\-]*ecdsa)[A-Za-z0-9_.\-]*?(?:curves?|ecdh[_.\-]?curve|named[_.\-]?groups?|groups)" + _SEP
    + r"([A-Za-z0-9:,_\s\-]+?)['\"]?\s*(?:#.*)?$",
    re.I | re.M,
)
_DHPARAM_KEY = re.compile(_LIST + r"(?:ssl[_.\-]?)?dh[_.\-]?param(?:s|_file|eters)?(?:\s*[=:]\s*|\s+)['\"]?(\S+)", re.I | re.M)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _tls_from_tokens(value: str) -> Iterable[tuple[str, str]]:
    for tok in re.split(r"[\s,+]+", value.strip()):
        low = tok.strip("'\"").lower()
        if not low or low in {"true", "false", "on", "off", "yes", "no", "all", "auto", "default", "none"}:
            continue
        algo = _TLSV.get(low) or _TLSV.get(low.replace("v", "", 1)) or _TLSV.get(low.replace("_", "."))
        if algo:
            yield algo, tok
        elif re.fullmatch(r"-?(?:tls|ssl)v?\d(?:[._]\d)?", low):
            yield "TLS", tok


def run_config_rules(
    file_path: Path,
    repo_root: Path | None,
    text: str,
    scanner_id: str,
    seen: set[tuple[int, str, str]] | None = None,
) -> list[RawFinding]:
    """Apply the config rule pack to ``text`` and return RawFindings.

    ``seen`` (line, algorithm, api_type) de-duplicates against findings the
    caller has already produced from the same line.
    """
    findings: list[RawFinding] = []
    seen = seen if seen is not None else set()
    name = file_path.name.lower()
    is_ssh = "ssh" in name

    def emit(pos: int, algo: str, api_type: str, purpose: str, library: str, raw: str,
             confidence: str = "HIGH", reason: str = "config-directive", **kw) -> None:
        ln = _line(text, pos)
        key = (ln, algo, api_type)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=ln,
                language="CONFIG",
                api_type=api_type,
                algorithm=algo,
                purpose=purpose,
                library=library,
                scanner_id=scanner_id,
                confidence=confidence,
                confidence_reason=reason,
                raw_transformation=raw[:80],
                **kw,
            )
        )

    # --- OpenSSH --------------------------------------------------------
    for m in _SSH_DIRECTIVE.finditer(text):
        directive, value = m.group(1), m.group(2)
        # HostKey/Ciphers/MACs are unique to ssh configs; only accept in other
        # files when the directive itself is unambiguous (KexAlgorithms etc.).
        if not is_ssh and directive.lower() in {"hostkey", "ciphers", "macs"} and "ssh" not in text.lower():
            continue
        for algo, api_type, tok in _ssh_items(directive, value):
            emit(m.start(), algo, api_type, "SSH", "openssh", f"{directive} {tok}",
                 reason="weak-ssh-algorithm" if algo in _WEAK_SSH else "ssh-directive")

    # --- TLS versions ----------------------------------------------------
    for m in _TLS_VERSION_KEY.finditer(text):
        for algo, tok in _tls_from_tokens(m.group(1)):
            emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", m.group(0).strip(),
                 reason="tls-version-setting")

    # --- Cipher suites --------------------------------------------------
    for m in _CIPHER_SUITE_KEY.finditer(text):
        value = m.group(1)
        if not re.search(r"(?i)(?:TLS_|SSL_|ECDHE|DHE|RSA|AES|3DES|RC4|CHACHA|NULL|EXP)", value):
            continue
        emit(m.start(), "TLS-CIPHERS", "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", "tls-config", value,
             confidence="MEDIUM", reason="cipher-suite-list")
        for algo, api_type in suite_components(value):
            emit(m.start(), algo, api_type, "NETWORK_ENCRYPTION", "tls-config", value, reason="cipher-suite-list")

    # --- JWT --------------------------------------------------------------
    for m in _JWT_ALG_KEY.finditer(text):
        alg = m.group(1)
        emit(m.start(), "JWT", "SIGNATURE", "AUTHENTICATION", "jwt", alg, reason="jwt-algorithm-setting")
        emit(m.start(), alg.upper() if alg.lower() != "eddsa" else "EdDSA", "SIGNATURE", "AUTHENTICATION", "jwt", alg,
             reason="jwt-algorithm-setting")
        if alg.lower() == "none":
            emit(m.start(), "JWT-NONE", "SIGNATURE", "AUTHENTICATION", "jwt", alg, reason="jwt-alg-none")

    # --- JCA transformation strings in properties -----------------------------
    try:
        from scanner.extractors.algorithm_extractor import parse_transformation
    except Exception:  # pragma: no cover
        parse_transformation = None  # type: ignore[assignment]
    for m in _JCA_TRANSFORMATION_KEY.finditer(text):
        raw = m.group(1)
        algo, mode, padding = raw, None, None
        if parse_transformation is not None:
            try:
                parsed = parse_transformation(raw)
                algo = parsed.algorithm or raw
                mode, padding = parsed.mode, parsed.padding
            except Exception:
                pass
        api_type = "HASH" if algo.upper().startswith(("SHA", "MD5")) else "MAC" if "HMAC" in algo.upper() else "KDF" if "PBKDF2" in algo.upper() else "CIPHER_INSTANCE"
        emit(m.start(), algo, api_type, "DATA_ENCRYPTION", "jca-config", raw, reason="jca-transformation-setting",
             mode=mode, padding=padding)

    # --- Password hashing scheme -------------------------------------------
    for m in _PASSWORD_HASH_KEY.finditer(text):
        val = m.group(1).lower()
        key = re.sub(r"[_\-]", "", val)
        algo = next((a for k, a in _PW_MAP.items() if key.startswith(k.replace("-", ""))), None)
        if algo:
            emit(m.start(), algo, "KDF" if algo in {"BCRYPT", "SCRYPT", "ARGON2", "PBKDF2"} else "HASH",
                 "PASSWORD_HASHING", "app-config", m.group(1), reason="password-hash-setting")

    # --- Verification kill-switches -----------------------------------------
    for m in _VERIFY_OFF.finditer(text):
        key, val = m.group(1), m.group(2).lower()
        k = key.lower()
        disabled = (
            (k in {"node_tls_reject_unauthorized", "pythonhttpsverify"} and val == "0")
            or (k in {"git_ssl_no_verify", "curl_insecure"} and val in {"1", "true", "yes", "on"})
            or ("skip" in k and val in {"1", "true", "yes", "on"})
            or ("insecure" in k and val in {"1", "true", "yes", "on"})
            or (k == "stricthostkeychecking" and val in {"no", "off", "false"})
            or (k == "rejectunauthorized" and val in {"false", "0"})
            or (k in {"sslmode", "ssl-mode"} and val in {"disable", "disabled", "allow", "prefer", "require"})
            or (k not in {"sslmode", "ssl-mode", "stricthostkeychecking", "rejectunauthorized", "git_ssl_no_verify", "curl_insecure"}
                and "skip" not in k and "insecure" not in k and val in {"0", "false", "no", "off", "none", "disable", "disabled"})
        )
        if not disabled:
            continue
        if k == "stricthostkeychecking":
            emit(m.start(), "SSH-HOSTKEY-NONE", "KEY_AGREEMENT", "SSH", "openssh", m.group(0).strip(), reason="host-key-verification-disabled")
        else:
            emit(m.start(), "TLS-CERT-NONE", "TLS_CONTEXT", "NETWORK_ENCRYPTION", "tls-config", m.group(0).strip(),
                 reason="certificate-verification-disabled")

    # --- PEM blocks -----------------------------------------------------------
    for m in _PEM_BLOCK.finditer(text):
        label = m.group(1)
        algo = "RSA" if label.startswith("RSA") else "ECDSA" if label.startswith("EC") else "DSA" if label.startswith("DSA") else "X509" if label == "CERTIFICATE" else "UNKNOWN"
        emit(m.start(), algo, "KEY_MATERIAL", "KEY_STORAGE", "pem", label,
             confidence="HIGH", reason="pem-block-in-config",
             is_hardcoded_key="PRIVATE" in label)
    for m in _PEM_DEK.finditer(text):
        dek = m.group(1).upper()
        algo = "3DES" if "DES-EDE3" in dek else "DES" if dek.startswith("DES") else "AES" if dek.startswith("AES") else dek
        emit(m.start(), algo, "CIPHER_INSTANCE", "KEY_STORAGE", "pem", dek, reason="pem-dek-info")

    # --- Curves / DH params ---------------------------------------------------
    for m in _CURVE_KEY.finditer(text):
        for tok in re.split(r"[\s,:]+", m.group(1)):
            low = tok.lower()
            if low in {"x25519", "curve25519"}:
                emit(m.start(), "X25519", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", tok, reason="curve-setting")
            elif re.fullmatch(r"(?:secp\d{3}[rk]1|prime\d{3}v1|p-?(?:256|384|521)|brainpoolp\d{3}[rt]1)", low):
                emit(m.start(), "ECDH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", tok, reason="curve-setting")
            elif re.fullmatch(r"ffdhe\d{4}", low):
                emit(m.start(), "DH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", tok, reason="curve-setting")
            elif low.startswith(("x25519kyber", "x25519mlkem", "secp256r1mlkem")):
                emit(m.start(), "ML-KEM", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", tok, reason="curve-setting")
    for m in _DHPARAM_KEY.finditer(text):
        emit(m.start(), "DH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", m.group(0).strip(),
             confidence="MEDIUM", reason="dhparam-setting")

    return findings
