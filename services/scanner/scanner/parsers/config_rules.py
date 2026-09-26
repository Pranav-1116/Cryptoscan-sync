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
    (re.compile(r"^curve25519-|^sntrup761x25519|^mlkem768x25519"), "X25519"),
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
            if "mlkem" in low or "kyber" in low:  # OpenSSH 9.9+ mlkem768x25519-sha256 hybrid
                yield "ML-KEM", "KEY_AGREEMENT", tok
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
    + r"(?:[A-Za-z0-9_./\-]*?(?:tls|ssl)[_.\-]?(?:min|max|minimum|maximum)?[_.\-]?(?:version|protocols?|protocol[_.\-]version)|"
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
    _LIST + r"[A-Za-z0-9_./\-]*?(?:cipher[_.\-]?suites?|ciphers|ssl[_.\-]?cipher(?:[_.\-]?list)?)" + _SEP
    + r"\[?([A-Za-z0-9_:+!@\-,\s]+?)\]?['\"]?\s*(?:#.*)?$",
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
    + r"(bcrypt|scrypt|argon2(?:id?|d)?|pbkdf2(?:[_-]?sha(?:1|256|512))?|md5(?:[_-]?crypt)?|scram[_-]sha[_-]256|sha[_-]?(?:1|256|512)(?:[_-]?crypt)?|plaintext|noop|clear(?:text)?|crypt)\b",
    re.I | re.M,
)
# PostgreSQL pg_hba.conf:  host  all  all  10.0.0.0/8  scram-sha-256
_PG_HBA = re.compile(
    r"^\s*(local|hostssl|hostnossl|hostgssenc|hostnogssenc|host)\s+\S+\s+\S+(?:\s+(?!md5\b|scram-sha-256\b|password\b|trust\b|cert\b|reject\b|peer\b|ident\b|gss\b|sspi\b|ldap\b|radius\b|pam\b|bsd\b)\S+){0,2}\s+(md5|scram-sha-256|password|trust|cert|reject|peer|ident|gss|sspi|ldap|radius|pam|bsd)\b",
    re.M,
)
_PG_HBA_MAP = {"md5": "MD5", "scram-sha-256": "SHA-256", "password": "PLAINTEXT", "cert": "X509"}
# MySQL / MariaDB authentication plugins
_MYSQL_AUTH = re.compile(
    _LIST + r"(?:default[_-]authentication[_-]plugin|authentication[_-]policy|auth[_-]plugin|default[_-]auth)" + _SEP
    + r"\*?(caching_sha2_password|sha256_password|mysql_native_password|mysql_old_password|mysql_clear_password|ed25519)\b",
    re.I | re.M,
)
_MYSQL_TLS = re.compile(_LIST + r"require[_-]secure[_-]transport" + _SEP + r"(?:ON|1|true)\b", re.I | re.M)
_MYSQL_AUTH_MAP = {"caching_sha2_password": "SHA-256", "sha256_password": "SHA-256", "mysql_native_password": "SHA-1", "mysql_old_password": "PLAINTEXT", "mysql_clear_password": "PLAINTEXT", "ed25519": "Ed25519"}
_PW_MAP = {
    "scramsha256": "SHA-256",
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

_PROTOCOL_KEY = re.compile(_LIST + r"(?:protocol|protocols|min[_.\-]?protocol|max[_.\-]?protocol)" + _SEP + r"((?:TLS|SSL)[A-Za-z0-9._,\s+\-]*?)['\"]?\s*(?:#.*)?$", re.M)
_TLS_MODE_KEY = re.compile(_LIST + r"(?:mode|(?:tls|ssl)[_.\-]?mode)" + _SEP + r"(requireTLS|preferTLS|allowTLS|requireSSL|preferSSL|allowSSL|VERIFY_IDENTITY|VERIFY_CA|REQUIRED|verify-full|verify-ca|require)\b", re.M)
_SSE_KEY = re.compile(_LIST + r"(?:SSEAlgorithm|sse[_.\-]?algorithm|ServerSideEncryption|server[_.\-]?side[_.\-]?encryption|encryption[_.\-]?type|EncryptionType)" + _SEP + r"(AES256|aws:kms|aws:kms:dsse|KMS|AES_256|AES)\b", re.I | re.M)
_SSL_POLICY_KEY = re.compile(_LIST + r"(?:SslPolicy|ssl[_.\-]?policy|security[_.\-]?policy|tls[_.\-]?policy)" + _SEP + r"((?:ELBSecurityPolicy|TLS|SSL)[A-Za-z0-9._\-]*)", re.M)
_KEY_TYPE_KEY = re.compile(_LIST + r"(?:key[_.\-]?type|key[_.\-]?algorithm|key[_.\-]?spec|customer[_.\-]?master[_.\-]?key[_.\-]?spec|KeySpec|algorithm)" + _SEP + r"(RSA(?:[_-](?:HSM|2048|3072|4096))?|EC(?:[_-]HSM)?|ECDSA|ECC[_-]NIST[_-]P(?:256|384|521)|ECC[_-]SECG[_-]P256K1|ED25519|Ed25519|SYMMETRIC_DEFAULT|HMAC[_-](?:224|256|384|512)|oct(?:[_-]HSM)?)\b", re.M)
_ELB_TLS = [("TLS13", "TLS1.3"), ("TLS-1-2", "TLS1.2"), ("TLS-1-1", "TLS1.1"), ("TLS-1-0", "TLS1.0"), ("FS-1-2", "TLS1.2"), ("FS-1-1", "TLS1.1"), ("2016-08", "TLS1.0"), ("2015-05", "TLS1.0"), ("2015-03", "TLS1.0"), ("2015-02", "TLS1.0"), ("FS-2018-06", "TLS1.0")]

_PEM_BLOCK = re.compile(r"^-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|CERTIFICATE|PUBLIC KEY|(?:RSA |EC |DSA )?PUBLIC KEY)-----", re.M)
_PEM_DEK = re.compile(r"^DEK-Info:\s*([A-Z0-9-]+)", re.M)
# Kerberos enctypes (krb5.conf, kdc.conf, sssd, AD msDS-SupportedEncryptionTypes lists)
_KRB_ENCTYPE = re.compile(
    r"\b(aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|aes256-cts-hmac-sha384-192|aes128-cts-hmac-sha256-128|aes256-cts|aes128-cts|"
    r"rc4-hmac(?:-exp)?|arcfour-hmac(?:-md5|-exp)?|des3-cbc-sha1(?:-kd)?|des3-hmac-sha1|des-cbc-crc|des-cbc-md5|des-cbc-md4|des-hmac-sha1|camellia(?:128|256)-cts-cmac)\b",
    re.I,
)
_KRB_ENCTYPE_MAP = {
    "aes256-cts-hmac-sha1-96": ("AES", "HMAC", "SHA-1"), "aes128-cts-hmac-sha1-96": ("AES", "HMAC", "SHA-1"),
    "aes256-cts-hmac-sha384-192": ("AES", "HMAC", "SHA-384"), "aes128-cts-hmac-sha256-128": ("AES", "HMAC", "SHA-256"),
    "aes256-cts": ("AES",), "aes128-cts": ("AES",),
    "rc4-hmac": ("RC4", "HMAC", "MD5"), "rc4-hmac-exp": ("RC4", "HMAC", "MD5"), "arcfour-hmac": ("RC4", "HMAC", "MD5"), "arcfour-hmac-md5": ("RC4", "HMAC", "MD5"), "arcfour-hmac-exp": ("RC4", "HMAC", "MD5"),
    "des3-cbc-sha1": ("3DES", "SHA-1"), "des3-cbc-sha1-kd": ("3DES", "SHA-1"), "des3-hmac-sha1": ("3DES", "HMAC", "SHA-1"),
    "des-cbc-crc": ("DES",), "des-cbc-md5": ("DES", "MD5"), "des-cbc-md4": ("DES", "MD4"), "des-hmac-sha1": ("DES", "HMAC", "SHA-1"),
    "camellia128-cts-cmac": ("Camellia", "CMAC"), "camellia256-cts-cmac": ("Camellia", "CMAC"),
}
# Windows: security templates (.inf), .reg exports, GPO registry.pol dumps — SCHANNEL ciphers/protocols and Kerberos etype bitmasks
_WIN_SCHANNEL = re.compile(
    r"SCHANNEL\\(Protocols|Ciphers|Hashes|KeyExchangeAlgorithms)\\([^\\\n=]+?)(?:\\(Server|Client))?\\(Enabled|DisabledByDefault)\s*[=:]\s*(?:(dword|hex|4)\s*[:,]\s*)?(?:0x)?([0-9a-fA-F]+)",
    re.I,
)
_WIN_SCHANNEL_NAME = {
    "ssl 2.0": "SSLv2", "ssl 3.0": "SSLv3", "tls 1.0": "TLS1.0", "tls 1.1": "TLS1.1", "tls 1.2": "TLS1.2", "tls 1.3": "TLS1.3", "pct 1.0": "SSLv2", "dtls 1.0": "TLS1.1", "dtls 1.2": "TLS1.2",
    "rc4 128/128": "RC4", "rc4 64/128": "RC4", "rc4 56/128": "RC4", "rc4 40/128": "RC4", "rc2 128/128": "RC2", "rc2 56/128": "RC2", "rc2 40/128": "RC2",
    "des 56/56": "DES", "triple des 168": "3DES", "triple des 168/168": "3DES", "aes 128/128": "AES", "aes 256/256": "AES", "null": "NULL",
    "md5": "MD5", "sha": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "diffie-hellman": "DH", "pkcs": "RSA", "ecdh": "ECDH",
}
_WIN_KRB_ETYPES = re.compile(r"(?:Kdc|Kerberos)\\Parameters\\SupportedEncryptionTypes\s*[=:]\s*(?:(dword|4)\s*[:,]\s*)?(?:0x)?([0-9a-fA-F]+)", re.I)
# generic policy keys (IBM MQ AMS policies, gateway YAML): signing: SHA256 / encryption: AES256 / digest_algorithm: SHA1
_POLICY_ALGO_KEY = re.compile(
    _LIST + r"[A-Za-z0-9_.\-]*?(?:signing|signature|digest|hash|encryption|cipher|encrypt)(?:[_.\-]?(?:algorithm|alg|method))?" + _SEP
    + r"(SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5|AES-?128|AES-?192|AES-?256|AES|3DES|TDES|DES|RC2|RC4|NONE)\b['\"]?\s*(?:#.*)?$",
    re.I | re.M,
)
_POLICY_ALGO_MAP = {"sha1": "SHA-1", "sha-1": "SHA-1", "sha224": "SHA-224", "sha-224": "SHA-224", "sha256": "SHA-256", "sha-256": "SHA-256", "sha384": "SHA-384", "sha-384": "SHA-384",
                    "sha512": "SHA-512", "sha-512": "SHA-512", "md5": "MD5", "aes128": "AES", "aes-128": "AES", "aes192": "AES", "aes-192": "AES", "aes256": "AES", "aes-256": "AES", "aes": "AES",
                    "3des": "3DES", "tdes": "3DES", "des": "DES", "rc2": "RC2", "rc4": "RC4", "none": "NULL"}

_CURVE_KEY = re.compile(
    _LIST + r"(?![A-Za-z0-9_.\-]*ecdsa)[A-Za-z0-9_.\-]*?(?:curves?|ecdh[_.\-]?curve|named[_.\-]?groups?|groups)" + _SEP
    + r"([A-Za-z0-9:,_\s\-]+?)['\"]?\s*(?:#.*)?$",
    re.I | re.M,
)
# OpenSSL 3.x `SignatureAlgorithms = mldsa65:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256` / nginx `ssl_conf_command SignatureAlgorithms`
_SIGALGS_KEY = re.compile(_LIST + r"(?:ssl_conf_command\s+)?(?:Client)?SignatureAlgorithms" + _SEP + r"([A-Za-z0-9:,_+\s\-]+?)['\"]?\s*(?:#.*)?$", re.I | re.M)
_SIGALG_TOKEN = [
    (re.compile(r"^(?:ml-?dsa|dilithium)"), "ML-DSA", "SIGNATURE"),
    (re.compile(r"^(?:slh-?dsa|sphincs)"), "SLH-DSA", "SIGNATURE"),
    (re.compile(r"^(?:falcon)"), "FALCON", "SIGNATURE"),
    (re.compile(r"^ecdsa"), "ECDSA", "SIGNATURE"),
    (re.compile(r"^rsa"), "RSA", "SIGNATURE"),
    (re.compile(r"^ed25519"), "Ed25519", "SIGNATURE"),
    (re.compile(r"^ed448"), "Ed448", "SIGNATURE"),
    (re.compile(r"sha256"), "SHA-256", "MESSAGE_DIGEST"),
    (re.compile(r"sha384"), "SHA-384", "MESSAGE_DIGEST"),
    (re.compile(r"sha512"), "SHA-512", "MESSAGE_DIGEST"),
    (re.compile(r"sha1$"), "SHA-1", "MESSAGE_DIGEST"),
]
_DHPARAM_KEY = re.compile(_LIST + r"(?:ssl[_.\-]?)?dh[_.\-]?param(?:s|_file|eters)?(?:\s*[=:]\s*|\s+)['\"]?(\S+)", re.I | re.M)



# --- Bank middleware: IBM MQ, WebSphere, WebLogic, IBM JSSE2/JCE, QuickFIX/J, SWIFT SAG -------------------
_MQ_CIPHERSPEC = {
    "tls_rsa_with_aes_128_cbc_sha256": ("AES", "SHA-256"), "tls_rsa_with_aes_256_cbc_sha256": ("AES", "SHA-256"),
    "tls_rsa_with_aes_128_gcm_sha256": ("AES", "SHA-256"), "tls_rsa_with_aes_256_gcm_sha384": ("AES", "SHA-384"),
    "ecdhe_rsa_aes_128_cbc_sha256": ("AES", "SHA-256"), "ecdhe_rsa_aes_256_cbc_sha384": ("AES", "SHA-384"),
    "ecdhe_rsa_aes_128_gcm_sha256": ("AES", "SHA-256"), "ecdhe_rsa_aes_256_gcm_sha384": ("AES", "SHA-384"),
    "ecdhe_ecdsa_aes_128_gcm_sha256": ("AES", "SHA-256"), "ecdhe_ecdsa_aes_256_gcm_sha384": ("AES", "SHA-384"),
    "ecdhe_ecdsa_aes_128_cbc_sha256": ("AES", "SHA-256"), "ecdhe_ecdsa_aes_256_cbc_sha384": ("AES", "SHA-384"),
    "tls_rsa_with_3des_ede_cbc_sha": ("3DES", "SHA-1"), "triple_des_sha_us": ("3DES", "SHA-1"), "des_sha_export": ("DES", "SHA-1"),
    "rc4_sha_us": ("RC4", "SHA-1"), "rc4_md5_us": ("RC4", "MD5"), "rc4_md5_export": ("RC4", "MD5"), "rc2_md5_export": ("RC2", "MD5"),
    "tls_rsa_with_rc4_128_sha256": ("RC4", "SHA-256"), "tls_rsa_with_null_sha256": ("NULL", "SHA-256"), "null_sha": ("NULL", "SHA-1"), "null_md5": ("NULL", "MD5"),
    "tls_rsa_with_des_cbc_sha": ("DES", "SHA-1"), "tls_rsa_with_aes_128_cbc_sha": ("AES", "SHA-1"), "tls_rsa_with_aes_256_cbc_sha": ("AES", "SHA-1"),
    "ecdhe_rsa_3des_ede_cbc_sha": ("3DES", "SHA-1"), "ecdhe_ecdsa_3des_ede_cbc_sha": ("3DES", "SHA-1"), "ecdhe_rsa_rc4_128_sha256": ("RC4", "SHA-256"), "ecdhe_ecdsa_rc4_128_sha256": ("RC4", "SHA-256"),
    "ecdhe_rsa_null_sha256": ("NULL", "SHA-256"), "ecdhe_ecdsa_null_sha256": ("NULL", "SHA-256"),
    "tls_aes_128_gcm_sha256": ("AES", "SHA-256"), "tls_aes_256_gcm_sha384": ("AES", "SHA-384"), "tls_chacha20_poly1305_sha256": ("ChaCha20-Poly1305", "SHA-256"),
    "tls_aes_128_ccm_sha256": ("AES", "SHA-256"), "tls_aes_128_ccm_8_sha256": ("AES", "SHA-256"),
    "any_tls12": ("TLS1.2", None), "any_tls12_or_higher": ("TLS1.2", None), "any_tls13": ("TLS1.3", None), "any_tls13_or_higher": ("TLS1.3", None), "any": ("TLS", None),
}
_MQ_SSLCIPH = re.compile(r"\b(?:SSLCIPH|SSLCipherSpec|sslCipherSpec|SSLCipherSuite|sslCipherSuite|CipherSpec|MQSSLCIPH)\s*(?:\(|=|:)\s*['\"]?([A-Za-z0-9_]+)['\"]?\s*\)?", re.M)
_MQ_MARKERS = re.compile(r"^\s*(?:DEFINE|ALTER)\s+CHANNEL\b[^\n]*\bSSLCIPH\b|\bSSLKEYR\s*(?:\(|=)|\bCERTLABL\s*\(|^\s*(?:SSLFIPS|SSLCAUTH|SSLPEER)\s*(?:\(|=)|^\s*\[SSL\]\s*$|^\s*(?:SSLKeyRepository|CertificateLabel|SSLKeyResetCount|OutboundSNI|SSLFipsRequired)\s*=", re.M | re.I)
_MQ_SNIPPET = re.compile(r"^\s*(?:MQCHLLIB|MQSSLKEYR|MQCERTLABL|MQCHLTAB)\s*=", re.M)
_WAS_SSL = re.compile(r"^\s*com\.ibm\.ssl\.(protocol|keyStoreType|trustStoreType|enabledCipherSuites|securityLevel|keyStore|trustStore|clientAuthentication|keyManager|trustManager)\s*=\s*([^\s#]+(?:\s*,\s*[^\s#,]+)*)", re.M)
_IBM_JSSE = re.compile(r"^\s*(com\.ibm\.jsse2\.overrideDefaultTLS|com\.ibm\.jsse2\.overrideDefaultProtocol|com\.ibm\.jsse2\.disableSSLv3|com\.ibm\.jsse2\.sp800-131|com\.ibm\.jsse2\.usefipsprovider|com\.ibm\.crypto\.provider\.fips|com\.ibm\.security\.enableCRLDP|https\.protocols|jdk\.tls\.client\.protocols|jdk\.tls\.disabledAlgorithms|jdk\.certpath\.disabledAlgorithms|jdk\.tls\.server\.protocols|jdk\.tls\.namedGroups|jdk\.tls\.ephemeralDHKeySize|crypto\.policy)\s*=\s*([^\n#]+)", re.M)
_JAVA_SECURITY_PROVIDER = re.compile(r"^\s*security\.provider\.\d+\s*=\s*([A-Za-z0-9_.$]+)(?:\s+([^\n#]+))?", re.M)
_PROVIDER_CLASS = {
    "com.ibm.crypto.provider.ibmjce": ("UNKNOWN", "IBMJCE"), "com.ibm.crypto.plus.provider.ibmjceplus": ("UNKNOWN", "IBMJCEPlus"), "com.ibm.crypto.fips.provider.ibmjcefips": ("UNKNOWN", "IBMJCEFIPS"),
    "com.ibm.crypto.hdwrcca.provider.ibmjcecca": ("UNKNOWN", "IBMJCECCA"), "com.ibm.crypto.ibmjcehybrid.provider.ibmjcehybrid": ("UNKNOWN", "IBMJCEHYBRID"), "com.ibm.jsse2.ibmjsseprovider2": ("TLS", "IBMJSSE2"),
    "com.ibm.crypto.pkcs11impl.provider.ibmpkcs11impl": ("UNKNOWN", "IBMPKCS11Impl"), "sun.security.pkcs11.sunpkcs11": ("UNKNOWN", "SunPKCS11"), "sunpkcs11": ("UNKNOWN", "SunPKCS11"),
    "org.bouncycastle.jce.provider.bouncycastleprovider": ("UNKNOWN", "BouncyCastle"), "org.bouncycastle.jcajce.provider.bouncycastlefipsprovider": ("UNKNOWN", "BC-FIPS"),
    "org.bouncycastle.jsse.provider.bouncycastlejsseprovider": ("TLS", "BCJSSE"), "com.safenetinc.luna.provider.lunaprovider": ("UNKNOWN", "HSM/Luna"), "com.ncipher.provider.km.ncipherkm": ("UNKNOWN", "HSM/nCipher"),
    "com.amazonaws.cloudhsm.jce.provider.cloudhsmprovider": ("UNKNOWN", "HSM/CloudHSM"), "com.cavium.provider.caviumprovider": ("UNKNOWN", "HSM/CloudHSM"),
    "sun.security.provider.sun": ("UNKNOWN", "SUN"), "com.sun.crypto.provider.sunjce": ("UNKNOWN", "SunJCE"), "sun.security.ssl.sunjsse": ("TLS", "SunJSSE"), "com.sun.net.ssl.internal.ssl.provider": ("TLS", "SunJSSE"),
    "sun.security.ec.sunec": ("ECDSA", "SunEC"), "sun.security.rsa.sunrsasign": ("RSA", "SunRsaSign"),
}
_WEBLOGIC = re.compile(r"^\s*-?D?(weblogic\.security\.SSL\.(?:protocolVersion|minimumProtocolVersion|ciphersuites|nojce|allowUnencryptedNullCipher|ignoreHostnameVerification|enforceConstraints|hostnameVerifier|trustedCAKeyStore)|weblogic\.security\.(?:TrustKeyStore|CustomTrustKeyStoreType|allowCryptoJDefaultJCEVerification))\s*=\s*([^\n#]+)", re.M)
_QUICKFIX = re.compile(r"^\s*(SocketUseSSL|SocketKeyStore|SocketKeyStoreType|SocketTrustStore|SocketTrustStoreType|EnabledProtocols|CipherSuites|NeedClientAuth|SSLProtocol|SSLCertificate|SSLPrivateKey|SSLValidateCertificates|SSLCertificateAuthorities|SSLCipherSuites|SSLEnabled)\s*=\s*([^\n#]+)", re.M)
_SWIFT = re.compile(r"\b(?:LAU|lau)[_.\- ]?(?:key|Key|KEY|left|right|LeftKey|RightKey|signature|Signature)\b|\bLocalAuthentication\b|\bSAG\s*LAU\b|\bswift\.lau\b|\bMQHA\b[^\n]*\bLAU\b|\bAlliance\s+(?:Access|Gateway|Lite2)\b[^\n]*\b(?:LAU|HMAC|TLS|SSL)\b", re.M)
_SWIFT_HSM = re.compile(r"\bSWIFT\b[^\n]*\b(?:HSM|3SKey|PKI|RMA|X\.?509)\b|\bswift\.hsm\b|\b3SKey\b", re.M | re.I)
_CAMEL_MULE_PROPS = re.compile(r"^\s*(?:camel\.ssl\.config\.[A-Za-z.]*(?:secure-socket-protocol|cipher-suites|key-store\.type)|mule\.tls\.[A-Za-z.]*(?:enabledProtocols|enabledCipherSuites|keyStoreType|defaultProtocol)|tls\.(?:defaultProtocol|enabledProtocols|enabledCipherSuites))\s*=\s*([^\n#]+)", re.M | re.I)
_TLS_PROTO_TOKEN = {"tlsv1.3": "TLS1.3", "tlsv1.2": "TLS1.2", "tlsv1.1": "TLS1.1", "tlsv1": "TLS1.0", "tlsv1.0": "TLS1.0", "tls": "TLS", "ssl_tlsv2": "TLS", "ssl_tls": "TLS1.0", "sslv3": "SSLv3", "ssl": "SSLv3", "sslv2hello": "SSLv2", "tls1.2": "TLS1.2", "tls1.3": "TLS1.3", "tls1.1": "TLS1.1", "tls1": "TLS1.0", "tls1.0": "TLS1.0"}


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

    for m in _PROTOCOL_KEY.finditer(text):
        for algo, tok in _tls_from_tokens(m.group(1)):
            emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", m.group(0).strip(), reason="tls-version-setting")
    for m in _TLS_MODE_KEY.finditer(text):
        emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", m.group(0).strip(), confidence="MEDIUM", reason="tls-mode-setting")
    for m in _SSE_KEY.finditer(text):
        emit(m.start(), "AES", "CIPHER_INSTANCE", "DATA_ENCRYPTION", "cloud-sse", m.group(1), confidence="MEDIUM", reason="server-side-encryption-setting", mode="GCM" if "kms" in m.group(1).lower() else None)
    for m in _SSL_POLICY_KEY.finditer(text):
        pol = m.group(1)
        algo = next((a for k, a in _ELB_TLS if k in pol), None)
        if algo is None:
            algo = _TLSV.get(pol.lower()) or "TLS"
        emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", pol, reason="tls-policy-setting")
    for m in _KEY_TYPE_KEY.finditer(text):
        v = m.group(1).upper()
        algo = "RSA" if v.startswith("RSA") else "ECDSA" if v.startswith(("EC", "ECC", "ECDSA")) else "Ed25519" if v == "ED25519" else "AES" if v in {"SYMMETRIC_DEFAULT", "OCT", "OCT-HSM", "OCT_HSM"} else "HMAC" if v.startswith("HMAC") else None
        if algo:
            emit(m.start(), algo, "KEY_PAIR_GENERATOR" if algo in {"RSA", "ECDSA", "Ed25519"} else "KEY_GENERATOR", "KEY_GENERATION", "key-config", m.group(1), confidence="MEDIUM", reason="key-type-setting")

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

    # --- PostgreSQL pg_hba.conf / MySQL auth plugins ------------------------
    for m in _PG_HBA.finditer(text):
        kind, method = m.group(1), m.group(2)
        algo = _PG_HBA_MAP.get(method)
        if algo:
            emit(m.start(), algo, "HASH" if algo in {"MD5", "SHA-256"} else "TLS", "PASSWORD_HASHING", "postgresql", method, reason="pg_hba-auth-method")
        if kind == "hostnossl":
            emit(m.start(), "TLS-DISABLED", "TLS", "NETWORK_ENCRYPTION", "postgresql", kind, reason="pg_hba-hostnossl")
        elif kind == "hostssl":
            emit(m.start(), "TLS", "TLS", "NETWORK_ENCRYPTION", "postgresql", kind, reason="pg_hba-hostssl")
    for m in _MYSQL_TLS.finditer(text):
        emit(m.start(), "TLS", "TLS", "NETWORK_ENCRYPTION", "mysql", m.group(0).strip(), reason="mysql-require-secure-transport")
    for m in _MYSQL_AUTH.finditer(text):
        algo = _MYSQL_AUTH_MAP.get(m.group(1).lower())
        if algo:
            emit(m.start(), algo, "HASH", "PASSWORD_HASHING", "mysql", m.group(1), reason="mysql-auth-plugin")

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


    # --- Bank middleware --------------------------------------------------------
    for m in _MQ_SSLCIPH.finditer(text):
        spec = m.group(1)
        low = spec.lower()
        algo, digest = _MQ_CIPHERSPEC.get(low, (None, None))
        emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ibm-mq", m.group(0).strip(), confidence="HIGH", reason="mq-cipherspec")
        if algo is None:
            if re.match(r"(?i)(?:tls|ssl)_", spec) or "_WITH_" in spec.upper():
                for a, api_type in suite_components(spec):
                    emit(m.start(), a, api_type, "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
            continue
        if algo.startswith("TLS"):
            emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
        else:
            emit(m.start(), algo, "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
        if digest:
            emit(m.start(), digest, "MESSAGE_DIGEST", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
        if low.startswith("ecdhe_ecdsa"):
            emit(m.start(), "ECDSA", "SIGNATURE", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
            emit(m.start(), "ECDHE", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
        elif low.startswith("ecdhe_rsa"):
            emit(m.start(), "RSA", "SIGNATURE", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
            emit(m.start(), "ECDHE", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
        elif low.startswith("tls_rsa"):
            emit(m.start(), "RSA", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ibm-mq", spec, reason="mq-cipherspec")
    for m in _MQ_MARKERS.finditer(text):
        raw = m.group(0).strip()
        if re.search(r"(?i)SSLKEYR|SSLKeyRepository|CertificateLabel", raw):
            emit(m.start(), "X509", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "ibm-mq", raw, confidence="MEDIUM", reason="mq-key-repository")
        else:
            emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "ibm-mq", raw, confidence="MEDIUM", reason="mq-channel-tls")
    for m in _MQ_SNIPPET.finditer(text):
        emit(m.start(), "X509", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "ibm-mq", m.group(0).strip(), confidence="LOW", reason="mq-client-env")
    for m in _WAS_SSL.finditer(text):
        key, val = m.group(1), m.group(2).strip()
        raw = m.group(0).strip()
        if key == "protocol":
            for tok in re.split(r"[,\s]+", val):
                algo = _TLS_PROTO_TOKEN.get(tok.lower())
                if algo:
                    emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "websphere-ssl", raw, reason="was-ssl-props")
        elif key in ("keyStoreType", "trustStoreType"):
            emit(m.start(), "X509", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "websphere-ssl", raw, confidence="MEDIUM", reason="was-ssl-props")
            if val.upper() in ("PKCS11", "PKCS11IMPLKS"):
                emit(m.start(), "UNKNOWN", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "websphere-ssl/PKCS#11", raw, confidence="MEDIUM", reason="was-ssl-props-hsm")
        elif key == "enabledCipherSuites":
            emit(m.start(), "TLS-CIPHERS", "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", "websphere-ssl", val, confidence="MEDIUM", reason="was-ssl-props")
            for a, api_type in suite_components(val):
                emit(m.start(), a, api_type, "NETWORK_ENCRYPTION", "websphere-ssl", val, reason="was-ssl-props")
        elif key == "securityLevel":
            emit(m.start(), "TLS-CIPHERS", "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", "websphere-ssl", raw, confidence="LOW", reason="was-security-level")
        else:
            emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "websphere-ssl", raw, confidence="MEDIUM", reason="was-ssl-props")
    for m in _IBM_JSSE.finditer(text):
        key, val = m.group(1), m.group(2).strip()
        raw = m.group(0).strip()
        lib = "ibm-jsse2" if key.startswith("com.ibm") else "java-security"
        if key.endswith(("disabledAlgorithms",)):
            emit(m.start(), "TLS-POLICY", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, raw, confidence="MEDIUM", reason="disabled-algorithms-policy (listed algorithms are blocked, not in use)")
            continue
        if key in ("com.ibm.jsse2.overrideDefaultTLS", "com.ibm.jsse2.disableSSLv3", "com.ibm.jsse2.sp800-131", "com.ibm.jsse2.usefipsprovider", "com.ibm.crypto.provider.fips", "crypto.policy", "com.ibm.security.enableCRLDP"):
            emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, raw, confidence="MEDIUM", reason="ibm-jsse2-policy")
            continue
        if key == "jdk.tls.namedGroups":
            for tok in re.split(r"[,\s]+", val):
                low = tok.lower()
                if low in {"x25519", "x448"}:
                    emit(m.start(), "X25519", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, tok, reason="named-groups")
                elif re.fullmatch(r"secp\d{3}[rk]1|brainpoolp\d{3}r1(?:tls13)?", low):
                    emit(m.start(), "ECDH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, tok, reason="named-groups")
                elif re.fullmatch(r"ffdhe\d{4}", low):
                    emit(m.start(), "DH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, tok, reason="named-groups")
                elif "mlkem" in low or "kyber" in low:
                    emit(m.start(), "ML-KEM", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, tok, reason="named-groups")
            continue
        if key == "jdk.tls.ephemeralDHKeySize":
            emit(m.start(), "DH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, raw, reason="dh-key-size")
            continue
        for tok in re.split(r"[,\s]+", val):
            algo = _TLS_PROTO_TOKEN.get(tok.lower())
            if algo:
                emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, raw, reason="jsse-protocol-property")
    for m in _JAVA_SECURITY_PROVIDER.finditer(text):
        cls = m.group(1)
        algo, lib = _PROVIDER_CLASS.get(cls.lower(), (None, None))
        if algo is None:
            continue
        emit(m.start(), algo, "KEY_PAIR_GENERATOR" if algo != "TLS" else "KEY_AGREEMENT", "KEY_MANAGEMENT" if algo != "TLS" else "NETWORK_ENCRYPTION", lib, m.group(0).strip(), confidence="MEDIUM", reason="java.security-provider-order")
    for m in _WEBLOGIC.finditer(text):
        key, val = m.group(1), m.group(2).strip()
        raw = m.group(0).strip()
        if key.endswith("ciphersuites"):
            emit(m.start(), "TLS-CIPHERS", "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", "weblogic-ssl", val, confidence="MEDIUM", reason="weblogic-ssl")
            for a, api_type in suite_components(val):
                emit(m.start(), a, api_type, "NETWORK_ENCRYPTION", "weblogic-ssl", val, reason="weblogic-ssl")
        elif key.endswith(("ignoreHostnameVerification", "allowUnencryptedNullCipher")) and val.lower().startswith("t"):
            emit(m.start(), "TLS-UNVERIFIED" if "Hostname" in key else "NULL", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "weblogic-ssl", raw, reason="weblogic-ssl-weakening")
        elif key.endswith(("protocolVersion", "minimumProtocolVersion")):
            algo = _TLS_PROTO_TOKEN.get(val.lower(), "TLS")
            emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "weblogic-ssl", raw, reason="weblogic-ssl")
        elif key.endswith(("TrustKeyStore", "CustomTrustKeyStoreType", "trustedCAKeyStore")):
            emit(m.start(), "X509", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "weblogic-ssl", raw, confidence="MEDIUM", reason="weblogic-ssl")
        else:
            emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "weblogic-ssl", raw, confidence="MEDIUM", reason="weblogic-ssl")
    if re.search(r"(?m)^\s*\[(?:DEFAULT|SESSION)\]\s*$", text) or "BeginString=FIX" in text or re.search(r"(?m)^\s*(?:SenderCompID|TargetCompID)\s*=", text):
        for m in _QUICKFIX.finditer(text):
            key, val = m.group(1), m.group(2).strip()
            raw = m.group(0).strip()
            if key in ("SocketUseSSL", "SSLEnabled"):
                if val.upper() in ("Y", "YES", "TRUE", "1"):
                    emit(m.start(), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "quickfix", raw, reason="fix-session-tls")
                else:
                    emit(m.start(), "PLAINTEXT", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "quickfix", raw, confidence="MEDIUM", reason="fix-session-without-tls")
            elif key in ("EnabledProtocols", "SSLProtocol"):
                for tok in re.split(r"[,\s]+", val):
                    algo = _TLS_PROTO_TOKEN.get(tok.lower())
                    if algo:
                        emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "quickfix", raw, reason="fix-session-tls")
            elif key in ("CipherSuites", "SSLCipherSuites"):
                emit(m.start(), "TLS-CIPHERS", "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", "quickfix", val, confidence="MEDIUM", reason="fix-session-tls")
                for a, api_type in suite_components(val):
                    emit(m.start(), a, api_type, "NETWORK_ENCRYPTION", "quickfix", val, reason="fix-session-tls")
            elif key == "SSLValidateCertificates" and val.upper() in ("N", "NO", "FALSE", "0"):
                emit(m.start(), "TLS-UNVERIFIED", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "quickfix", raw, reason="fix-session-tls-unverified")
            else:
                emit(m.start(), "X509", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "quickfix", raw, confidence="MEDIUM", reason="fix-session-keystore")
    for m in _SWIFT.finditer(text):
        emit(m.start(), "HMAC-SHA256", "MAC", "MAC_GENERATION", "swift-alliance-lau", m.group(0).strip(), confidence="MEDIUM", reason="swift-lau (HMAC-SHA-256 over the message with the left/right LAU keys)")
    for m in _SWIFT_HSM.finditer(text):
        emit(m.start(), "X509", "SIGNATURE", "SIGNING", "swift-pki", m.group(0).strip()[:80], confidence="LOW", reason="swift-pki/hsm reference")
    for m in _CAMEL_MULE_PROPS.finditer(text):
        val = m.group(1).strip()
        raw = m.group(0).strip()
        lib = "camel" if raw.lower().startswith("camel") else "mule"
        if re.search(r"(?i)cipher", raw):
            emit(m.start(), "TLS-CIPHERS", "CIPHER_INSTANCE", "NETWORK_ENCRYPTION", lib, val, confidence="MEDIUM", reason="middleware-tls")
            for a, api_type in suite_components(val):
                emit(m.start(), a, api_type, "NETWORK_ENCRYPTION", lib, val, reason="middleware-tls")
        elif re.search(r"(?i)store\.?type", raw):
            emit(m.start(), "X509", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", lib, raw, confidence="MEDIUM", reason="middleware-tls")
        else:
            for tok in re.split(r"[,\s]+", val):
                algo = _TLS_PROTO_TOKEN.get(tok.lower())
                if algo:
                    emit(m.start(), algo, "KEY_AGREEMENT", "NETWORK_ENCRYPTION", lib, raw, reason="middleware-tls")
    # --- Kerberos enctypes / Windows SCHANNEL & Kdc registry policy --------------
    for m in _KRB_ENCTYPE.finditer(text):
        for algo in _KRB_ENCTYPE_MAP.get(m.group(1).lower(), ()):
            api = "MAC" if algo == "HMAC" else "MESSAGE_DIGEST" if algo.startswith(("SHA", "MD")) else "CIPHER_INSTANCE"
            emit(m.start(), algo, api, "AUTHENTICATION", "kerberos", m.group(1), confidence="HIGH" if algo in {"RC4", "DES", "3DES", "MD5", "MD4"} else "MEDIUM", reason="kerberos-enctype")
    for m in _WIN_SCHANNEL.finditer(text):
        kind, name, _side, setting, vtype, val = m.groups()
        algo = _WIN_SCHANNEL_NAME.get(name.strip().lower())
        if not algo:
            continue
        enabled = int(val, 10 if vtype == "4" else 16) != 0  # .inf "4,<decimal>" vs .reg "dword:<hex>"
        if setting.lower() == "disabledbydefault":
            enabled = not enabled
        if not enabled:
            continue  # explicitly disabled protocol/cipher is hardening, not an in-use algorithm
        api = "KEY_AGREEMENT" if kind.lower() in {"protocols", "keyexchangealgorithms"} else "MESSAGE_DIGEST" if kind.lower() == "hashes" else "CIPHER_INSTANCE"
        emit(m.start(), algo, api, "NETWORK_ENCRYPTION", "windows-schannel", m.group(0)[:80],
             confidence="HIGH", reason="schannel-registry-policy")
    for m in _WIN_KRB_ETYPES.finditer(text):
        mask = int(m.group(2), 10 if m.group(1) == "4" else 16)
        for bit, algo in ((0x1, "DES"), (0x2, "DES"), (0x4, "RC4"), (0x8, "AES"), (0x10, "AES")):
            if mask & bit:
                emit(m.start(), algo, "CIPHER_INSTANCE", "AUTHENTICATION", "kerberos", m.group(0)[:80], confidence="HIGH", reason="kerberos-supported-etype-bitmask")
    for m in _POLICY_ALGO_KEY.finditer(text):
        algo = _POLICY_ALGO_MAP.get(m.group(1).lower())
        if not algo:
            continue
        api = "MESSAGE_DIGEST" if algo.startswith(("SHA", "MD")) else "CIPHER_INSTANCE"
        emit(m.start(), algo, api, "DATA_ENCRYPTION", "policy-config", m.group(0).strip()[:80], confidence="MEDIUM", reason="policy-algorithm-key")
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
    for m in _SIGALGS_KEY.finditer(text):
        for tok in re.split(r"[\s,:]+", m.group(1)):
            low = tok.lower()
            if not low:
                continue
            for rx, algo, api in _SIGALG_TOKEN:
                if rx.search(low):
                    emit(m.start(), algo, api, "SIGNING" if api == "SIGNATURE" else "HASHING", "tls-config", tok, reason="signature-algorithms")
    for m in _DHPARAM_KEY.finditer(text):
        emit(m.start(), "DH", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "tls-config", m.group(0).strip(),
             confidence="MEDIUM", reason="dhparam-setting")

    return findings
