"""Shell-script crypto detector: openssl / ssh-keygen / gpg / keytool / certbot CLIs,
TLS kill-switch environment variables and `curl -k` style verification bypasses.

Shell scripts are where a lot of real-world cryptography is *provisioned* (certificates,
key pairs, encrypted backups, password hashes) and where TLS verification is switched
off "temporarily". None of that shows up in application source.

Deliberately not reported: ``md5sum``/``sha256sum`` integrity checks (checksums, not
cryptographic assets — the corpus negative set enforces this), ``base64``, ``uuidgen``.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-shell-scanner-v1.0"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_SSH = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern), {**base, "library": library, **extra}


_OPENSSL_CIPHERS = {
    "aes": "AES", "aria": "ARIA", "camellia": "Camellia", "sm4": "SM4", "des-ede3": "3DES", "des3": "3DES",
    "des-ede": "3DES", "des": "DES", "bf": "Blowfish", "blowfish": "Blowfish", "rc4": "RC4", "rc2": "RC2",
    "cast5": "CAST5", "cast": "CAST5", "idea": "IDEA", "seed": "SEED", "chacha20": "ChaCha20",
}
_OPENSSL_DIGESTS = {
    "md5": "MD5", "md4": "MD4", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
    "blake2b512": "BLAKE2b", "blake2s256": "BLAKE2s", "ripemd160": "RIPEMD-160", "sm3": "SM3", "whirlpool": "WHIRLPOOL",
}
_SSH_KEY_TYPES = {"rsa": "RSA", "dsa": "DSA", "ecdsa": "ECDSA", "ed25519": "Ed25519", "ecdsa-sk": "ECDSA", "ed25519-sk": "Ed25519", "rsa1": "RSA"}
_GPG_CIPHERS = {"aes": "AES", "aes192": "AES", "aes256": "AES", "twofish": "Twofish", "camellia128": "Camellia",
                "camellia192": "Camellia", "camellia256": "Camellia", "3des": "3DES", "cast5": "CAST5", "blowfish": "Blowfish", "idea": "IDEA"}
_KEYTOOL_ALGS = {"rsa": "RSA", "dsa": "DSA", "ec": "ECDSA", "aes": "AES", "des": "DES", "desede": "3DES", "hmacsha256": "HMAC-SHA256", "hmacsha1": "HMAC-SHA1"}
_HTPASSWD = {"-m": "MD5", "-B": "BCRYPT", "-s": "SHA-1", "-d": "DES", "-2": "SHA-256", "-5": "SHA-512"}

_RULES: list[Rule] = [
    # ------------------------------------------------------------- openssl enc / dgst / genpkey / req / x509 / rand
    _r(r"\bopenssl\s+enc\b[^\n|;&]*?-(aes|aria|camellia|sm4|des-ede3|des3|des-ede|des|bf|blowfish|rc4|rc2|cast5|cast|idea|seed|chacha20)(?:-\d{3})?(?:-(?:cbc|gcm|ctr|ecb|cfb|ofb|xts|ccm))?\b",
       _C, "openssl-cli", algo_from_group=1, algo_map=_OPENSSL_CIPHERS),
    _r(r"\bopenssl\s+(?:aes|des|des3|bf|rc4|rc2|cast5|camellia|aria|sm4)(?:-\d{3})?-(?:cbc|gcm|ctr|ecb|cfb|ofb)\b", _C, "openssl-cli", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bopenssl\s+(?:pkcs8|pkcs12|genrsa|genpkey|ecparam|ec|rsa|req)\b[^\n|;&]*?(?:-v2\s+|-)(aes|aria|camellia|des3|des-ede3|des|idea|seed|rc2)(?:-?\d{3})?(?:-(?:cbc|gcm|ctr|ecb|cfb|ofb))?\b", _C, "openssl-cli", algo_from_group=1, algo_map=_OPENSSL_CIPHERS, confidence="HIGH", confidence_reason="private-key file encryption"),
    _r(r"\bopenssl\s+enc\b[^\n|;&]*?-pbkdf2\b|\bopenssl\s+kdf\b[^\n|;&]*?PBKDF2\b", _KDF, "openssl-cli", algorithm="PBKDF2"),
    _r(r"\bopenssl\s+enc\b[^\n|;&]*?-md\s+(md5|sha1|sha256|sha512)\b", _D, "openssl-cli", algo_from_group=1, algo_map=_OPENSSL_DIGESTS),
    _r(r"\bopenssl\s+(?:dgst|req|x509|ca|ts|cms|smime|pkeyutl|rsautl|dsa|ec|genpkey|crl)\b[^\n|;&]*?-(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-384|sha3-512|blake2b512|blake2s256|ripemd160|sm3|whirlpool)\b",
       _D, "openssl-cli", algo_from_group=1, algo_map=_OPENSSL_DIGESTS),
    _r(r"\bopenssl\s+(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-384|sha3-512|blake2b512|blake2s256|ripemd160|sm3|whirlpool)\b", _D, "openssl-cli", algo_from_group=1, algo_map=_OPENSSL_DIGESTS),
    _r(r"\bopenssl\s+dgst\b[^\n|;&]*?-hmac\b|\bopenssl\s+mac\b[^\n|;&]*?\bHMAC\b|\bopenssl\s+dgst\b[^\n|;&]*?-mac\s+HMAC\b", _M, "openssl-cli", algorithm="HMAC"),
    _r(r"\bopenssl\s+dgst\b[^\n|;&]*?-(?:sign|verify|prverify)\b|\bopenssl\s+pkeyutl\b[^\n|;&]*?-(?:sign|verify)\b", _S, "openssl-cli", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bopenssl\s+genrsa\b|\bopenssl\s+rsa\b|\bopenssl\s+rsautl\b|\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+RSA(?:-PSS)?\b|\bopenssl\s+req\b[^\n|;&]*?-newkey\s+rsa:\d+", _K, "openssl-cli", algorithm="RSA"),
    _r(r"\bopenssl\s+ecparam\b|\bopenssl\s+ec\b|\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+EC\b|\bopenssl\s+req\b[^\n|;&]*?-newkey\s+ec\b", _K, "openssl-cli", algorithm="ECDSA"),
    _r(r"\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+(?:ED25519|Ed25519)\b", _K, "openssl-cli", algorithm="Ed25519"),
    _r(r"\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+(?:X25519)\b", _K, "openssl-cli", algorithm="X25519"),
    _r(r"\bopenssl\s+(?:gendsa|dsaparam|dsa)\b|\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+DSA\b", _K, "openssl-cli", algorithm="DSA"),
    _r(r"\bopenssl\s+dhparam\b|\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+DH\b", _K, "openssl-cli", algorithm="DH"),
    _r(r"\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+(?:ML-KEM|mlkem)[-_]?(?:512|768|1024)\b", _K, "openssl-cli", algorithm="ML-KEM"),
    _r(r"\bopenssl\s+genpkey\b[^\n|;&]*?-algorithm\s+(?:ML-DSA|mldsa)[-_]?(?:44|65|87)\b", _K, "openssl-cli", algorithm="ML-DSA"),
    _r(r"\bopenssl\s+(?:req|x509|ca|verify|crl|pkcs12|pkcs7|pkcs8|crl2pkcs7|ocsp|storeutl)\b", _S, "openssl-cli", algorithm="X509", confidence="MEDIUM", confidence_reason="certificate / PKCS container handling"),
    _r(r"\bopenssl\s+ocsp\b", _S, "openssl-cli", algorithm="OCSP", confidence="MEDIUM"),
    _r(r"\bopenssl\s+rand\b", _RNG, "openssl-cli", algorithm="CSPRNG"),
    _r(r"\bopenssl\s+passwd\b[^\n|;&]*?-(?:1|apr1)\b", _KDF, "openssl-cli", algorithm="MD5", confidence="HIGH", confidence_reason="md5crypt password hash"),
    _r(r"\bopenssl\s+passwd\b[^\n|;&]*?-5\b", _KDF, "openssl-cli", algorithm="SHA-256", confidence="HIGH", confidence_reason="sha256crypt password hash"),
    _r(r"\bopenssl\s+passwd\b[^\n|;&]*?-6\b", _KDF, "openssl-cli", algorithm="SHA-512", confidence="HIGH", confidence_reason="sha512crypt password hash"),
    _r(r"\bopenssl\s+passwd\b(?![^\n|;&]*?-(?:1|apr1|5|6)\b)", _KDF, "openssl-cli", algorithm="DES", confidence="MEDIUM", confidence_reason="openssl passwd default is crypt(3)/DES"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-(?:tls1_3)\b", _TLS, "openssl-cli", algorithm="TLS1.3"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-(?:tls1_2)\b", _TLS, "openssl-cli", algorithm="TLS1.2"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-(?:tls1_1)\b", _TLS, "openssl-cli", algorithm="TLS1.1"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-(?:tls1)\b", _TLS, "openssl-cli", algorithm="TLS1.0"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-(?:ssl3)\b", _TLS, "openssl-cli", algorithm="SSLv3"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-(?:ssl2)\b", _TLS, "openssl-cli", algorithm="SSLv2"),
    _r(r"\bopenssl\s+s_client\b(?![^\n|;&]*?-(?:tls1_3|tls1_2|tls1_1|tls1|ssl3|ssl2)\b)|\bopenssl\s+s_server\b", _TLS, "openssl-cli", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bopenssl\s+s_client\b[^\n|;&]*?-cipher\s+['\"]?([A-Za-z0-9:!+@=_-]+)", _TLS, "openssl-cli", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"\bopenssl\s+ciphers\b", _TLS, "openssl-cli", algorithm="TLS-CIPHERS", confidence="LOW"),
    # ------------------------------------------------------------- ssh-keygen / ssh / scp
    _r(r"\bssh-keygen\b[^\n|;&]*?-t\s+(rsa1|rsa|dsa|ecdsa-sk|ecdsa|ed25519-sk|ed25519)\b", _K, "openssh", algo_from_group=1, algo_map=_SSH_KEY_TYPES),
    _r(r"\bssh-keygen\b(?![^\n|;&]*?-t\s)", _K, "openssh", algorithm="RSA", confidence="MEDIUM", confidence_reason="ssh-keygen default key type is RSA (ed25519 on OpenSSH ≥ 9.5)"),
    _r(r"\bssh-keygen\b[^\n|;&]*?-Y\s+(?:sign|verify)\b", _S, "openssh", algorithm="SSH", confidence="MEDIUM"),
    _r(r"\b(?:ssh|scp|sftp|rsync)\b[^\n]*?-o\s*['\"]?StrictHostKeyChecking[= ]no\b|\bStrictHostKeyChecking\s*[= ]\s*no\b", _SSH, "openssh", algorithm="SSH-HOSTKEY-NONE", confidence="HIGH", confidence_reason="host key verification disabled"),
    _r(r"\bUserKnownHostsFile[= ]/dev/null\b", _SSH, "openssh", algorithm="SSH-HOSTKEY-NONE", confidence="HIGH", confidence_reason="known_hosts discarded"),
    _r(r"\bssh-keyscan\b|\bssh-add\b|\bssh-agent\b", _SSH, "openssh", algorithm="SSH", confidence="LOW"),
    # ------------------------------------------------------------- gpg
    _r(r"\bgpg2?\b[^\n|;&]*?--cipher-algo\s+((?i:aes256|aes192|aes|twofish|camellia128|camellia192|camellia256|3des|cast5|blowfish|idea))\b", _C, "gnupg", algo_from_group=1, algo_map=_GPG_CIPHERS),
    _r(r"\bgpg2?\b[^\n|;&]*?--digest-algo\s+((?i:sha512|sha384|sha256|sha224|sha1|md5|ripemd160))\b", _D, "gnupg", algo_from_group=1, algo_map={**_OPENSSL_DIGESTS}),
    _r(r"\bgpg2?\b[^\n|;&]*?--s2k-digest-algo\s+((?i:sha512|sha256|sha1))\b", _KDF, "gnupg", algo_from_group=1, algo_map=_OPENSSL_DIGESTS),
    _r(r"\bgpg2?\s+(?:--symmetric|-c)\b|\bgpg2?\b[^\n|;&]*?\s--symmetric\b", _C, "gnupg", algorithm="AES", confidence="MEDIUM", confidence_reason="gpg --symmetric defaults to AES-128 (AES-256 in GnuPG 2.3+)"),
    _r(r"\bgpg2?\b[^\n|;&]*?\s(?:--encrypt|-e|--recipient|-r)\b", _C, "gnupg", algorithm="UNKNOWN", confidence="LOW", confidence_reason="public-key encryption to recipient key"),
    _r(r"\bgpg2?\b[^\n|;&]*?\s(?:--sign|--clearsign|--detach-sign|-s|-b|--verify)\b", _S, "gnupg", algorithm="UNKNOWN", confidence="LOW", confidence_reason="OpenPGP signature"),
    _r(r"\bgpg2?\b[^\n|;&]*?--(?:quick-)?gen(?:erate)?-key\b[^\n|;&]*?\b(rsa|dsa|ed25519|cv25519|nistp256|nistp384|secp256k1|brainpoolP256r1)\b", _K, "gnupg", algo_from_group=1,
       algo_map={"rsa": "RSA", "dsa": "DSA", "ed25519": "Ed25519", "cv25519": "X25519", "nistp256": "ECDSA", "nistp384": "ECDSA", "secp256k1": "ECDSA", "brainpoolP256r1": "ECDSA"}),
    # ------------------------------------------------------------- keytool (JVM keystores)
    _r(r"\bkeytool\b[^\n|;&]*?-keyalg\s+(RSA|DSA|EC|AES|DES|DESede|HmacSHA256|HmacSHA1)\b", _K, "keytool", algo_from_group=1, algo_map={k.lower(): v for k, v in _KEYTOOL_ALGS.items()}),
    _r(r"\bkeytool\b[^\n|;&]*?-sigalg\s+(SHA256|SHA384|SHA512|SHA1|MD5)with(?:RSA|ECDSA|DSA)\b", _D, "keytool", algo_from_group=1, algo_map={"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5"}),
    _r(r"\bkeytool\b[^\n|;&]*?-(?:genkeypair|genkey|importcert|import|exportcert|certreq|gencert|list|printcert|importkeystore|storepasswd|keypasswd)\b", _S, "keytool", algorithm="X509", confidence="MEDIUM", confidence_reason="JVM keystore / certificate management"),
    # ------------------------------------------------------------- certbot / acme.sh / mkcert / cfssl / step
    _r(r"\bcertbot\b(?!\.)|\bacme\.sh\b[^\n|;&]*?--(?:issue|renew(?:-all)?|install-cert|register-account|revoke|deploy|signcsr|createCSR|createDomainKey|createAccountKey)\b|\bmkcert\b|\bcfssl\s+(?:gencert|genkey|selfsign|sign)\b|\bstep\s+(?:ca|certificate)\b|\blego\s+(?:run|renew)\b|\bcertutil\b", _S, "acme-tooling", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bcertbot\b[^\n|;&]*?--key-type\s+(rsa|ecdsa)\b|\bacme\.sh\b[^\n|;&]*?--keylength\s+(ec-\d+|\d{4})", _K, "acme-tooling", algo_from_group=1, algo_map={"rsa": "RSA", "ecdsa": "ECDSA", "ec-256": "ECDSA", "ec-384": "ECDSA", "2048": "RSA", "3072": "RSA", "4096": "RSA"}),
    _r(r"\bcertbot\b[^\n|;&]*?--rsa-key-size\s+\d+", _K, "acme-tooling", algorithm="RSA"),
    # ------------------------------------------------------------- password hashing CLIs
    _r(r"\bhtpasswd\b[^\n|;&]*?\s-[bcinpDvC]*?([mBsd25])[bcinpDvC]*\b", _KDF, "apache-htpasswd", algo_from_group=1, algo_map={k.lstrip("-").lower(): v for k, v in _HTPASSWD.items()}),
    _r(r"\bhtpasswd\b(?![^\n|;&]*?\s-[bcinpDvC]*?[mBsd25])", _KDF, "apache-htpasswd", algorithm="MD5", confidence="MEDIUM", confidence_reason="htpasswd default is apr1 (MD5)"),
    _r(r"\bmkpasswd\b[^\n|;&]*?(?:-m|--method)[= ]\s*((?i:sha-?512crypt|sha-?512|sha-?256crypt|sha-?256|md5crypt|md5|bcrypt|yescrypt|des))\b", _KDF, "whois-mkpasswd", algo_from_group=1,
       algo_map={"sha-512crypt": "SHA-512", "sha512crypt": "SHA-512", "sha-512": "SHA-512", "sha512": "SHA-512", "sha-256crypt": "SHA-256", "sha256crypt": "SHA-256", "sha-256": "SHA-256", "sha256": "SHA-256", "md5crypt": "MD5", "md5": "MD5", "bcrypt": "BCRYPT", "yescrypt": "YESCRYPT", "des": "DES"}),
    _r(r"\bchpasswd\b[^\n|;&]*?(?:-c|--crypt-method)\s+(SHA512|SHA256|MD5|DES)\b", _KDF, "shadow-utils", algo_from_group=1, algo_map={"sha512": "SHA-512", "sha256": "SHA-256", "md5": "MD5", "des": "DES"}),
    _r(r"\bargon2\s+\S+[^\n|;&]*?-(?:id|i|d)\b|\becho\b[^\n|;&]*\|\s*argon2\b", _KDF, "argon2-cli", algorithm="ARGON2"),
    _r(r"\bbcrypt-cli\b|\bpython3?\s+-c\s+['\"][^'\"]*\bbcrypt\.hashpw\b", _KDF, "bcrypt-cli", algorithm="BCRYPT"),
    # ------------------------------------------------------------- modern file encryption / secrets tooling
    _r(r"\bage\s+(?:-e|--encrypt|-d|--decrypt|-r|--recipient|-p|--passphrase)\b|\bage-keygen\b", _C, "age", algorithm="ChaCha20-Poly1305", confidence="MEDIUM", confidence_reason="age uses X25519 + ChaCha20-Poly1305"),
    _r(r"\bage-keygen\b|\bage\s+(?:-r|--recipient)\s+age1", _K, "age", algorithm="X25519", confidence="MEDIUM"),
    _r(r"\bsops\s+(?:-e|--encrypt|-d|--decrypt|updatekeys|rotate)\b|\bsops\b[^\n|;&]*?--(?:kms|pgp|age|gcp-kms|azure-kv|hc-vault-transit)\b", _C, "sops", algorithm="AES", mode="GCM", confidence="MEDIUM", confidence_reason="sops data keys encrypt values with AES-256-GCM"),
    _r(r"\bvault\s+(?:transit|write\s+transit/|kv\s+put|operator\s+(?:init|unseal|rekey))\b", _C, "hashicorp-vault-cli", algorithm="AES", mode="GCM", confidence="LOW", confidence_reason="Vault barrier / transit default AES-256-GCM"),
    _r(r"\baws\s+kms\s+(?:encrypt|decrypt|generate-data-key|create-key|sign|verify|re-encrypt)\b|\bgcloud\s+kms\s+(?:encrypt|decrypt|keys)\b|\baz\s+keyvault\s+(?:key|secret|certificate)\b", _C, "cloud-kms-cli", algorithm="AES", mode="GCM", confidence="LOW", confidence_reason="cloud KMS symmetric default is AES-256-GCM"),
    _r(r"\bcryptsetup\s+(?:luksFormat|open|luksOpen|luksAddKey|reencrypt)\b", _C, "cryptsetup", algorithm="AES", mode="XTS", confidence="MEDIUM", confidence_reason="LUKS default aes-xts-plain64"),
    _r(r"\bcryptsetup\b[^\n|;&]*?(?:-c|--cipher)[= ]\s*(aes|serpent|twofish|camellia)-", _C, "cryptsetup", algo_from_group=1, algo_map={"aes": "AES", "serpent": "Serpent", "twofish": "Twofish", "camellia": "Camellia"}),
    _r(r"\b7z\s+a\b[^\n|;&]*?\s-p|\bzip\b[^\n|;&]*?\s(?:-e|--encrypt|-P)\b|\bunzip\b[^\n|;&]*?\s-P\b", _C, "archive-cli", algorithm="UNKNOWN", confidence="LOW", confidence_reason="archive password protection (ZipCrypto/AES depending on tool)"),
    _r(r"\bwg\s+genkey\b|\bwg\s+genpsk\b|\bwg-quick\b", _K, "wireguard", algorithm="X25519", confidence="MEDIUM", confidence_reason="WireGuard Curve25519 keys"),
    _r(r"\bcosign\s+(?:sign|verify|generate-key-pair|sign-blob|verify-blob)\b|\bgpg\s+--export-secret-key\b", _S, "sigstore-cosign", algorithm="ECDSA", confidence="MEDIUM", confidence_reason="cosign default ECDSA-P256"),
    _r(r"\bminisign\s+-(?:S|V|G)\b|\bsigntool\s+sign\b|\bcodesign\s+(?:-s|--sign)\b|\bjarsigner\b|\bapksigner\s+sign\b|\brpm\s+--addsign\b|\bdpkg-sig\b|\bdebsign\b", _S, "code-signing", algorithm="UNKNOWN", confidence="LOW", confidence_reason="code / package signing"),
    _r(r"\bjarsigner\b[^\n|;&]*?-(?:sigalg|digestalg)\s+(SHA256|SHA384|SHA512|SHA1|MD5)", _D, "jarsigner", algo_from_group=1, algo_map={"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5"}),
    # ------------------------------------------------------------- TLS verification kill-switches
    _r(r"\bcurl\b[^\n|]*?\s(?:-k|--insecure)\b|\bcurl\b[^\n|]*?\s-[A-Za-z]*k[A-Za-z]*\b(?=[^\n|]*\bhttps?://)", _TLS, "curl", algorithm="TLS-UNVERIFIED", confidence="HIGH", confidence_reason="curl --insecure disables certificate verification"),
    _r(r"\bwget\b[^\n|]*?--no-check-certificate\b", _TLS, "wget", algorithm="TLS-UNVERIFIED", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--(?:tlsv1\.0|tlsv1\b|tls-max\s+1\.0)|\bcurl\b[^\n|]*?\s-1\b", _TLS, "curl", algorithm="TLS1.0", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--tlsv1\.1\b", _TLS, "curl", algorithm="TLS1.1", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--tlsv1\.2\b", _TLS, "curl", algorithm="TLS1.2", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--tlsv1\.3\b", _TLS, "curl", algorithm="TLS1.3", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--(?:sslv3|ssl3)\b|\bcurl\b[^\n|]*?\s-3\b", _TLS, "curl", algorithm="SSLv3", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--(?:sslv2|ssl2)\b|\bcurl\b[^\n|]*?\s-2\b", _TLS, "curl", algorithm="SSLv2", confidence="HIGH"),
    _r(r"\bcurl\b[^\n|]*?--ciphers\s+['\"]?([A-Za-z0-9:!+@=_-]+)", _TLS, "curl", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"\bcurl\b[^\n|]*?--(?:cacert|cert|key|pinnedpubkey|cert-status)\b", _TLS, "curl", algorithm="X509", confidence="MEDIUM"),
    _r(r"\b(?:export\s+)?(?:NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY|CURL_INSECURE)\s*=\s*['\"]?0\b|\b(?:export\s+)?GIT_SSL_NO_VERIFY\s*=\s*['\"]?(?:1|true)\b|\bgit\s+config\b[^\n|;&]*?http\.sslVerify\s+['\"]?false\b|\bnpm\s+config\s+set\s+strict-ssl\s+false\b|\bpip\b[^\n|;&]*?--trusted-host\b|\bhelm\b[^\n|;&]*?--insecure-skip-tls-verify\b|\bkubectl\b[^\n|;&]*?--insecure-skip-tls-verify\b|\bdocker\b[^\n|;&]*?--tlsverify=false\b|\b(?:export\s+)?REQUESTS_CA_BUNDLE\s*=\s*['\"]?\s*['\"]?\s*$|\bgit\s+-c\s+http\.sslVerify=false\b",
       _TLS, "shell-env", algorithm="TLS-UNVERIFIED", confidence="HIGH", confidence_reason="TLS certificate verification disabled via environment / tool flag"),
    _r(r"\bsslmode=(?:disable|allow|prefer)\b|\bpsql\b[^\n|;&]*?sslmode=disable|\bmysql\b[^\n|;&]*?--ssl-mode=DISABLED\b|\bmysql\b[^\n|;&]*?--skip-ssl\b|\bredis-cli\b(?![^\n|;&]*--tls)[^\n|;&]*?-h\s", _TLS, "db-cli", algorithm="TLS-DISABLED", confidence="MEDIUM", confidence_reason="database CLI without TLS"),
    _r(r"\bmysql\b[^\n|;&]*?--ssl-mode=(?:REQUIRED|VERIFY_CA|VERIFY_IDENTITY)\b|\bpsql\b[^\n|;&]*?sslmode=(?:require|verify-ca|verify-full)|\bredis-cli\b[^\n|;&]*?--tls\b|\bmongosh?\b[^\n|;&]*?--tls\b", _TLS, "db-cli", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bstunnel\b|\bsocat\b[^\n|;&]*?\bOPENSSL(?:-LISTEN)?:", _TLS, "stunnel/socat", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bsocat\b[^\n|;&]*?\bverify=0\b", _TLS, "socat", algorithm="TLS-UNVERIFIED", confidence="HIGH"),
    _r(r"\bnmap\b[^\n|;&]*?--script\s+ssl-enum-ciphers\b|\btestssl(?:\.sh)?\b|\bsslscan\b|\bsslyze\b", _TLS, "tls-audit", algorithm="TLS-CIPHERS", confidence="LOW", confidence_reason="TLS audit tooling"),
    # ------------------------------------------------------------- randomness for secrets
    _r(r"\b(?:head|dd)\b[^\n|;&]*?/dev/(?:u)?random\b|\bcat\s+/dev/urandom\b|\b\$\(\s*openssl\s+rand\b|\bpwgen\b[^\n|;&]*?\s-s\b|\bapg\b", _RNG, "shell", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\b\w*(?:SECRET|TOKEN|PASSWORD|PASSWD|NONCE|SALT|API_KEY|KEY)\w*\s*=\s*['\"]?\$\(\s*(?:echo\s+\$RANDOM|shuf\b|awk\s+['\"]BEGIN\s*\{\s*srand)", _RNG, "shell", algorithm="PRNG", confidence="HIGH", confidence_reason="$RANDOM / shuf are not cryptographically secure"),
    _r(r"\b\w*(?:SECRET|TOKEN|PASSWORD|PASSWD|NONCE|SALT|API_KEY|KEY)\w*\s*=\s*['\"]?\$RANDOM\b|\b\w*(?:secret|token|password|passwd|nonce|salt|key)\w*=[^\n;|&]*\$RANDOM\b", _RNG, "shell", algorithm="PRNG", confidence="HIGH", confidence_reason="$RANDOM is a 15-bit LCG"),
    _r(r"\bpwgen\b(?![^\n|;&]*\s-s\b)", _RNG, "shell", algorithm="PRNG", confidence="MEDIUM", confidence_reason="pwgen without -s produces pronounceable, low-entropy passwords"),
]


# ``${ACME_OPENSSL_BIN:-openssl} genrsa``, ``"$OPENSSL" dgst``, ``$(which openssl) rand``:
# the binary is very often reached through a variable. Normalise to a bare ``openssl``
# token before the rules run (same for gpg / keytool / ssh-keygen / curl).
_TOOL_VAR = re.compile(
    r"""(?:"?\$\{?[A-Za-z0-9_]*?(OPENSSL|GPG|KEYTOOL|SSH_KEYGEN|CURL)(?:_BIN|_CMD|_PATH|_EXE|BIN|CMD)?(?::-[^}]*)?\}?"?|\$\((?:which|command\s+-v)\s+(openssl|gpg2?|keytool|ssh-keygen|curl)\)|(?:/usr(?:/local)?)?/bin/(openssl|gpg2?|keytool|ssh-keygen|curl))(?=\s)""",
    re.IGNORECASE,
)
_TOOL_NAMES = {"openssl": "openssl", "gpg": "gpg", "gpg2": "gpg", "keytool": "keytool", "ssh_keygen": "ssh-keygen", "ssh-keygen": "ssh-keygen", "curl": "curl"}


def _normalise_tool_vars(text: str) -> str:
    def repl(m: re.Match) -> str:
        name = (m.group(1) or m.group(2) or m.group(3)).lower()
        return _TOOL_NAMES.get(name, name)

    return _TOOL_VAR.sub(repl, text)


def parse_shell_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_hash_line_comments

    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=_normalise_tool_vars(strip_hash_line_comments(text)),
        rules=_RULES,
        language="SHELL",
        scanner_id=SCANNER_ID,
        confidence_reason="shell-cli-invocation",
        strip_comments=False,
    )
