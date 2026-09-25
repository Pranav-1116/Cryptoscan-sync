"""C / C++ crypto detector.

Covers the APIs that account for the overwhelming majority of native crypto
usage: OpenSSL / BoringSSL / LibreSSL (EVP and legacy low-level APIs), mbedTLS,
wolfSSL / wolfCrypt, libsodium, Crypto++, Botan, Windows CNG / CryptoAPI,
Apple CommonCrypto, Nettle / libgcrypt and the Linux kernel crypto API.

Regex-backed (no compiler needed).  Comments are stripped, single-line
``#define`` macros are inlined so macro-wrapped cipher selection is still
attributed, and identifiers are matched on word boundaries so ``md5sum_path``,
``description`` or ``crc32`` never fire.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import CIPHER_TOKENS, DIGEST_TOKENS, Rule, run_rules

SCANNER_ID = "static-c-scanner-v1.0"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_KA = {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    spec = {**base, "library": library, **extra}
    return re.compile(pattern), spec


_OSSL = "openssl"
_MBED = "mbedtls"
_WOLF = "wolfssl"
_SOD = "libsodium"
_CPP = "crypto++"
_BOTAN = "botan"
_CNG = "windows-cng"
_CAPI = "windows-cryptoapi"
_CC = "commoncrypto"
_GCRYPT = "libgcrypt"
_NETTLE = "nettle"
_KERNEL = "linux-crypto-api"

_CIPHER_TOKEN = r"(aes_\d{3}_\w+|aes_\d{3}|aria_\d{3}_\w+|camellia_\d{3}_\w+|des_ede3_\w+|des_ede_\w+|des_ede3|des_ede|des_\w+|desx_\w+|rc4_40|rc4|rc2_\w+|rc2|rc5_32_12_16_\w+|bf_\w+|cast5_\w+|idea_\w+|seed_\w+|sm4_\w+|chacha20_poly1305|chacha20)"
_DIGEST_TOKEN = r"(md2|md4|md5|sha1|sha224|sha256|sha384|sha512|sha512_256|sha3_256|sha3_384|sha3_512|blake2b512|blake2s256|ripemd160|whirlpool|sm3|mdc2)"

_RULES: list[Rule] = [
    _r(r"\bcredentialForTrust:\s*\w+(?:\.protectionSpace)?\.serverTrust\b|\bNSURLSessionAuthChallengeUseCredential\b[^;]{0,120}\bcredentialForTrust:|\ballowsAnyHTTPSCertificateForHost:|\bsetAllowsAnyHTTPSCertificate:\s*YES|\bkCFStreamSSLValidatesCertificateChain\b[^;]{0,40}kCFBooleanFalse|\bvalidatesSecureCertificate\s*=\s*NO\b|\bSecTrustSetExceptions\s*\(", _TLS, "foundation", algorithm="TLS-CERT-NONE", confidence="MEDIUM", confidence_reason="server trust accepted without evaluation"),
    _r(r"\bkSecAttrKeyType(RSA|EC|ECSECPrimeRandom|Ed25519|X25519)\b", _K, "security.framework", algo_from_group=1, algo_map={"rsa": "RSA", "ec": "ECDSA", "ecsecprimerandom": "ECDSA", "ed25519": "Ed25519", "x25519": "X25519"}),
    _r(r"\bkCCPRFHmacAlg(SHA1|SHA224|SHA256|SHA384|SHA512)\b", _M, "commoncrypto", algorithm="HMAC", emit_digest_group=1),
    # ---------------------------------------------------------------- OpenSSL EVP
    _r(rf"\bEVP_{_CIPHER_TOKEN}\s*\(", _C, _OSSL, algo_from_group=1, algo_map=CIPHER_TOKENS),
    _r(rf"\bEVP_{_DIGEST_TOKEN}\s*\(", _D, _OSSL, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bEVP_(?:CIPHER|get_cipherbyname)\s*\(\s*\"([A-Za-z0-9-]+)\"", _C, _OSSL, algo_from_group=1, algo_map=CIPHER_TOKENS, split_cipher=True),
    _r(r"\bEVP_(?:get_digestbyname|MD_fetch)\s*\([^\"]*\"([A-Za-z0-9-]+)\"", _D, _OSSL, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bEVP_CIPHER_fetch\s*\([^\"]*\"([A-Za-z0-9-]+)\"", _C, _OSSL, algo_from_group=1, algo_map=CIPHER_TOKENS, split_cipher=True),
    _r(r"\bEVP_PKEY_(?:RSA|RSA_PSS|RSA2)\b", _K, _OSSL, algorithm="RSA"),
    _r(r"\bEVP_PKEY_EC\b", _K, _OSSL, algorithm="ECDSA"),
    _r(r"\bEVP_PKEY_DSA\b", _K, _OSSL, algorithm="DSA"),
    _r(r"\bEVP_PKEY_DH\b", _KA, _OSSL, algorithm="DH"),
    _r(r"\bEVP_PKEY_ED25519\b", _S, _OSSL, algorithm="Ed25519"),
    _r(r"\bEVP_PKEY_ED448\b", _S, _OSSL, algorithm="Ed448"),
    _r(r"\bEVP_PKEY_X25519\b", _KA, _OSSL, algorithm="X25519"),
    _r(r"\bEVP_PKEY_X448\b", _KA, _OSSL, algorithm="X448"),
    _r(r"\bEVP_PKEY_HMAC\b", _M, _OSSL, algorithm="HMAC"),
    _r(r"\bEVP_PKEY_CMAC\b", _M, _OSSL, algorithm="CMAC"),
    _r(r"\bEVP_PKEY_(?:HKDF|SCRYPT)\b|\bEVP_KDF_fetch\s*\([^\"]*\"(HKDF|PBKDF2|SCRYPT|ARGON2ID|ARGON2I|ARGON2D)\"", _KDF, _OSSL, algo_from_group=1,
       algo_map={"hkdf": "HKDF", "pbkdf2": "PBKDF2", "scrypt": "SCRYPT", "argon2id": "ARGON2", "argon2i": "ARGON2", "argon2d": "ARGON2"}),
    _r(r"\bEVP_PKEY_HKDF\b", _KDF, _OSSL, algorithm="HKDF"),
    _r(r"\bEVP_PKEY_SCRYPT\b", _KDF, _OSSL, algorithm="SCRYPT"),
    _r(r"\bEVP_PKEY_keygen_init\b|\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_(RSA|EC|DSA|DH|ED25519|X25519)", _K, _OSSL, algo_from_group=1,
       algo_map={"rsa": "RSA", "ec": "ECDSA", "dsa": "DSA", "dh": "DH", "ed25519": "Ed25519", "x25519": "X25519"}),
    _r(r"\bEVP_PKEY_CTX_set_rsa_keygen_bits\s*\([^,]+,\s*(\d+)", _K, _OSSL, algorithm="RSA", key_from_group=1),
    _r(r"\bEVP_PKEY_CTX_set_ec_paramgen_curve_nid\b", _K, _OSSL, algorithm="ECDSA"),
    _r(r"\bEVP_(?:Digest)?Sign(?:Init|Update|Final)(?:_ex)?\s*\(", _S, _OSSL, algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bEVP_BytesToKey\b", _KDF, _OSSL, algorithm="EVP_BytesToKey", confidence="HIGH", confidence_reason="legacy-openssl-kdf"),
    # ---------------------------------------------------------------- OpenSSL legacy low-level
    _r(r"\bMD5(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="MD5"),
    _r(r"\bMD4(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="MD4"),
    _r(r"\bMD2(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="MD2"),
    _r(r"\bSHA1?(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="SHA-1"),
    _r(r"\bSHA224(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="SHA-224"),
    _r(r"\bSHA256(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="SHA-256"),
    _r(r"\bSHA384(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="SHA-384"),
    _r(r"\bSHA512(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="SHA-512"),
    _r(r"\bRIPEMD160(?:_Init|_Update|_Final)?\s*\(", _D, _OSSL, algorithm="RIPEMD-160"),
    _r(r"\b(?:MD5|MD4|SHA|SHA256|SHA512|RIPEMD160)_CTX\b", _D, _OSSL, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bHMAC(?:_Init(?:_ex)?|_Update|_Final|_CTX_new)?\s*\((?:[^;()]*?EVP_" + _DIGEST_TOKEN + r"\s*\(\s*\))?", _M, _OSSL, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCMAC_(?:Init|CTX_new)\b", _M, _OSSL, algorithm="CMAC"),
    _r(r"\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\s*\((?:[^;]*?EVP_" + _DIGEST_TOKEN + r"\s*\(\s*\))?", _KDF, _OSSL, algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bPKCS5_PBKDF2_HMAC_SHA1\b", _D, _OSSL, algorithm="SHA-1"),
    _r(r"\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\s*\(", _M, _OSSL, algorithm="HMAC", confidence="MEDIUM", confidence_reason="PBKDF2 PRF is HMAC"),
    _r(r"\bSSL(?:_CTX)?_set_cipher_list\s*\([^,]+,\s*\"([^\"]+)\"|\bSSL(?:_CTX)?_set_ciphersuites\s*\([^,]+,\s*\"([^\"]+)\"", _TLS, _OSSL, algorithm="TLS-CIPHERS", confidence="MEDIUM", confidence_reason="cipher-suite-list"),
    _r(r"\bs?random\s*\(\s*(?:\(\s*unsigned(?:\s+int)?\s*\)\s*)?time\s*\(|\bsrand\s*\(\s*(?:\(\s*unsigned(?:\s+int)?\s*\)\s*)?(?:time\s*\(|getpid\s*\(|clock\s*\()", _RNG, "libc", algorithm="PRNG", confidence="MEDIUM", confidence_reason="libc PRNG seeded from time/pid; not a CSPRNG"),
    _r(r"(?is)\b\w*(?:nonce|token|secret|session|salt|key|iv|otp|password)\w*\s*\([^)]*\)\s*\{[^{}]{0,200}?(?<![\w.])(?:rand|random|rand_r|lrand48|drand48)\s*\(", _RNG, "libc", algorithm="PRNG", confidence="MEDIUM", confidence_reason="libc rand() used to build key/nonce/token material"),
    _r(r"\bEVP_PBE_scrypt\b", _KDF, _OSSL, algorithm="SCRYPT"),
    _r(r"\bDES_(?:set_key\w*|ecb_encrypt|ncbc_encrypt|cbc_encrypt|cfb_encrypt|ofb_encrypt|key_sched|string_to_key|random_key|is_weak_key)\b", _C, _OSSL, algorithm="DES"),
    _r(r"\bDES_(?:ede|ecb|ncbc|cbc|cfb|ofb|cfb64|ofb64|pcbc)[23]_\w+\b", _C, _OSSL, algorithm="3DES"),
    _r(r"\bDES_(?:key_schedule|cblock)\b", _C, _OSSL, algorithm="DES", confidence="MEDIUM"),
    _r(r"\bRC4(?:_set_key)?\s*\(|\bRC4_KEY\b", _C, _OSSL, algorithm="RC4"),
    _r(r"\bRC2_(?:set_key|ecb_encrypt|cbc_encrypt|cfb64_encrypt|ofb64_encrypt)\b|\bRC2_KEY\b", _C, _OSSL, algorithm="RC2"),
    _r(r"\bBF_(?:set_key|ecb_encrypt|cbc_encrypt|cfb64_encrypt|ofb64_encrypt|encrypt|decrypt)\b|\bBF_KEY\b", _C, _OSSL, algorithm="Blowfish"),
    _r(r"\bCAST_(?:set_key|ecb_encrypt|cbc_encrypt|cfb64_encrypt|ofb64_encrypt)\b|\bCAST_KEY\b", _C, _OSSL, algorithm="CAST5"),
    _r(r"\bIDEA_(?:set_encrypt_key|set_decrypt_key|ecb_encrypt|cbc_encrypt)\b|\bIDEA_KEY_SCHEDULE\b", _C, _OSSL, algorithm="IDEA"),
    _r(r"\bAES_(?:set_encrypt_key|set_decrypt_key|encrypt|decrypt|ecb_encrypt|cbc_encrypt|cfb\d*_encrypt|ofb128_encrypt|ctr128_encrypt|wrap_key|unwrap_key)\b|\bAES_KEY\b", _C, _OSSL, algorithm="AES"),
    _r(r"\bCamellia_(?:set_key|encrypt|decrypt|ecb_encrypt|cbc_encrypt)\b", _C, _OSSL, algorithm="Camellia"),
    _r(r"\bSEED_(?:set_key|encrypt|decrypt|ecb_encrypt|cbc_encrypt)\b", _C, _OSSL, algorithm="SEED"),
    _r(r"\bChaCha20_ctr32\b|\bCRYPTO_chacha_20\b|\bCRYPTO_poly1305_\w+", _C, _OSSL, algorithm="ChaCha20"),
    _r(r"\bRSA_generate_key_ex\s*\([^,]+,\s*(\d+)", _K, _OSSL, algorithm="RSA", key_from_group=1),
    _r(r"\bRSA_generate_key\s*\(\s*(\d+)", _K, _OSSL, algorithm="RSA", key_from_group=1),
    _r(r"\bRSA_(?:new|generate_key\w*|public_encrypt|private_decrypt|private_encrypt|public_decrypt|sign|verify|sign_ASN1_OCTET_STRING|padding_add_\w+|size|set0_key)\b", _C, _OSSL, algorithm="RSA"),
    _r(r"\bRSA_PKCS1_PADDING\b", _C, _OSSL, algorithm="RSA", padding="PKCS1", confidence_reason="rsa-pkcs1v15-padding"),
    _r(r"\bRSA_NO_PADDING\b", _C, _OSSL, algorithm="RSA", padding="NoPadding"),
    _r(r"\bRSA_PKCS1_OAEP_PADDING\b", _C, _OSSL, algorithm="RSA", padding="OAEP"),
    _r(r"\bPEM_(?:read|write)(?:_bio)?_RSA(?:Private|Public|_PUB)Key\b|\bd2i_RSA(?:Private|Public)Key\b", _K, _OSSL, algorithm="RSA"),
    _r(r"\bDSA_(?:new|generate_parameters_ex|generate_key|do_sign|do_verify|sign|verify)\b", _K, _OSSL, algorithm="DSA"),
    _r(r"\bDH_(?:new|generate_parameters_ex|generate_key|compute_key|get_\d+)\b", _KA, _OSSL, algorithm="DH"),
    _r(r"\bEC_KEY_(?:new\w*|generate_key|set_group|check_key)\b|\bEC_GROUP_new_by_curve_name\b", _K, _OSSL, algorithm="ECDSA"),
    _r(r"\bECDSA_(?:do_sign\w*|do_verify|sign\w*|verify|SIG_new|size)\b", _S, _OSSL, algorithm="ECDSA"),
    _r(r"\bECDH_compute_key\b", _KA, _OSSL, algorithm="ECDH"),
    _r(r"\bNID_(?:X9_62_prime256v1|secp256k1|secp384r1|secp521r1|X25519|ED25519|brainpoolP\w+)\b", _K, _OSSL, algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bRAND_(?:bytes|priv_bytes|pseudo_bytes|seed|add|poll|status)\b", _RNG, _OSSL, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bX509_(?:new|sign|verify|verify_cert|get_pubkey|STORE_new|REQ_new|check_host)\b|\bPEM_read(?:_bio)?_X509\b", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, _OSSL, algorithm="X509", confidence="MEDIUM"),
    _r(r"\bOCSP_(?:request_new|basic_verify|response_status)\b", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, _OSSL, algorithm="OCSP", confidence="MEDIUM"),
    # ---------------------------------------------------------------- OpenSSL libssl
    _r(r"\bSSLv2_(?:client_|server_)?method\b", _TLS, _OSSL, algorithm="SSLv2"),
    _r(r"\bSSLv3_(?:client_|server_)?method\b", _TLS, _OSSL, algorithm="SSLv3"),
    _r(r"\bTLSv1_(?:client_|server_)?method\b", _TLS, _OSSL, algorithm="TLS1.0"),
    _r(r"\bTLSv1_1_(?:client_|server_)?method\b", _TLS, _OSSL, algorithm="TLS1.1"),
    _r(r"\bTLSv1_2_(?:client_|server_)?method\b", _TLS, _OSSL, algorithm="TLS1.2"),
    _r(r"\bSSLv23_(?:client_|server_)?method\b|\bTLS_(?:client_|server_)?method\b|\bDTLS\w*_method\b", _TLS, _OSSL, algorithm="TLS"),
    _r(r"\bSSL_CTX_(?:new|set_cipher_list|set_ciphersuites|set_verify|set_min_proto_version|set_max_proto_version|set_options|use_certificate\w*|use_PrivateKey\w*|load_verify_locations)\b", _TLS, _OSSL, algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bSSL_(?:new|connect|accept|read|write|set_verify|set_cipher_list)\s*\(", _TLS, _OSSL, algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bSSL_VERIFY_NONE\b", _TLS, _OSSL, algorithm="TLS-CERT-NONE", confidence_reason="certificate verification disabled"),
    _r(r"\bTLS1_VERSION\b|\bSSL_OP_NO_TLSv1_2\b", _TLS, _OSSL, algorithm="TLS1.0", confidence="MEDIUM"),
    _r(r"\bTLS1_1_VERSION\b", _TLS, _OSSL, algorithm="TLS1.1", confidence="MEDIUM"),
    _r(r"\bTLS1_2_VERSION\b", _TLS, _OSSL, algorithm="TLS1.2", confidence="MEDIUM"),
    _r(r"\bTLS1_3_VERSION\b", _TLS, _OSSL, algorithm="TLS1.3", confidence="MEDIUM"),
    _r(r"\bSSL3_VERSION\b", _TLS, _OSSL, algorithm="SSLv3", confidence="MEDIUM"),
    # ---------------------------------------------------------------- mbedTLS
    _r(r"\bmbedtls_aes_(?:init|setkey_enc|setkey_dec|crypt_\w+|xts_\w+)\b|\bmbedtls_aes_context\b", _C, _MBED, algorithm="AES"),
    _r(r"\bmbedtls_gcm_(?:init|setkey|crypt_and_tag|auth_decrypt|starts)\b", _C, _MBED, algorithm="AES", mode="GCM"),
    _r(r"\bmbedtls_ccm_(?:init|setkey|encrypt_and_tag|auth_decrypt)\b", _C, _MBED, algorithm="AES", mode="CCM"),
    _r(r"\bmbedtls_des_(?:init|setkey_\w+|crypt_\w+)\b|\bmbedtls_des_context\b", _C, _MBED, algorithm="DES"),
    _r(r"\bmbedtls_des3_(?:init|set\dkey_\w+|crypt_\w+)\b|\bmbedtls_des3_context\b", _C, _MBED, algorithm="3DES"),
    _r(r"\bmbedtls_arc4_(?:init|setup|crypt)\b|\bmbedtls_arc4_context\b", _C, _MBED, algorithm="RC4"),
    _r(r"\bmbedtls_blowfish_\w+\b", _C, _MBED, algorithm="Blowfish"),
    _r(r"\bmbedtls_camellia_\w+\b", _C, _MBED, algorithm="Camellia"),
    _r(r"\bmbedtls_aria_\w+\b", _C, _MBED, algorithm="ARIA"),
    _r(r"\bmbedtls_chachapoly_\w+\b|\bmbedtls_chacha20_\w+\b", _C, _MBED, algorithm="ChaCha20-Poly1305"),
    _r(r"\bmbedtls_cipher_info_from_type\s*\(\s*MBEDTLS_CIPHER_([A-Z0-9_]+)", _C, _MBED, algo_from_group=1, algo_map=CIPHER_TOKENS, split_cipher=True),
    _r(r"\bMBEDTLS_CIPHER_(AES_\d+_\w+|DES_\w+|DES_EDE3?_\w+|ARC4_128|BLOWFISH_\w+|CAMELLIA_\w+|CHACHA20_POLY1305|CHACHA20)\b", _C, _MBED, algo_from_group=1, algo_map=CIPHER_TOKENS, split_cipher=True),
    _r(r"\bmbedtls_md5(?:_init|_starts\w*|_update\w*|_finish\w*|_ret)?\s*\(|\bmbedtls_md5_context\b", _D, _MBED, algorithm="MD5"),
    _r(r"\bmbedtls_md4\w*\s*\(", _D, _MBED, algorithm="MD4"),
    _r(r"\bmbedtls_md2\w*\s*\(", _D, _MBED, algorithm="MD2"),
    _r(r"\bmbedtls_sha1(?:_init|_starts\w*|_update\w*|_finish\w*|_ret)?\s*\(|\bmbedtls_sha1_context\b", _D, _MBED, algorithm="SHA-1"),
    _r(r"\bmbedtls_sha256(?:_init|_starts\w*|_update\w*|_finish\w*|_ret)?\s*\(|\bmbedtls_sha256_context\b", _D, _MBED, algorithm="SHA-256"),
    _r(r"\bmbedtls_sha512(?:_init|_starts\w*|_update\w*|_finish\w*|_ret)?\s*\(|\bmbedtls_sha512_context\b", _D, _MBED, algorithm="SHA-512"),
    _r(r"\bmbedtls_sha3\w*\s*\(", _D, _MBED, algorithm="SHA3-256"),
    _r(r"\bmbedtls_ripemd160\w*\s*\(", _D, _MBED, algorithm="RIPEMD-160"),
    _r(r"\bMBEDTLS_MD_(MD2|MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|RIPEMD160|SHA3_256|SHA3_512)\b", _D, _MBED, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bmbedtls_md_hmac(?:_starts|_update|_finish|_reset)?\s*\(", _M, _MBED, algorithm="HMAC"),
    _r(r"\bmbedtls_cipher_cmac\w*\b", _M, _MBED, algorithm="CMAC"),
    _r(r"\bmbedtls_pkcs5_pbkdf2_hmac\w*\b", _KDF, _MBED, algorithm="PBKDF2"),
    _r(r"\bmbedtls_hkdf\w*\b", _KDF, _MBED, algorithm="HKDF"),
    _r(r"\bmbedtls_rsa_gen_key\s*\([^;]*?,\s*(\d{3,5})\s*,", _K, _MBED, algorithm="RSA", key_from_group=1),
    _r(r"\bmbedtls_rsa_(?:init|gen_key|pkcs1_\w+|rsaes_\w+|rsassa_\w+|public|private|import\w*)\b|\bmbedtls_rsa_context\b", _K, _MBED, algorithm="RSA"),
    _r(r"\bmbedtls_ecdsa_(?:init|genkey|sign\w*|verify\w*|write_signature\w*|read_signature\w*)\b|\bmbedtls_ecdsa_context\b", _S, _MBED, algorithm="ECDSA"),
    _r(r"\bmbedtls_ecdh_(?:init|gen_public|compute_shared|setup|make_params|make_public|calc_secret)\b|\bmbedtls_ecdh_context\b", _KA, _MBED, algorithm="ECDH"),
    _r(r"\bmbedtls_dhm_(?:init|make_params|make_public|calc_secret|read_params)\b", _KA, _MBED, algorithm="DH"),
    _r(r"\bMBEDTLS_ECP_DP_CURVE25519\b", _KA, _MBED, algorithm="X25519"),
    _r(r"\bMBEDTLS_ECP_DP_(?:SECP\w+|BP\w+)\b", _K, _MBED, algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bmbedtls_ctr_drbg_(?:init|seed|random\w*)\b|\bmbedtls_hmac_drbg_\w+\b|\bmbedtls_entropy_func\b", _RNG, _MBED, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bmbedtls_ssl_(?:setup|handshake|conf_authmode|conf_min_version|conf_max_version|conf_ciphersuites|config_defaults)\b|\bmbedtls_ssl_context\b", _TLS, _MBED, algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bMBEDTLS_SSL_VERIFY_NONE\b", _TLS, _MBED, algorithm="TLS-CERT-NONE"),
    _r(r"\bMBEDTLS_SSL_MINOR_VERSION_0\b", _TLS, _MBED, algorithm="SSLv3"),
    _r(r"\bMBEDTLS_SSL_MINOR_VERSION_1\b", _TLS, _MBED, algorithm="TLS1.0"),
    _r(r"\bMBEDTLS_SSL_MINOR_VERSION_2\b", _TLS, _MBED, algorithm="TLS1.1"),
    _r(r"\bMBEDTLS_SSL_MINOR_VERSION_3\b|\bMBEDTLS_SSL_VERSION_TLS1_2\b", _TLS, _MBED, algorithm="TLS1.2"),
    _r(r"\bMBEDTLS_SSL_VERSION_TLS1_3\b", _TLS, _MBED, algorithm="TLS1.3"),
    _r(r"\bmbedtls_x509_crt_(?:parse\w*|verify\w*|init)\b", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, _MBED, algorithm="X509", confidence="MEDIUM"),
    # ---------------------------------------------------------------- wolfSSL / wolfCrypt
    _r(r"\bwc_Aes(?:SetKey\w*|CbcEncrypt|CbcDecrypt|GcmSetKey|GcmEncrypt|GcmDecrypt|CcmEncrypt|CcmDecrypt|CtrEncrypt|EcbEncrypt|XtsEncrypt|Init)\b", _C, _WOLF, algorithm="AES"),
    _r(r"\bwc_Des_(?:SetKey|CbcEncrypt|CbcDecrypt|EcbEncrypt)\b", _C, _WOLF, algorithm="DES"),
    _r(r"\bwc_Des3_(?:SetKey|CbcEncrypt|CbcDecrypt)\b", _C, _WOLF, algorithm="3DES"),
    _r(r"\bwc_Arc4(?:SetKey|Process)\b", _C, _WOLF, algorithm="RC4"),
    _r(r"\bwc_ChaCha20Poly1305_\w+\b|\bwc_Chacha_\w+\b", _C, _WOLF, algorithm="ChaCha20-Poly1305"),
    _r(r"\bwc_Camellia\w+\b", _C, _WOLF, algorithm="Camellia"),
    _r(r"\bwc_(?:Init)?Md5(?:Hash|Update|Final|_ex)?\b", _D, _WOLF, algorithm="MD5"),
    _r(r"\bwc_(?:Init)?Md4\w*\b", _D, _WOLF, algorithm="MD4"),
    _r(r"\bwc_(?:Init)?Sha(?:Hash|Update|Final|_ex)?\b", _D, _WOLF, algorithm="SHA-1"),
    _r(r"\bwc_(?:Init)?Sha224\w*\b", _D, _WOLF, algorithm="SHA-224"),
    _r(r"\bwc_(?:Init)?Sha256\w*\b", _D, _WOLF, algorithm="SHA-256"),
    _r(r"\bwc_(?:Init)?Sha384\w*\b", _D, _WOLF, algorithm="SHA-384"),
    _r(r"\bwc_(?:Init)?Sha512\w*\b", _D, _WOLF, algorithm="SHA-512"),
    _r(r"\bwc_(?:Init)?Sha3_\w+\b", _D, _WOLF, algorithm="SHA3-256"),
    _r(r"\bwc_(?:Init)?Blake2b\w*\b", _D, _WOLF, algorithm="BLAKE2b"),
    _r(r"\bwc_Hmac(?:SetKey|Update|Final|Init)\b", _M, _WOLF, algorithm="HMAC"),
    _r(r"\bwc_(?:Init)?Cmac\w*\b|\bwc_AesCmac\w*\b", _M, _WOLF, algorithm="CMAC"),
    _r(r"\bwc_PBKDF2\b|\bwc_PBKDF1\b", _KDF, _WOLF, algorithm="PBKDF2"),
    _r(r"\bwc_scrypt\b", _KDF, _WOLF, algorithm="SCRYPT"),
    _r(r"\bwc_HKDF\w*\b", _KDF, _WOLF, algorithm="HKDF"),
    _r(r"\bwc_MakeRsaKey\s*\([^,]+,\s*(\d+)", _K, _WOLF, algorithm="RSA", key_from_group=1),
    _r(r"\bwc_(?:InitRsaKey|MakeRsaKey|Rsa\w+)\b", _K, _WOLF, algorithm="RSA"),
    _r(r"\bwc_ecc_(?:make_key\w*|sign_hash\w*|verify_hash\w*|init|import\w*)\b", _S, _WOLF, algorithm="ECDSA"),
    _r(r"\bwc_ecc_shared_secret\w*\b", _KA, _WOLF, algorithm="ECDH"),
    _r(r"\bwc_ed25519_\w+\b", _S, _WOLF, algorithm="Ed25519"),
    _r(r"\bwc_curve25519_\w+\b", _KA, _WOLF, algorithm="X25519"),
    _r(r"\bwc_Dsa\w+\b|\bwc_(?:Init|Make)DsaKey\b", _K, _WOLF, algorithm="DSA"),
    _r(r"\bwc_Dh\w+\b", _KA, _WOLF, algorithm="DH"),
    _r(r"\bwc_RNG_GenerateBlock\b|\bwc_InitRng\b", _RNG, _WOLF, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bwolf(?:SSLv23|TLSv1_[0-3]|TLS)_(?:client_|server_)?method\b|\bwolfSSL_CTX_new\b", _TLS, _WOLF, algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bwolfSSLv3_(?:client_|server_)?method\b", _TLS, _WOLF, algorithm="SSLv3"),
    _r(r"\bwolfTLSv1_(?:client_|server_)?method\b", _TLS, _WOLF, algorithm="TLS1.0"),
    _r(r"\bwolfTLSv1_1_(?:client_|server_)?method\b", _TLS, _WOLF, algorithm="TLS1.1"),
    _r(r"\bWOLFSSL_VERIFY_NONE\b", _TLS, _WOLF, algorithm="TLS-CERT-NONE"),
    # ---------------------------------------------------------------- libsodium / NaCl
    _r(r"\bcrypto_secretbox(?:_xsalsa20poly1305)?(?:_easy|_open_easy|_detached|_open_detached|_keygen)?\s*\(", _C, _SOD, algorithm="XSalsa20-Poly1305"),
    _r(r"\bcrypto_box(?:_curve25519xsalsa20poly1305)?(?:_easy|_open_easy|_keypair|_seal|_seal_open|_detached|_beforenm)?\s*\(", _C, _SOD, algorithm="X25519"),
    _r(r"\bcrypto_box(?:_curve25519xsalsa20poly1305)?(?:_easy|_open_easy|_seal|_seal_open|_detached)\s*\(", _C, _SOD, algorithm="XSalsa20-Poly1305"),
    _r(r"\bcrypto_sign(?:_ed25519)?(?:_keypair|_seed_keypair|_detached|_verify_detached|_open|_init|_update|_final_create)?\s*\(", _S, _SOD, algorithm="Ed25519"),
    _r(r"\bcrypto_aead_chacha20poly1305(?:_ietf)?_\w+\b", _C, _SOD, algorithm="ChaCha20-Poly1305"),
    _r(r"\bcrypto_aead_xchacha20poly1305_ietf_\w+\b", _C, _SOD, algorithm="XChaCha20-Poly1305"),
    _r(r"\bcrypto_aead_aes256gcm_\w+\b|\bcrypto_aead_aegis\w+", _C, _SOD, algorithm="AES", mode="GCM"),
    _r(r"\bcrypto_stream_(?:xsalsa20|salsa20|salsa2012|salsa208)\w*\b", _C, _SOD, algorithm="XSalsa20"),
    _r(r"\bcrypto_stream_(?:chacha20|xchacha20)\w*\b", _C, _SOD, algorithm="ChaCha20"),
    _r(r"\bcrypto_pwhash(?:_str|_str_verify|_argon2id\w*|_argon2i\w*|_ALG_ARGON2\w*)?\s*[\(]", _KDF, _SOD, algorithm="ARGON2"),
    _r(r"\bcrypto_pwhash_scryptsalsa208sha256\w*\b", _KDF, _SOD, algorithm="SCRYPT"),
    _r(r"\bcrypto_kdf_(?:derive_from_key|keygen|hkdf_\w+)\b", _KDF, _SOD, algorithm="HKDF", confidence="MEDIUM"),
    _r(r"\bcrypto_auth(?:_hmacsha512256|_hmacsha256|_hmacsha512)?(?:_verify|_keygen)?\s*\(", _M, _SOD, algorithm="HMAC"),
    _r(r"\bcrypto_onetimeauth\w*\s*\(", _M, _SOD, algorithm="Poly1305"),
    _r(r"\bcrypto_generichash\w*\s*\(", _D, _SOD, algorithm="BLAKE2b"),
    _r(r"\bcrypto_hash_sha256\w*\s*\(", _D, _SOD, algorithm="SHA-256"),
    _r(r"\bcrypto_hash_sha512\w*\s*\(", _D, _SOD, algorithm="SHA-512"),
    _r(r"\bcrypto_shorthash\w*\s*\(", _D, _SOD, algorithm="SipHash", confidence="MEDIUM"),
    _r(r"\bcrypto_scalarmult(?:_curve25519)?(?:_base)?\s*\(", _KA, _SOD, algorithm="X25519"),
    _r(r"\bcrypto_kx_\w+\s*\(", _KA, _SOD, algorithm="X25519"),
    _r(r"\brandombytes_(?:buf|random|uniform|buf_deterministic)\b", _RNG, _SOD, algorithm="CSPRNG", confidence="MEDIUM"),
    # ---------------------------------------------------------------- Crypto++
    _r(r"\bCryptoPP::(?:AES|Rijndael)\b", _C, _CPP, algorithm="AES"),
    _r(r"\bCryptoPP::DES_EDE[23]\b", _C, _CPP, algorithm="3DES"),
    _r(r"\bCryptoPP::DES\b", _C, _CPP, algorithm="DES"),
    _r(r"\bCryptoPP::(?:ARC4|Weak::ARC4|Weak1::ARC4|MARC4)\b", _C, _CPP, algorithm="RC4"),
    _r(r"\bCryptoPP::RC2\b", _C, _CPP, algorithm="RC2"),
    _r(r"\bCryptoPP::Blowfish\b", _C, _CPP, algorithm="Blowfish"),
    _r(r"\bCryptoPP::CAST128\b", _C, _CPP, algorithm="CAST5"),
    _r(r"\bCryptoPP::IDEA\b", _C, _CPP, algorithm="IDEA"),
    _r(r"\bCryptoPP::Twofish\b", _C, _CPP, algorithm="Twofish"),
    _r(r"\bCryptoPP::Serpent\b", _C, _CPP, algorithm="Serpent"),
    _r(r"\bCryptoPP::Camellia\b", _C, _CPP, algorithm="Camellia"),
    _r(r"\bCryptoPP::(?:ChaCha20Poly1305|ChaCha|XChaCha20Poly1305|ChaChaTLS)\b", _C, _CPP, algorithm="ChaCha20-Poly1305"),
    _r(r"\bCryptoPP::(?:Salsa20|XSalsa20)\b", _C, _CPP, algorithm="Salsa20"),
    _r(r"\bCryptoPP::(?:Weak::|Weak1::)?MD5\b", _D, _CPP, algorithm="MD5"),
    _r(r"\bCryptoPP::(?:Weak::|Weak1::)?MD4\b", _D, _CPP, algorithm="MD4"),
    _r(r"\bCryptoPP::(?:Weak::|Weak1::)?MD2\b", _D, _CPP, algorithm="MD2"),
    _r(r"\bCryptoPP::SHA1?\b", _D, _CPP, algorithm="SHA-1"),
    _r(r"\bCryptoPP::SHA224\b", _D, _CPP, algorithm="SHA-224"),
    _r(r"\bCryptoPP::SHA256\b", _D, _CPP, algorithm="SHA-256"),
    _r(r"\bCryptoPP::SHA384\b", _D, _CPP, algorithm="SHA-384"),
    _r(r"\bCryptoPP::SHA512\b", _D, _CPP, algorithm="SHA-512"),
    _r(r"\bCryptoPP::SHA3_(?:224|256|384|512)\b|\bCryptoPP::Keccak_\d+\b", _D, _CPP, algorithm="SHA3-256"),
    _r(r"\bCryptoPP::BLAKE2[bs]\b", _D, _CPP, algorithm="BLAKE2b"),
    _r(r"\bCryptoPP::RIPEMD\d+\b", _D, _CPP, algorithm="RIPEMD-160"),
    _r(r"\bCryptoPP::Whirlpool\b", _D, _CPP, algorithm="WHIRLPOOL"),
    _r(r"\bCryptoPP::HMAC\s*<\s*(?:CryptoPP::)?(\w+)\s*>", _M, _CPP, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCryptoPP::CMAC\s*<", _M, _CPP, algorithm="CMAC"),
    _r(r"\bCryptoPP::PKCS5_PBKDF2_HMAC\s*<\s*(?:CryptoPP::)?(\w+)\s*>", _KDF, _CPP, algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bCryptoPP::Scrypt\b", _KDF, _CPP, algorithm="SCRYPT"),
    _r(r"\bCryptoPP::HKDF\s*<", _KDF, _CPP, algorithm="HKDF"),
    _r(r"\bCryptoPP::(?:RSA(?:ES|SS)?|RSAFunction|InvertibleRSAFunction)\b", _K, _CPP, algorithm="RSA"),
    _r(r"\bCryptoPP::(?:ECDSA|ECDSA_RFC6979)\s*<", _S, _CPP, algorithm="ECDSA"),
    _r(r"\bCryptoPP::ECDH\s*<", _KA, _CPP, algorithm="ECDH"),
    _r(r"\bCryptoPP::(?:ed25519|ed25519Signer|ed25519Verifier)\b", _S, _CPP, algorithm="Ed25519"),
    _r(r"\bCryptoPP::x25519\b", _KA, _CPP, algorithm="X25519"),
    _r(r"\bCryptoPP::DSA2?\b", _K, _CPP, algorithm="DSA"),
    _r(r"\bCryptoPP::DH2?\b", _KA, _CPP, algorithm="DH"),
    _r(r"\bCryptoPP::(?:AutoSeededRandomPool|AutoSeededX917RNG|OS_GenerateRandomBlock|NonblockingRng)\b", _RNG, _CPP, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bCryptoPP::(?:LC_RNG|RandomPool)\b", _RNG, _CPP, algorithm="PRNG", confidence="MEDIUM"),
    # ---------------------------------------------------------------- Botan
    _r(r"\bBotan::(?:Cipher_Mode|BlockCipher|StreamCipher|AEAD_Mode)::create\w*\s*\(\s*\"([A-Za-z0-9/-]+)", _C, _BOTAN, algo_from_group=1, algo_map=CIPHER_TOKENS, split_cipher=True),
    _r(r"\bBotan::HashFunction::create\w*\s*\(\s*\"([A-Za-z0-9-]+)", _D, _BOTAN, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bBotan::MessageAuthenticationCode::create\w*\s*\(\s*\"HMAC\(([A-Za-z0-9-]+)\)", _M, _BOTAN, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bBotan::(?:RSA_PrivateKey|RSA_PublicKey)\b", _K, _BOTAN, algorithm="RSA"),
    _r(r"\bBotan::(?:ECDSA_PrivateKey|ECDSA_PublicKey)\b", _S, _BOTAN, algorithm="ECDSA"),
    _r(r"\bBotan::(?:ECDH_PrivateKey|ECDH_PublicKey)\b", _KA, _BOTAN, algorithm="ECDH"),
    _r(r"\bBotan::(?:Ed25519_PrivateKey|Ed25519_PublicKey)\b", _S, _BOTAN, algorithm="Ed25519"),
    _r(r"\bBotan::(?:X25519_PrivateKey|Curve25519_PrivateKey)\b", _KA, _BOTAN, algorithm="X25519"),
    _r(r"\bBotan::(?:DSA_PrivateKey|DSA_PublicKey)\b", _K, _BOTAN, algorithm="DSA"),
    _r(r"\bBotan::(?:DH_PrivateKey|DH_PublicKey)\b", _KA, _BOTAN, algorithm="DH"),
    _r(r"\bBotan::(?:PBKDF|PasswordHashFamily)::create\w*\s*\(\s*\"(PBKDF2|Scrypt|Argon2id|Argon2i|Argon2d|Bcrypt)", _KDF, _BOTAN, algo_from_group=1,
       algo_map={"pbkdf2": "PBKDF2", "scrypt": "SCRYPT", "argon2id": "ARGON2", "argon2i": "ARGON2", "argon2d": "ARGON2", "bcrypt": "BCRYPT"}),
    _r(r"\bBotan::(?:argon2\w*|generate_bcrypt|check_bcrypt)\s*\(", _KDF, _BOTAN, algorithm="ARGON2"),
    _r(r"\bBotan::(?:AutoSeeded_RNG|System_RNG|HMAC_DRBG|ChaCha_RNG)\b", _RNG, _BOTAN, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bBotan::TLS::(?:Client|Server|Policy|Context)\b", _TLS, _BOTAN, algorithm="TLS", confidence="MEDIUM"),
    # ---------------------------------------------------------------- Windows CNG / CryptoAPI
    _r(r"\bBCRYPT_(AES|DES|3DES|3DES_112|DESX|RC2|RC4|AES_GMAC|AES_CMAC)_ALGORITHM\b", _C, _CNG, algo_from_group=1,
       algo_map={"aes": "AES", "des": "DES", "3des": "3DES", "3des_112": "3DES", "desx": "DES", "rc2": "RC2", "rc4": "RC4", "aes_gmac": "GMAC", "aes_cmac": "CMAC"}),
    _r(r"\bBCRYPT_(MD2|MD4|MD5|SHA1|SHA256|SHA384|SHA512)_ALGORITHM\b", _D, _CNG, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bBCRYPT_(RSA|RSA_SIGN)_ALGORITHM\b", _K, _CNG, algorithm="RSA"),
    _r(r"\bBCRYPT_(?:DSA)_ALGORITHM\b", _K, _CNG, algorithm="DSA"),
    _r(r"\bBCRYPT_(?:DH)_ALGORITHM\b", _KA, _CNG, algorithm="DH"),
    _r(r"\bBCRYPT_ECDSA(?:_P256|_P384|_P521)?_ALGORITHM\b", _S, _CNG, algorithm="ECDSA"),
    _r(r"\bBCRYPT_ECDH(?:_P256|_P384|_P521)?_ALGORITHM\b", _KA, _CNG, algorithm="ECDH"),
    _r(r"\bBCRYPT_RNG_(?:ALGORITHM|FIPS186_DSA_ALGORITHM|DUAL_EC_ALGORITHM)\b|\bBCryptGenRandom\b", _RNG, _CNG, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bBCRYPT_PBKDF2_ALGORITHM\b|\bBCryptDeriveKeyPBKDF2\b", _KDF, _CNG, algorithm="PBKDF2"),
    _r(r"\bBCRYPT_CHAIN_MODE_(CBC|ECB|CFB|CCM|GCM)\b", _C, _CNG, algorithm="AES", confidence="LOW"),
    _r(r"\bBCryptOpenAlgorithmProvider\s*\([^,]+,\s*L?\"(AES|DES|3DES|RC2|RC4|MD5|SHA1|SHA256|SHA384|SHA512|RSA|ECDSA_P256|ECDH_P256|DSA|DH)\"", _C, _CNG, algo_from_group=1,
       algo_map={"aes": "AES", "des": "DES", "3des": "3DES", "rc2": "RC2", "rc4": "RC4", "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "rsa": "RSA", "ecdsa_p256": "ECDSA", "ecdh_p256": "ECDH", "dsa": "DSA", "dh": "DH"}),
    _r(r"\bCALG_(MD2|MD4|MD5|SHA1|SHA_1|SHA|SHA_256|SHA_384|SHA_512)\b", _D, _CAPI, algo_from_group=1,
       algo_map={"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha1": "SHA-1", "sha_1": "SHA-1", "sha": "SHA-1", "sha_256": "SHA-256", "sha_384": "SHA-384", "sha_512": "SHA-512"}),
    _r(r"\bCALG_(AES|AES_128|AES_192|AES_256|DES|3DES|3DES_112|DESX|RC2|RC4|RC5)\b", _C, _CAPI, algo_from_group=1,
       algo_map={"aes": "AES", "aes_128": "AES", "aes_192": "AES", "aes_256": "AES", "des": "DES", "3des": "3DES", "3des_112": "3DES", "desx": "DES", "rc2": "RC2", "rc4": "RC4", "rc5": "RC5"}),
    _r(r"\bCALG_(?:RSA_SIGN|RSA_KEYX)\b|\bAT_KEYEXCHANGE\b|\bAT_SIGNATURE\b", _K, _CAPI, algorithm="RSA", confidence="MEDIUM"),
    _r(r"\bCALG_(?:DSS_SIGN)\b", _K, _CAPI, algorithm="DSA"),
    _r(r"\bCALG_(?:DH_SF|DH_EPHEM)\b", _KA, _CAPI, algorithm="DH"),
    _r(r"\bCALG_HMAC\b|\bCALG_MAC\b", _M, _CAPI, algorithm="HMAC"),
    _r(r"\bCryptGenRandom\b|\bRtlGenRandom\b|\bSystemFunction036\b", _RNG, _CAPI, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bCryptDeriveKey\b", _KDF, _CAPI, algorithm="CryptDeriveKey", confidence="MEDIUM"),
    _r(r"\bSCH_CRED_\w+\b|\bSP_PROT_(TLS1\w*|SSL3\w*|SSL2\w*)\b|\bSCHANNEL_CRED\b", _TLS, "schannel", algorithm="TLS", confidence="MEDIUM"),
    # ---------------------------------------------------------------- Apple CommonCrypto
    _r(r"\bCC_MD5(?:_Init|_Update|_Final)?\s*\(", _D, _CC, algorithm="MD5"),
    _r(r"\bCC_MD4\w*\s*\(|\bCC_MD2\w*\s*\(", _D, _CC, algorithm="MD4"),
    _r(r"\bCC_SHA1(?:_Init|_Update|_Final)?\s*\(", _D, _CC, algorithm="SHA-1"),
    _r(r"\bCC_SHA224\w*\s*\(", _D, _CC, algorithm="SHA-224"),
    _r(r"\bCC_SHA256(?:_Init|_Update|_Final)?\s*\(", _D, _CC, algorithm="SHA-256"),
    _r(r"\bCC_SHA384\w*\s*\(", _D, _CC, algorithm="SHA-384"),
    _r(r"\bCC_SHA512(?:_Init|_Update|_Final)?\s*\(", _D, _CC, algorithm="SHA-512"),
    _r(r"\bkCCAlgorithmAES(?:128)?\b", _C, _CC, algorithm="AES"),
    _r(r"\bkCCAlgorithmDES\b", _C, _CC, algorithm="DES"),
    _r(r"\bkCCAlgorithm3DES\b", _C, _CC, algorithm="3DES"),
    _r(r"\bkCCAlgorithmRC4\b", _C, _CC, algorithm="RC4"),
    _r(r"\bkCCAlgorithmRC2\b", _C, _CC, algorithm="RC2"),
    _r(r"\bkCCAlgorithmCAST\b", _C, _CC, algorithm="CAST5"),
    _r(r"\bkCCAlgorithmBlowfish\b", _C, _CC, algorithm="Blowfish"),
    _r(r"\bkCCHmacAlg(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\b", _M, _CC, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCCHmac(?:Init|Update|Final)?\s*\(", _M, _CC, algorithm="HMAC"),
    _r(r"\bCCKeyDerivationPBKDF\b|\bkCCPBKDF2\b", _KDF, _CC, algorithm="PBKDF2"),
    _r(r"\bkCCPRFHmacAlg(SHA1|SHA224|SHA256|SHA384|SHA512)\b", _KDF, _CC, algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bCCRandomGenerateBytes\b|\bSecRandomCopyBytes\b|\bCCRandomCopyBytes\b", _RNG, _CC, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bkSecAttrKeyTypeRSA\b|\bSecKeyCreateRandomKey\b", _K, "security-framework", algorithm="RSA", confidence="MEDIUM"),
    _r(r"\bkSecAttrKeyTypeEC(?:SECPrimeRandom)?\b", _K, "security-framework", algorithm="ECDSA"),
    # ---------------------------------------------------------------- libgcrypt
    _r(r"\bGCRY_CIPHER_(AES|AES128|AES192|AES256|RIJNDAEL\d*|DES|3DES|BLOWFISH|CAST5|ARCFOUR|IDEA|TWOFISH|TWOFISH128|SERPENT\d*|RFC2268_40|RFC2268_128|SEED|CAMELLIA\d*|SALSA20|SALSA20R12|CHACHA20|SM4)\b", _C, _GCRYPT, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "rijndael192": "AES", "rijndael256": "AES", "rfc2268_40": "RC2", "rfc2268_128": "RC2", "twofish128": "Twofish", "serpent128": "Serpent", "serpent192": "Serpent", "serpent256": "Serpent", "salsa20r12": "Salsa20", "camellia192": "Camellia"}),
    _r(r"\bGCRY_MD_(MD2|MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_512|RMD160|WHIRLPOOL|BLAKE2B_512|BLAKE2S_256|SM3|TIGER)\b", _D, _GCRYPT, algo_from_group=1,
       algo_map={**DIGEST_TOKENS, "rmd160": "RIPEMD-160", "blake2b_512": "BLAKE2b", "blake2s_256": "BLAKE2s", "sm3": "SM3", "tiger": "TIGER"}),
    _r(r"\bGCRY_MAC_HMAC_\w+\b|\bgcry_mac_open\b", _M, _GCRYPT, algorithm="HMAC"),
    _r(r"\bGCRY_MAC_CMAC_\w+\b", _M, _GCRYPT, algorithm="CMAC"),
    _r(r"\bGCRY_KDF_PBKDF2\b", _KDF, _GCRYPT, algorithm="PBKDF2"),
    _r(r"\bGCRY_KDF_SCRYPT\b", _KDF, _GCRYPT, algorithm="SCRYPT"),
    _r(r"\bGCRY_KDF_ARGON2\w*\b", _KDF, _GCRYPT, algorithm="ARGON2"),
    _r(r"\bGCRY_PK_RSA\b|\"\(genkey\s*\(rsa\b", _K, _GCRYPT, algorithm="RSA"),
    _r(r"\bGCRY_PK_DSA\b", _K, _GCRYPT, algorithm="DSA"),
    _r(r"\bGCRY_PK_ELG\w*\b", _K, _GCRYPT, algorithm="ElGamal"),
    _r(r"\bGCRY_PK_(?:ECDSA|ECC)\b|\"\(genkey\s*\(ecc\b|\(ecdsa\b", _S, _GCRYPT, algorithm="ECDSA"),
    _r(r"\bGCRY_PK_ECDH\b", _KA, _GCRYPT, algorithm="ECDH"),
    _r(r"\bGCRY_PK_EDDSA\b|\(eddsa\b", _S, _GCRYPT, algorithm="Ed25519"),
    _r(r"\bgcry_randomize\b|\bgcry_create_nonce\b|\bGCRY_STRONG_RANDOM\b|\bGCRY_VERY_STRONG_RANDOM\b", _RNG, _GCRYPT, algorithm="CSPRNG", confidence="MEDIUM"),
    # ---------------------------------------------------------------- Nettle
    _r(r"\bnettle_(md5|md4|md2|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|ripemd160)_(?:init|update|digest)\b|\b(md5|md4|sha1|sha256|sha512)_(?:init|update|digest)\s*\(\s*&", _D, _NETTLE, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bnettle_(aes\d*|des|des3|arcfour|arctwo|blowfish|cast128|camellia\d*|serpent|twofish|chacha|salsa20|chacha_poly1305)_(?:set_encrypt_key|set_decrypt_key|set_key|encrypt|decrypt|crypt)\b", _C, _NETTLE, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "arctwo": "RC2", "cast128": "CAST5", "chacha": "ChaCha20", "chacha_poly1305": "ChaCha20-Poly1305"}),
    _r(r"\b(aes\d*|des3|des|arcfour|blowfish|cast128|twofish|serpent)_(?:set_encrypt_key|set_decrypt_key|set_key|encrypt|decrypt)\s*\(\s*&", _C, _NETTLE, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "cast128": "CAST5"}, confidence="MEDIUM"),
    _r(r"\bnettle_(?:hmac_\w+|hmac_set_key|hmac_update|hmac_digest)\b|\bhmac_(md5|sha1|sha256|sha512)_(?:set_key|update|digest)\b", _M, _NETTLE, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bnettle_pbkdf2\w*\b|\bpbkdf2_hmac_(sha1|sha256|sha384|sha512)\b", _KDF, _NETTLE, algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bnettle_rsa_\w+\b|\brsa_(?:generate_keypair|encrypt|decrypt|sha1_sign\w*|sha256_sign\w*|pkcs1_sign\w*|pss_sha256_sign\w*)\b", _K, _NETTLE, algorithm="RSA", confidence="MEDIUM"),
    _r(r"\bnettle_ecdsa_\w+\b|\becdsa_(?:generate_keypair|sign|verify)\b", _S, _NETTLE, algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bnettle_ed25519_\w+\b|\bed25519_sha512_(?:sign|verify|public_key)\b", _S, _NETTLE, algorithm="Ed25519"),
    _r(r"\bnettle_curve25519_\w+\b|\bcurve25519_mul(?:_g)?\b", _KA, _NETTLE, algorithm="X25519"),
    _r(r"\bnettle_dsa_\w+\b|\bdsa_(?:generate_keypair|sign|verify)\b", _K, _NETTLE, algorithm="DSA", confidence="MEDIUM"),
    _r(r"\byarrow256_\w+\b|\bnettle_yarrow\w*\b", _RNG, _NETTLE, algorithm="CSPRNG", confidence="MEDIUM"),
    # ---------------------------------------------------------------- Linux kernel crypto API
    _r(r"\bcrypto_alloc_(?:shash|ahash)\s*\(\s*\"(md4|md5|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-512|blake2b-512|blake2s-256|rmd160|crc32c?|xxhash64|hmac\([a-z0-9-]+\))\"", _D, _KERNEL, algo_from_group=1,
       algo_map={**DIGEST_TOKENS, "rmd160": "RIPEMD-160"}),
    _r(r"\bcrypto_alloc_(?:shash|ahash)\s*\(\s*\"hmac\(([a-z0-9-]+)\)\"", _M, _KERNEL, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bcrypto_alloc_(?:skcipher|sync_skcipher|cipher|blkcipher|ablkcipher)\s*\(\s*\"(?:(?:cbc|ecb|ctr|xts|cfb|ofb|lrw|cts|essiv)\()?([a-z0-9]+)", _C, _KERNEL, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "des3_ede": "3DES", "arc4": "RC4", "twofish": "Twofish", "serpent": "Serpent", "cast6": "CAST6", "anubis": "Anubis"}),
    _r(r"\bcrypto_alloc_aead\s*\(\s*\"(?:gcm|ccm|rfc4106|rfc4543)\((aes|sm4)\)\"", _C, _KERNEL, algo_from_group=1, algo_map=CIPHER_TOKENS),
    _r(r"\bcrypto_alloc_aead\s*\(\s*\"(?:rfc7539|rfc7539esp)\(chacha20,poly1305\)\"", _C, _KERNEL, algorithm="ChaCha20-Poly1305"),
    _r(r"\bcrypto_alloc_akcipher\s*\(\s*\"(?:pkcs1pad\()?rsa\b", _K, _KERNEL, algorithm="RSA"),
    _r(r"\bcrypto_alloc_kpp\s*\(\s*\"(ecdh|dh|curve25519|ecdh-nist-p256)\"", _KA, _KERNEL, algo_from_group=1,
       algo_map={"ecdh": "ECDH", "dh": "DH", "curve25519": "X25519", "ecdh-nist-p256": "ECDH"}),
    _r(r"\bget_random_bytes\b|\bcrypto_alloc_rng\b|\bcrypto_rng_get_bytes\b", _RNG, _KERNEL, algorithm="CSPRNG", confidence="MEDIUM"),
    # ---------------------------------------------------------------- libc / weak RNG in key contexts
    _r(r"\b(?:getrandom|getentropy|arc4random(?:_buf|_uniform)?)\s*\(", _RNG, "libc", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bfopen\s*\(\s*\"/dev/u?random\"", _RNG, "libc", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\b(?:srand|srandom|srand48)\s*\(\s*(?:time\s*\(|getpid|\d+)", _RNG, "libc", algorithm="PRNG", confidence="LOW", confidence_reason="time/constant-seeded libc PRNG; not suitable for keys"),
    # ---------------------------------------------------------------- Header includes (LOW - signals linkage only)
    _r(r"^\s*#\s*include\s*[<\"]openssl/(md5|md4|md2|sha|ripemd|whrlpool|mdc2)\.h[>\"]", _D, _OSSL, algo_from_group=1,
       algo_map={"md5": "MD5", "md4": "MD4", "md2": "MD2", "sha": "SHA-1", "ripemd": "RIPEMD-160", "whrlpool": "WHIRLPOOL", "mdc2": "MDC2"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/(des|rc4|rc2|blowfish|cast|idea|aes|camellia|seed|rc5)\.h[>\"]", _C, _OSSL, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "blowfish": "Blowfish", "cast": "CAST5"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/rsa\.h[>\"]", _K, _OSSL, algorithm="RSA", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/(?:ec|ecdsa)\.h[>\"]", _K, _OSSL, algorithm="ECDSA", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/dsa\.h[>\"]", _K, _OSSL, algorithm="DSA", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/dh\.h[>\"]", _KA, _OSSL, algorithm="DH", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/hmac\.h[>\"]", _M, _OSSL, algorithm="HMAC", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]openssl/ssl\.h[>\"]", _TLS, _OSSL, algorithm="TLS", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"](?:mbedtls|polarssl)/(md5|md4|md2|sha1|sha256|sha512|ripemd160)\.h[>\"]", _D, _MBED, algo_from_group=1, algo_map=DIGEST_TOKENS, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"](?:mbedtls|polarssl)/(aes|des|arc4|blowfish|camellia|chacha20|chachapoly|aria)\.h[>\"]", _C, _MBED, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "arc4": "RC4", "blowfish": "Blowfish", "chachapoly": "ChaCha20-Poly1305"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]wolfssl/wolfcrypt/(md5|md4|sha|sha256|sha512|sha3|ripemd)\.h[>\"]", _D, _WOLF, algo_from_group=1,
       algo_map={**DIGEST_TOKENS, "sha3": "SHA3-256", "ripemd": "RIPEMD-160"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]wolfssl/wolfcrypt/(aes|des3|arc4|chacha|chacha20_poly1305|camellia)\.h[>\"]", _C, _WOLF, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "arc4": "RC4", "chacha": "ChaCha20"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]crypto(?:pp|\+\+)/(md5|md4|md2|sha|sha3|ripemd|whrlpool|blake2)\.h[>\"]", _D, _CPP, algo_from_group=1,
       algo_map={**DIGEST_TOKENS, "sha3": "SHA3-256", "ripemd": "RIPEMD-160", "whrlpool": "WHIRLPOOL", "blake2": "BLAKE2b"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]crypto(?:pp|\+\+)/(aes|rijndael|des|arc4|rc2|blowfish|cast|idea|twofish|serpent|camellia|chacha|chachapoly|salsa)\.h[>\"]", _C, _CPP, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "arc4": "RC4", "blowfish": "Blowfish", "cast": "CAST5", "chacha": "ChaCha20", "chachapoly": "ChaCha20-Poly1305", "salsa": "Salsa20"}, confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]crypto(?:pp|\+\+)/rsa\.h[>\"]", _K, _CPP, algorithm="RSA", confidence="LOW", confidence_reason="header-include"),
    _r(r"^\s*#\s*include\s*[<\"]crypto(?:pp|\+\+)/(?:eccrypto|ecp)\.h[>\"]", _K, _CPP, algorithm="ECDSA", confidence="LOW", confidence_reason="header-include"),
    # ------------------------------------------------------------- project-local digest/MAC wrappers
    # curl: Curl_MD5_init / Curl_HMAC_init / Curl_sha256it; nginx: ngx_md5_init; git: git_SHA1_Update ...
    # A function whose name embeds the digest AND an init/update/final verb is a hash API by construction.
    _r(r"\b[A-Za-z]\w*?_(MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3)_?(?:[Ii]nit|[Uu]pdate|[Ff]inal(?:ize)?|[Dd]igest|it)\s*\(|\b(?:ngx|git|curl|Curl|php|py|apr|ap|ssh|mysql|pg)_(md4|md5|sha1|sha224|sha256|sha384|sha512)(?:_?(?:init|update|final|digest|it))?\s*\(", _D, "project-wrapper", algo_from_group=1, algo_map={**DIGEST_TOKENS, "sha3": "SHA3-256"}, confidence="MEDIUM", confidence_reason="project-local wrapper around a named digest"),
    _r(r"\b[A-Za-z]\w*?_HMAC_?(?:[Ii]nit|[Uu]pdate|[Ff]inal(?:ize)?|[Dd]igest|it)\s*\(|\b(?:ngx|git|curl|Curl|apr|ap|ssh|mysql|pg)_hmac(?:_(?:init|update|final|digest|it|sha1|sha256|sha512|md5))?\s*\(", _M, "project-wrapper", algorithm="HMAC", confidence="MEDIUM", confidence_reason="project-local HMAC wrapper"),
    _r(r"\b[A-Za-z]\w*_HMAC_(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\b", _M, "project-wrapper", algorithm="HMAC", emit_digest_group=1, confidence="MEDIUM", confidence_reason="project-local HMAC descriptor"),
    _r(r"\b[A-Za-z]\w*_DIGEST_(MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\b(?!_LEN|_LENGTH|_SIZE)", _D, "project-wrapper", algo_from_group=1, algo_map=DIGEST_TOKENS, confidence="MEDIUM", confidence_reason="project-local digest descriptor"),
    # ------------------------------------------------------------- rustls-ffi / Apple Secure Transport / Network.framework
    _r(r"\brustls_(?:client_config_builder|server_config_builder|client_config|server_config|connection|root_cert_store|crypto_provider|supported_ciphersuite)\w*\s*[\(;,)]|\brustls_(?:client|server)_connection_new\s*\(", _TLS, "rustls-ffi", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bSSLCreateContext\s*\(|\bSSLHandshake\s*\(|\bSSLSetProtocolVersion(?:Min|Max)\s*\(|\bSSLSetSessionOption\s*\(|\bsec_protocol_options_set_(?:min|max)_tls_protocol_version\s*\(|\bnw_tls_create_options\s*\(", _TLS, "SecureTransport", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bkSSLProtocol3\b|\bkSSLProtocol3Only\b", _TLS, "SecureTransport", algorithm="SSLv3", confidence="HIGH"),
    _r(r"\bkSSLProtocol2\b", _TLS, "SecureTransport", algorithm="SSLv2", confidence="HIGH"),
    _r(r"\bkTLSProtocol1\b|\btls_protocol_version_TLSv10\b", _TLS, "SecureTransport", algorithm="TLS1.0", confidence="HIGH"),
    _r(r"\bkTLSProtocol11\b|\btls_protocol_version_TLSv11\b", _TLS, "SecureTransport", algorithm="TLS1.1", confidence="HIGH"),
    _r(r"\bkTLSProtocol12\b|\btls_protocol_version_TLSv12\b", _TLS, "SecureTransport", algorithm="TLS1.2", confidence="HIGH"),
    _r(r"\bkTLSProtocol13\b|\btls_protocol_version_TLSv13\b", _TLS, "SecureTransport", algorithm="TLS1.3", confidence="HIGH"),
    _r(r"\bkSSLSessionOptionBreakOnServerAuth\b|\bSSLSetEnableCertVerify\s*\([^,]+,\s*false\s*\)", _TLS, "SecureTransport", algorithm="TLS-UNVERIFIED", confidence="MEDIUM"),
]

_MULTILINE_RULES = [(re.compile(p.pattern, p.flags | re.M), s) for p, s in _RULES]


def parse_c_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    language = "CPP" if file_path.suffix.lower() in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".mm"} else "C"
    if file_path.suffix.lower() == ".m":
        language = "OBJECTIVE_C"
    findings = run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=raw,
        rules=_MULTILINE_RULES,
        language=language,
        scanner_id=SCANNER_ID,
        confidence_reason="native-crypto-api",
        strip_comments=True,
        macros=True,
    )
    # OpenSSL legacy DES API: the key schedules of a 2-/3-key TDES call (DES_ecb2_encrypt,
    # DES_ede3_cbc_encrypt) are set with the single-DES DES_set_key*; report them as 3DES.
    if _TDES_CALL.search(raw):
        for f in findings:
            if f.crypto.algorithm == "DES" and _DES_SCHEDULE.search(f.crypto.raw_transformation or ""):
                f.crypto.algorithm = "3DES"
                f.metadata.confidence_reason = "DES key schedule used by a TDES (ede2/ede3) call in this file"
    return findings


_TDES_CALL = re.compile(r"\bDES_(?:ede|ecb|ncbc|cbc|cfb|ofb|cfb64|ofb64|pcbc)[23]_\w+\s*\(")
_DES_SCHEDULE = re.compile(r"\bDES_(?:set_key\w*|key_sched|key_schedule|cblock)\b|openssl/des\.h")
