"""SQL crypto detector — Oracle PL/SQL (DBMS_CRYPTO, DBMS_OBFUSCATION_TOOLKIT, TDE),
SQL Server T-SQL (HASHBYTES, ENCRYPTBY*, symmetric/asymmetric keys, Always Encrypted,
TDE), PostgreSQL pgcrypto and MySQL/MariaDB built-ins.

Banks keep a large share of their cryptography *inside the database*: card-number
column encryption in PL/SQL packages, password hashing in stored procedures,
HMAC'd audit trails, TDE DDL. None of it is visible to application-language parsers.

Deliberately not reported: ``ORA_HASH`` / ``CHECKSUM`` / ``BINARY_CHECKSUM`` /
``PARTITION BY HASH`` / hash indexes (not cryptographic), Base64 / hex encoders,
``NEWID``/``gen_random_uuid`` (identifiers), ``PRIMARY KEY`` / ``FOREIGN KEY``.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-sql-scanner-v1.0"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.IGNORECASE), {**base, "library": library, **extra}


_TSQL_HASH = {"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha": "SHA-1", "sha1": "SHA-1", "sha2_256": "SHA-256", "sha2_512": "SHA-512"}
_TSQL_SYM = {"aes_128": "AES", "aes_192": "AES", "aes_256": "AES", "triple_des": "3DES", "triple_des_3key": "3DES", "des": "DES", "desx": "DES", "rc2": "RC2", "rc4": "RC4", "rc4_128": "RC4"}
_PG_DIGEST = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha3-256": "SHA3-256", "sha3-512": "SHA3-512"}
_PG_CRYPT = {"bf": "BCRYPT", "md5": "MD5", "xdes": "DES", "des": "DES"}
_PG_CIPHER = {"aes": "AES", "bf": "Blowfish", "blowfish": "Blowfish", "3des": "3DES", "cast5": "CAST5"}
_ORA_STD_HASH = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}
_SECRET_CTX = r"(?=[^\n;]*(?:passw|pwd|secret|token|salt|otp|pin\b|nonce|session|api_key|apikey))"
# ``gen_otp ... \n RETURN ... DBMS_RANDOM.VALUE(`` / ``INSERT INTO reset_tokens (..., token) VALUES (md5(random()``
_SECRET_BEFORE = r"(?:passw\w*|pwd|secret\w*|token\w*|salt|otp|pin|nonce|session\w*|api_?key)\b(?:[^\n]*\n){0,3}[^\n]*?"

_RULES: list[Rule] = [
    # ------------------------------------------------------------- Oracle DBMS_CRYPTO
    _r(r"\bDBMS_CRYPTO\.ENCRYPT_AES(?:128|192|256)\b", _C, "oracle-dbms_crypto", algorithm="AES"),
    _r(r"\bDBMS_CRYPTO\.ENCRYPT_3DES(?:_2KEY)?\b", _C, "oracle-dbms_crypto", algorithm="3DES"),
    _r(r"\bDBMS_CRYPTO\.ENCRYPT_DES\b", _C, "oracle-dbms_crypto", algorithm="DES"),
    _r(r"\bDBMS_CRYPTO\.ENCRYPT_RC4\b", _C, "oracle-dbms_crypto", algorithm="RC4"),
    _r(r"\bDBMS_CRYPTO\.(?:ENCRYPT|DECRYPT)\s*\((?![^\n;]*ENCRYPT_(?:AES|3DES|DES|RC4))", _C, "oracle-dbms_crypto", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="cipher chosen by a typ variable — inspect ENCRYPT_* constant"),
    _r(r"\bDBMS_CRYPTO\.HASH_(MD4|MD5|SH1|SH256|SH384|SH512)\b", _D, "oracle-dbms_crypto", algo_from_group=1,
       algo_map={"md4": "MD4", "md5": "MD5", "sh1": "SHA-1", "sh256": "SHA-256", "sh384": "SHA-384", "sh512": "SHA-512"}),
    _r(r"\bDBMS_CRYPTO\.HMAC_(MD5|SH1|SH256|SH384|SH512)\b", _M, "oracle-dbms_crypto", algo_from_group=1,
       algo_map={"md5": "HMAC-MD5", "sh1": "HMAC-SHA1", "sh256": "HMAC-SHA256", "sh384": "HMAC-SHA384", "sh512": "HMAC-SHA512"}),
    _r(r"\bDBMS_CRYPTO\.SIGN_SHA(?:1|224|256|384|512)_RSA(?:_X931)?\b|\bDBMS_CRYPTO\.(?:SIGN|VERIFY|PKENCRYPT|PKDECRYPT)\s*\(", _S, "oracle-dbms_crypto", algorithm="RSA"),
    _r(r"\bDBMS_CRYPTO\.KEY_TYPE_RSA\b|\bDBMS_CRYPTO\.PKENCRYPT_RSA_PKCS1_OAEP\b", _K, "oracle-dbms_crypto", algorithm="RSA"),
    _r(r"\bDBMS_CRYPTO\.RANDOM(?:BYTES|INTEGER|NUMBER)\b", _RNG, "oracle-dbms_crypto", algorithm="CSPRNG"),
    _r(r"\bDBMS_OBFUSCATION_TOOLKIT\.DES3(?:ENCRYPT|DECRYPT|GETKEY)\b", _C, "oracle-obfuscation-toolkit", algorithm="3DES", confidence="HIGH", confidence_reason="deprecated DBMS_OBFUSCATION_TOOLKIT"),
    _r(r"\bDBMS_OBFUSCATION_TOOLKIT\.DES(?:ENCRYPT|DECRYPT|GETKEY)\b", _C, "oracle-obfuscation-toolkit", algorithm="DES", confidence="HIGH", confidence_reason="deprecated DBMS_OBFUSCATION_TOOLKIT"),
    _r(r"\bDBMS_OBFUSCATION_TOOLKIT\.MD5\b", _D, "oracle-obfuscation-toolkit", algorithm="MD5"),
    _r(r"\bSTANDARD_HASH\s*\([^)]*?,\s*'(SHA1|SHA256|SHA384|SHA512|MD5)'", _D, "oracle-standard_hash", algo_from_group=1, algo_map=_ORA_STD_HASH),
    _r(r"\bSTANDARD_HASH\s*\((?![^)]*,)", _D, "oracle-standard_hash", algorithm="SHA-1", confidence="MEDIUM", confidence_reason="STANDARD_HASH default method is SHA1"),
    _r(r"\bDBMS_RANDOM\.(?:VALUE|STRING|RANDOM|NORMAL)\s*\(" + _SECRET_CTX, _RNG, "oracle-dbms_random", algorithm="PRNG", confidence="HIGH", confidence_reason="DBMS_RANDOM is not cryptographically secure"),
    _r(_SECRET_BEFORE + r"(DBMS_RANDOM\.(?:VALUE|STRING|RANDOM|NORMAL)\s*\(|(?<![\w.])random\s*\(\s*\)|\bRAND\s*\(\s*\))", _RNG, "sql-prng", algorithm="PRNG", confidence="HIGH", line_group=1,
       confidence_reason="non-cryptographic PRNG feeding a secret / token / OTP (context within 3 lines)"),
    # Oracle TDE / wallet
    _r(r"\bENCRYPT\s+USING\s+'?(AES128|AES192|AES256|3DES168|ARIA\d+|SEED128|GOST\d+)'?", _C, "oracle-tde", algo_from_group=1,
       algo_map={"aes128": "AES", "aes192": "AES", "aes256": "AES", "3des168": "3DES", "aria128": "ARIA", "aria192": "ARIA", "aria256": "ARIA", "seed128": "SEED", "gost256": "GOST"}),
    _r(r"\bENCRYPTION\s+USING\s+'?(AES128|AES192|AES256|3DES168|ARIA\d+|SEED128|GOST\d+)'?", _C, "oracle-tde", algo_from_group=1,
       algo_map={"aes128": "AES", "aes192": "AES", "aes256": "AES", "3des168": "3DES", "aria128": "ARIA", "aria192": "ARIA", "aria256": "ARIA", "seed128": "SEED", "gost256": "GOST"}),
    _r(r"\bENCRYPT\b\s*(?:NO\s+SALT|SALT)?\s*(?:,|\)|NOT\s+NULL|$)(?![^\n]*USING)", _C, "oracle-tde", algorithm="AES", confidence="MEDIUM", confidence_reason="TDE column encryption default AES192"),
    _r(r"\bADMINISTER\s+KEY\s+MANAGEMENT\b|\bENCRYPTION_WALLET_LOCATION\b|\bWALLET_ROOT\b|\bTDE_CONFIGURATION\b", _K, "oracle-tde", algorithm="UNKNOWN", confidence="LOW", confidence_reason="TDE master key / wallet management"),
    _r(r"\bSQLNET\.ENCRYPTION_TYPES_(?:SERVER|CLIENT)\s*=\s*\(?\s*([A-Z0-9_,\s]+)\)?", _C, "oracle-net-encryption", algorithm="UNKNOWN", confidence="MEDIUM", raw_group=1),
    # ------------------------------------------------------------- SQL Server T-SQL
    _r(r"\bHASHBYTES\s*\(\s*N?'(MD2|MD4|MD5|SHA|SHA1|SHA2_256|SHA2_512)'", _D, "tsql-hashbytes", algo_from_group=1, algo_map=_TSQL_HASH),
    _r(r"\bCREATE\s+SYMMETRIC\s+KEY\b[^;]*?\bALGORITHM\s*=\s*(AES_128|AES_192|AES_256|TRIPLE_DES_3KEY|TRIPLE_DES|DESX|DES|RC2|RC4_128|RC4)\b", _K, "tsql-symmetric-key", algo_from_group=1, algo_map=_TSQL_SYM),
    _r(r"\bCREATE\s+DATABASE\s+ENCRYPTION\s+KEY\b[^;]*?\bALGORITHM\s*=\s*(AES_128|AES_192|AES_256|TRIPLE_DES_3KEY)\b", _K, "tsql-tde", algo_from_group=1, algo_map=_TSQL_SYM),
    _r(r"\bCREATE\s+ASYMMETRIC\s+KEY\b[^;]*?\bALGORITHM\s*=\s*RSA_(?:512|1024|2048|3072|4096)\b|\bCREATE\s+ASYMMETRIC\s+KEY\b", _K, "tsql-asymmetric-key", algorithm="RSA"),
    _r(r"\b(?:ENCRYPTBYKEY|DECRYPTBYKEY|DECRYPTBYKEYAUTOCERT|DECRYPTBYKEYAUTOASYMKEY)\s*\(", _C, "tsql-cell-encryption", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="algorithm fixed by CREATE SYMMETRIC KEY ... ALGORITHM"),
    _r(r"\b(?:ENCRYPTBYPASSPHRASE|DECRYPTBYPASSPHRASE)\s*\(", _C, "tsql-cell-encryption", algorithm="3DES", confidence="MEDIUM", confidence_reason="TRIPLE_DES below compatibility level 140; AES-256 from SQL Server 2017 (140+)"),
    _r(r"\b(?:ENCRYPTBYCERT|DECRYPTBYCERT|SIGNBYCERT|VERIFYSIGNEDBYCERT|ENCRYPTBYASYMKEY|DECRYPTBYASYMKEY|SIGNBYASYMKEY|VERIFYSIGNEDBYASYMKEY)\s*\(", _S, "tsql-certificate", algorithm="RSA", confidence="HIGH"),
    _r(r"\bCREATE\s+CERTIFICATE\b|\bBACKUP\s+CERTIFICATE\b|\bENCRYPTION\s+BY\s+SERVER\s+CERTIFICATE\b", _K, "tsql-certificate", algorithm="X509", confidence="HIGH"),
    _r(r"\bCREATE\s+MASTER\s+KEY\s+ENCRYPTION\s+BY\s+PASSWORD\b|\bOPEN\s+MASTER\s+KEY\b", _K, "tsql-dmk", algorithm="AES", confidence="LOW", confidence_reason="database master key (AES-256 from SQL Server 2012, 3DES before)"),
    _r(r"\bALGORITHM\s*=\s*'?(AEAD_AES_256_CBC_HMAC_SHA_256)'?", _C, "tsql-always-encrypted", algorithm="AES", mode="CBC", key_size=256, confidence="HIGH", confidence_reason="Always Encrypted column"),
    _r(r"\bAEAD_AES_256_CBC_HMAC_SHA_256\b", _M, "tsql-always-encrypted", algorithm="HMAC-SHA256"),
    _r(r"\bCOLUMN_ENCRYPTION_KEY\s*=|\bCREATE\s+COLUMN\s+(?:ENCRYPTION|MASTER)\s+KEY\b", _K, "tsql-always-encrypted", algorithm="AES", confidence="MEDIUM", confidence_reason="Always Encrypted CEK (AES-256)"),
    _r(r"\bSET\s+ENCRYPTION\s+ON\b", _C, "tsql-tde", algorithm="UNKNOWN", confidence="LOW", confidence_reason="TDE enable — algorithm from DATABASE ENCRYPTION KEY"),
    _r(r"\bPWDENCRYPT\s*\(|\bPWDCOMPARE\s*\(", _KDF, "tsql-pwdencrypt", algorithm="SHA-512", confidence="MEDIUM", confidence_reason="undocumented PWDENCRYPT (SHA-512 salted since 2012, SHA-1 before)"),
    _r(r"\bCRYPT_GEN_RANDOM\s*\(", _RNG, "tsql", algorithm="CSPRNG"),
    _r(r"\bRAND\s*\(" + _SECRET_CTX, _RNG, "tsql/mysql", algorithm="PRNG", confidence="HIGH", confidence_reason="RAND() is not cryptographically secure"),
    _r(r"\bLOGINPROPERTY\s*\([^)]*'PasswordHash'", _KDF, "tsql", algorithm="SHA-512", confidence="LOW"),
    # ------------------------------------------------------------- PostgreSQL pgcrypto / built-ins
    _r(r"\bdigest\s*\([^;]*?,\s*'(md5|sha1|sha224|sha256|sha384|sha512|sha3-256|sha3-512)'\s*\)", _D, "pgcrypto", algo_from_group=1, algo_map=_PG_DIGEST),
    _r(r"\bhmac\s*\([^;]*?,\s*'(md5|sha1|sha224|sha256|sha384|sha512)'\s*\)", _M, "pgcrypto", algo_from_group=1,
       algo_map={"md5": "HMAC-MD5", "sha1": "HMAC-SHA1", "sha224": "HMAC-SHA224", "sha256": "HMAC-SHA256", "sha384": "HMAC-SHA384", "sha512": "HMAC-SHA512"}),
    _r(r"\bgen_salt\s*\(\s*'(bf|md5|xdes|des)'", _KDF, "pgcrypto", algo_from_group=1, algo_map=_PG_CRYPT),
    _r(r"\bcrypt\s*\(\s*[^,]+,\s*(?!gen_salt)[^)]*\)", _KDF, "pgcrypto", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="crypt() against a stored hash — scheme is in the salt prefix"),
    _r(r"\bpgp_(?:sym|pub)_(?:encrypt|decrypt)(?:_bytea)?\s*\(", _C, "pgcrypto-pgp", algorithm="PGP", confidence="HIGH"),
    _r(r"\bcipher-algo\s*=\s*(aes128|aes192|aes256|bf|3des|cast5)", _C, "pgcrypto-pgp", algo_from_group=1, algo_map={"aes128": "AES", "aes192": "AES", "aes256": "AES", "bf": "Blowfish", "3des": "3DES", "cast5": "CAST5"}),
    _r(r"\bpgp_sym_(?:encrypt|decrypt)(?:_bytea)?\s*\((?![^;]*cipher-algo)", _C, "pgcrypto-pgp", algorithm="AES", confidence="MEDIUM", confidence_reason="pgp_sym_* default cipher-algo=aes128"),
    _r(r"\bpgp_pub_(?:encrypt|decrypt)(?:_bytea)?\s*\(", _K, "pgcrypto-pgp", algorithm="RSA", confidence="LOW", confidence_reason="PGP public key (RSA or ElGamal)"),
    _r(r"\b(?:encrypt|decrypt)(?:_iv)?\s*\([^;]*?,\s*'(aes|bf|blowfish|3des|cast5)(?:-(?:cbc|ecb))?(?:/pad:(?:pkcs|none))?'\s*\)", _C, "pgcrypto", algo_from_group=1, algo_map=_PG_CIPHER),
    _r(r"\bgen_random_bytes\s*\(", _RNG, "pgcrypto", algorithm="CSPRNG"),
    _r(r"\brandom\s*\(\s*\)" + _SECRET_CTX, _RNG, "postgresql", algorithm="PRNG", confidence="HIGH", confidence_reason="random() is not cryptographically secure"),
    _r(r"(?<![\w.])md5\s*\(", _D, "sql-builtin", algorithm="MD5"),
    _r(r"\bsha(?:224|256|384|512)\s*\(", _D, "postgresql", algorithm="SHA-256", confidence="MEDIUM"),
    _r(r"\bPASSWORD_ENCRYPTION\s*=\s*'?(scram-sha-256|md5)'?", _KDF, "postgresql", algo_from_group=1, algo_map={"scram-sha-256": "SHA-256", "md5": "MD5"}),
    # ------------------------------------------------------------- MySQL / MariaDB
    _r(r"\bAES_(?:ENCRYPT|DECRYPT)\s*\(", _C, "mysql", algorithm="AES", confidence="HIGH", confidence_reason="mode from block_encryption_mode (default aes-128-ecb)"),
    _r(r"\bblock_encryption_mode\s*=\s*'?aes-(?:128|192|256)-(cbc|ecb|cfb1|cfb8|cfb128|ofb)", _C, "mysql", algorithm="AES", confidence="HIGH", raw_group=1),
    _r(r"\bDES_(?:ENCRYPT|DECRYPT)\s*\(", _C, "mysql", algorithm="DES", confidence="HIGH"),
    _r(r"(?<![\w.])ENCRYPT\s*\(\s*[^)]*(?:pass|pwd|secret)", _KDF, "mysql", algorithm="DES", confidence="MEDIUM", confidence_reason="MySQL ENCRYPT() is Unix crypt(3) DES"),
    _r(r"(?<![\w.])SHA1?\s*\(", _D, "mysql", algorithm="SHA-1"),
    _r(r"\bSHA2\s*\([^,]+,\s*(224|256|384|512|0)\s*\)", _D, "mysql", algo_from_group=1,
       algo_map={"224": "SHA-224", "256": "SHA-256", "384": "SHA-384", "512": "SHA-512", "0": "SHA-256"}),
    _r(r"\bOLD_PASSWORD\s*\(", _KDF, "mysql", algorithm="UNKNOWN", confidence="HIGH", confidence_reason="pre-4.1 MySQL password hash (broken)"),
    _r(r"(?<![\w.])PASSWORD\s*\(\s*['\"@:a-z_]", _KDF, "mysql", algorithm="SHA-1", confidence="MEDIUM", confidence_reason="MySQL PASSWORD() = SHA1(SHA1(x))"),
    _r(r"\bIDENTIFIED\s+WITH\s+'?(mysql_native_password|caching_sha2_password|sha256_password|ed25519)'?", _KDF, "mysql-auth-plugin", algo_from_group=1,
       algo_map={"mysql_native_password": "SHA-1", "caching_sha2_password": "SHA-256", "sha256_password": "SHA-256", "ed25519": "Ed25519"}),
    _r(r"\bREQUIRE\s+(?:SSL|X509)\b|\brequire_secure_transport\s*=\s*(?:ON|1)", _TLS, "mysql", algorithm="TLS", confidence="HIGH"),
    _r(r"\bENCRYPTION\s*=\s*'Y'", _C, "mysql-tablespace-encryption", algorithm="AES", confidence="MEDIUM", confidence_reason="InnoDB tablespace encryption AES-256"),
    # ------------------------------------------------------------- DB2 / generic
    _r(r"\bENCRYPT_AES\s*\(|\bDECRYPT_(?:CHAR|BIN)\s*\(", _C, "db2", algorithm="AES", confidence="HIGH"),
    _r(r"\bENCRYPT_TDES\s*\(", _C, "db2", algorithm="3DES", confidence="HIGH"),
    _r(r"\bHASH_(MD5|SHA1|SHA256|SHA512)\s*\(|(?<![\w.])HASH\s*\(\s*[\w.:\[\]]+\s*,\s*(0|1|2|3)\s*\)", _D, "db2", algo_from_group=1,
       algo_map={"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512", "0": "MD5", "1": "SHA-1", "2": "SHA-256", "3": "SHA-512"}),
    _r(r"\bGETHINT\s*\(|\bENCRYPTION\s+PASSWORD\b", _C, "db2", algorithm="AES", confidence="LOW", confidence_reason="DB2 column encryption (RC2 legacy / AES)"),
]

_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _strip_sql_comments(text: str) -> str:
    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    return _LINE_COMMENT.sub(blank, _BLOCK_COMMENT.sub(blank, text))


def parse_sql_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=_strip_sql_comments(text),
        rules=_RULES,
        language="SQL",
        scanner_id=SCANNER_ID,
        confidence_reason="sql-crypto-call",
        strip_comments=False,
    )
