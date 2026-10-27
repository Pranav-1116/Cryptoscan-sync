"""IBM i (AS/400) crypto detector — RPG IV (fixed and **FREE), CL/CLLE, ILE C headers.

What banks actually run on IBM i:

* **Cryptographic Services APIs** (``QC3*``): ``Qc3EncryptData`` / ``QC3ENCDT``,
  ``Qc3CalculateHash`` / ``QC3CALHA``, ``Qc3CalculateHMAC``, ``Qc3CalculateSignature``,
  ``Qc3GenPRNs``, key/algorithm context builders. The algorithm is *not* in the call —
  it is a numeric code in the ``ALGD0200`` (block cipher: 20 DES, 21 3DES, 22 AES,
  23 RC2, 30 RC4) / ``ALGD0400`` (50 RSA) / ``ALGD0500`` (hash: 1 MD5, 2 SHA-1,
  3 SHA-256, 4 SHA-384, 5 SHA-512) structures. We resolve it from the algorithm-field
  initialiser (``blockCipherAlg inz(22)``, ``hashAlg = 3``) or a keyword in a ±12-line
  window; otherwise the call is reported as UNKNOWN (never guessed).
* **GSKit / Global Secure Toolkit** TLS (``gsk_environment_open``, ``GSK_PROTOCOL_TLSV12``,
  ``GSK_TLSV12_CIPHER_SPECS``, ``GSK_KEYRING_FILE``).
* **CL system values**: ``CHGSYSVAL SYSVAL(QSSLPCL) VALUE('*TLSV1.2 *TLSV1.3')`` and
  ``QSSLCSL`` cipher lists, master-key commands (``SETMSTKEY``/``LODMSTKEY``/``ADDMSTPART``).
* **MI / older APIs**: ``_CIPHER`` / ``cipher()`` MI instruction, ``Qc3`` predecessors
  ``QsyEncryptData`` is not a thing — but ``QSYGENPRN``/``Qsy*`` random and ``encrypt``
  builtins are covered where they exist.
* **Embedded SQL** (``SQLRPGLE``): DB2 for i ``ENCRYPT_AES``/``ENCRYPT_TDES``/``HASH_SHA256``
  via the shared SQL rule table.

Negatives that must stay silent: ``QC3`` in library lists / object names without an API
call, ``CHGSYSVAL`` for unrelated values, ``*SYSTEM`` in ``OVRDBF``, ``KEYFLD``/``KLIST``
(record keys), ``%RANDOM`` is not an RPG builtin (``CEERAN0`` is, and is flagged only in a
secret/token context).
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-rpg-scanner-v1.0"

_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_KG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.IGNORECASE), {**base, "library": library, **extra}


# Qc3 API: bound procedure name (RPG prototype / C) or *PGM name (CALL 'QC3ENCDT')
_QC3_ENC = r"(?:Qc3EncryptData|Qc3DecryptData|Qc3TranslateData|QC3ENCDT|QC3DECDT|QC3TRNDT)"
_QC3_HASH = r"(?:Qc3CalculateHash|QC3CALHA)"
_QC3_HMAC = r"(?:Qc3CalculateHMAC|QC3CALHM)"
_QC3_SIG = r"(?:Qc3CalculateSignature|Qc3VerifySignature|QC3CALSG|QC3VFYSG)"
_QC3_RNG = r"(?:Qc3GenPRNs|Qc3PRNG?|QC3GENRN|Qc3GenPRNSeed|QC3PRNSD)"
_QC3_KEY = r"(?:Qc3GenSymmetricKey|Qc3GenPKAKeyPair|Qc3CreateKeyContext|Qc3EncryptKey|Qc3DecryptKey|Qc3ExportKey|Qc3ImportKey|Qc3ExtractPublicKey|Qc3WriteKeyRecord|Qc3AddKeyStore|Qc3TranslateKeyStore|Qc3RetrieveKeyRecordAtr|Qc3DeleteKeyRecord|Qc3CreateAlgorithmContext|QC3GENSK|QC3GENPK|QC3CRTKX|QC3ENCKY|QC3DECKY|QC3EXPKY|QC3IMPKY|QC3EXTPB|QC3WRTKR|QC3ADDKS|QC3TRNKS|QC3CRTAX|QC3RTVKA|QC3DLTKR)"
# a call/prototype, not a mention in a comment or an object list
_CALLISH = r"(?=\s*(?:\(|:|\bextproc|\bextpgm|;|\+|\s*$))"
_PGMCALL = r"(?:\bCALL\s+(?:PGM\()?'?|\bextpgm\s*\(\s*'|\bextproc\s*\(\s*'|\bCALLP\s+|\bdcl-pr\s+\w+\s+\w*\s*extpgm\s*\(\s*'|\bdcl-pr\s+\w+\s+\w*\s*extproc\s*\(\s*')"

_RULES: list[Rule] = [
    _r(rf"\b{_QC3_ENC}\b{_CALLISH}|{_PGMCALL}{_QC3_ENC}\b", _C, "IBM-i-Cryptographic-Services", algorithm="UNKNOWN", confidence="MEDIUM",
       confidence_reason="Qc3 encrypt/decrypt — algorithm comes from the ALGD0200/ALGD0400 context"),
    _r(rf"\b{_QC3_HASH}\b{_CALLISH}|{_PGMCALL}{_QC3_HASH}\b", _D, "IBM-i-Cryptographic-Services", algorithm="UNKNOWN", confidence="MEDIUM",
       confidence_reason="Qc3 hash — algorithm from ALGD0500 (1 MD5, 2 SHA-1, 3 SHA-256, 4 SHA-384, 5 SHA-512)"),
    _r(rf"\b{_QC3_HMAC}\b{_CALLISH}|{_PGMCALL}{_QC3_HMAC}\b", _M, "IBM-i-Cryptographic-Services", algorithm="HMAC", confidence="HIGH"),
    _r(rf"\b{_QC3_SIG}\b{_CALLISH}|{_PGMCALL}{_QC3_SIG}\b", _S, "IBM-i-Cryptographic-Services", algorithm="RSA", confidence="MEDIUM",
       confidence_reason="Qc3 signature — ALGD0400 public-key algorithm 50 = RSA (only PKA algorithm on IBM i)"),
    _r(rf"\b{_QC3_RNG}\b{_CALLISH}|{_PGMCALL}{_QC3_RNG}\b", _KG, "IBM-i-Cryptographic-Services", algorithm="CSPRNG", confidence="HIGH"),
    _r(rf"\b{_QC3_KEY}\b{_CALLISH}|{_PGMCALL}{_QC3_KEY}\b", _K, "IBM-i-Cryptographic-Services", algorithm="UNKNOWN", confidence="MEDIUM",
       confidence_reason="Qc3 key / algorithm context management"),
    # Algorithm-field initialisers of the ALGD structures (resolved via _ALGD_CODES)
    _r(r"\b(\w*(?:blockCipherAlg|blkCphAlg|cipherAlg|BlockCipher|hashAlg|HashAlgorithm|hashAlgo|signHash|sigHash|pkaAlg|publicKeyAlg|PKAAlgorithm|algorithm)\w*)\s*(?:\d+[IUBP]\s+\d\s+)?(?:inz\s*\(\s*|=\s*|\bint\(10\)\s+inz\s*\(\s*)(\d{1,2})\b",
       _C, "IBM-i-Cryptographic-Services", algo_from_group=2, algo_map={"1": "MD5", "2": "SHA-1", "3": "SHA-256", "4": "SHA-384", "5": "SHA-512", "20": "DES", "21": "3DES", "22": "AES", "23": "RC2", "30": "RC4", "50": "RSA"},
       confidence="MEDIUM", confidence_reason="ALGD02xx/05xx algorithm code"),
    # QSYSINC qc3cci.h symbolic algorithm constants (Qc3_AES = 22, Qc3_SHA256 = 3 ...)
    _r(r"\bQc3_(MD5|SHA1|SHA256|SHA384|SHA512)\b(?!\s*=\s*\d)", _D, "IBM-i-Cryptographic-Services", algo_from_group=1,
       algo_map={"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"},
       confidence="MEDIUM", confidence_reason="ALGD0500 hash constant from qc3cci.h"),
    _r(r"\bQc3_(DES|TDES|AES|RC2|RC4)\b(?!\s*=\s*\d)", _C, "IBM-i-Cryptographic-Services", algo_from_group=1,
       algo_map={"des": "DES", "tdes": "3DES", "aes": "AES", "rc2": "RC2", "rc4": "RC4"}, confidence="MEDIUM", confidence_reason="ALGD0200 cipher constant from qc3cci.h"),
    _r(r"\bQc3_RSA\b(?!\s*=\s*\d)", _K, "IBM-i-Cryptographic-Services", algorithm="RSA", confidence="MEDIUM", confidence_reason="ALGD0400 constant from qc3cci.h"),
    # MI cipher instruction (very old but still in production) and CEE random
    _r(r"\b_CIPHER\b\s*\(|\bcipher\s*\(\s*&?\w*(?:ctl|control)\w*\s*[,:]", _C, "IBM-i-MI", algorithm="UNKNOWN", confidence="LOW", confidence_reason="MI CIPHER instruction (DES/3DES/RC4/AES/SHA by control block)"),
    _r(r"\bCEERAN0\b(?=[^\n]*(?:\n[^\n]*){0,2}(?:pass|pwd|secret|token|salt|otp|pin|nonce|key))", _KG, "ILE-CEE", algorithm="PRNG", confidence="HIGH", confidence_reason="CEERAN0 is not cryptographically secure"),
    # GSKit TLS
    _r(r"\bgsk_(?:environment_open|environment_init|secure_soc_open|secure_soc_init|attribute_set_(?:enum|buffer|numeric_value))\b", _TLS, "IBM-i-GSKit", algorithm="TLS", confidence="HIGH"),
    _r(r"\bGSK_PROTOCOL_(TLSV13|TLSV12|TLSV11|TLSV10|TLSV1|SSLV3|SSLV2)\b", _TLS, "IBM-i-GSKit", algo_from_group=1,
       algo_map={"tlsv13": "TLS1.3", "tlsv12": "TLS1.2", "tlsv11": "TLS1.1", "tlsv10": "TLS1.0", "tlsv1": "TLS1.0", "sslv3": "SSLv3", "sslv2": "SSLv2"}, confidence="HIGH"),
    _r(r"\bGSK_(?:TLSV1[023]|V3|V2)_CIPHER_SPECS(?:_EX)?\b(?:[^'\n]*'([^'\n]+)')?", _TLS, "IBM-i-GSKit", algorithm="TLS-CIPHERS", confidence="MEDIUM", raw_group=1),
    _r(r"\bGSK_(?:KEYRING_FILE|KEYRING_LABEL|OS400_APPLICATION_ID|SERVER_AUTH_TYPE|CLIENT_AUTH_TYPE)\b", _S, "IBM-i-GSKit", algorithm="X509", confidence="MEDIUM", confidence_reason="DCM certificate store / application id"),
    _r(r"\bGSK_(?:CLIENT_AUTH_PASSTHRU|SERVER_AUTH_PASSTHRU)\b|\bGSK_(?:SERVER|CLIENT)_AUTH_TYPE\b[^\n]*\bGSK_(?:CLIENT|SERVER)_AUTH_PASSTHRU\b", _TLS, "IBM-i-GSKit", algorithm="TLS-UNVERIFIED", confidence="HIGH", confidence_reason="certificate validation bypassed"),
    # CL system values
    _r(r"\bCHGSYSVAL\s+SYSVAL\(\s*QSSLPCL\s*\)\s+VALUE\(\s*'([^']*)'", _TLS, "IBM-i-QSSLPCL", algorithm="TLS", confidence="HIGH", raw_group=1),
    _r(r"\bCHGSYSVAL\s+SYSVAL\(\s*QSSLCSL\s*\)\s+VALUE\(\s*'([^']*)'", _TLS, "IBM-i-QSSLCSL", algorithm="TLS-CIPHERS", confidence="HIGH", raw_group=1, ibm_i_suites=1),
    _r(r"\b(?:SETMSTKEY|LODMSTKEY|ADDMSTPART|CLRMSTKEY|TSTMSTKEY|TRNCKMKSF|CRTCKMKSF|ADDCKMKSFE|RSTMSTKEY|SAVMSTKEY)\b", _K, "IBM-i-master-key", algorithm="AES", confidence="MEDIUM",
       confidence_reason="IBM i master keys are AES-256 (Cryptographic Services key store)"),
    _r(r"\bCHGTCPA\b[^\n]*\bSSL", _TLS, "IBM-i-CL", algorithm="TLS", confidence="LOW"),
    _r(r"\bSNDDST\b[^\n]*\bENCRYPT\b|\bCPYTOIMPF\b[^\n]*\bENCRYPT\b", _C, "IBM-i-CL", algorithm="UNKNOWN", confidence="LOW"),
    # ODBC/JDBC secure connection keywords in RPG/CL string literals
    _r(r"\bSSL_(?:VERIFY|SERVER_CERT|CLIENT_CERT)\b", _TLS, "IBM-i-ODBC", algorithm="TLS", confidence="LOW"),
]

# QSSLCSL / GSKit suite token → families (IBM i spellings: *RSA_AES_128_CBC_SHA256, *ECDHE_ECDSA_AES_256_GCM_SHA384, *RSA_RC4_128_SHA)
_SUITE_TOKENS = [
    (re.compile(r"CHACHA20"), "ChaCha20", "CIPHER_INSTANCE"),
    (re.compile(r"AES_?\d{3}"), "AES", "CIPHER_INSTANCE"),
    (re.compile(r"3DES|DES_EDE3|TDES"), "3DES", "CIPHER_INSTANCE"),
    (re.compile(r"(?<![3A-Z])DES(?!_EDE)"), "DES", "CIPHER_INSTANCE"),
    (re.compile(r"RC4"), "RC4", "CIPHER_INSTANCE"),
    (re.compile(r"RC2"), "RC2", "CIPHER_INSTANCE"),
    (re.compile(r"NULL"), "NULL-CIPHER", "CIPHER_INSTANCE"),
    (re.compile(r"SHA512"), "SHA-512", "MESSAGE_DIGEST"),
    (re.compile(r"SHA384"), "SHA-384", "MESSAGE_DIGEST"),
    (re.compile(r"SHA256"), "SHA-256", "MESSAGE_DIGEST"),
    (re.compile(r"SHA(?!\d)"), "SHA-1", "MESSAGE_DIGEST"),
    (re.compile(r"MD5"), "MD5", "MESSAGE_DIGEST"),
    (re.compile(r"ECDHE"), "ECDH", "KEY_AGREEMENT"),
    (re.compile(r"ECDSA"), "ECDSA", "SIGNATURE"),
    (re.compile(r"(?<!ECDHE_)RSA"), "RSA", "KEY_AGREEMENT"),
    (re.compile(r"DHE(?!_)|_DHE_"), "DH", "KEY_AGREEMENT"),
]

_PCL = {"TLSV1.3": "TLS1.3", "TLSV1.2": "TLS1.2", "TLSV1.1": "TLS1.1", "TLSV1": "TLS1.0", "TLSV1.0": "TLS1.0", "SSLV3": "SSLv3", "SSLV2": "SSLv2"}

_ALGO_WINDOW = re.compile(
    r"\b(AES|TDES|3DES|TRIPLE[_ ]?DES|DES|RC2|RC4|SHA[_-]?512|SHA[_-]?384|SHA[_-]?256|SHA[_-]?1|MD5|RSA)\b", re.I
)
_WINDOW_MAP = {"aes": "AES", "tdes": "3DES", "3des": "3DES", "triple_des": "3DES", "triple des": "3DES", "tripledes": "3DES", "des": "DES",
               "rc2": "RC2", "rc4": "RC4", "sha512": "SHA-512", "sha-512": "SHA-512", "sha_512": "SHA-512", "sha384": "SHA-384", "sha-384": "SHA-384",
               "sha_384": "SHA-384", "sha256": "SHA-256", "sha-256": "SHA-256", "sha_256": "SHA-256", "sha1": "SHA-1", "sha-1": "SHA-1", "sha_1": "SHA-1",
               "md5": "MD5", "rsa": "RSA"}
_HASH_FAMILIES = {"SHA-512", "SHA-384", "SHA-256", "SHA-1", "MD5"}
_CIPHER_FAMILIES = {"AES", "3DES", "DES", "RC2", "RC4"}


def _strip_rpg_comments(text: str) -> str:
    """Blank RPG comments (``//`` free-form, ``*`` in column 7 fixed-form), CL ``/* */``.

    Keep line structure so line numbers survive.
    """
    out = []
    for line in text.split("\n"):
        stripped = line
        # fixed-form: col 7 == '*' means comment (also '*' in col 7 of CL prompt lines)
        if len(line) >= 7 and line[6] == "*" and not line.lstrip().startswith(("*TLSV", "*SSLV", "*AES", "*RSA", "*ECDHE")):
            stripped = ""
        else:
            i = line.find("//")
            if i >= 0 and not re.search(r"['\"][^'\"]*//", line[: i + 2]):  # not inside a literal (URLs)
                stripped = line[:i]
        out.append(stripped)
    text = "\n".join(out)
    return re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)


def _resolve_unknowns(text: str, findings: list[RawFinding]) -> None:
    """Fill UNKNOWN Qc3 encrypt/hash findings from an algorithm keyword within ±12 lines."""
    lines = text.split("\n")
    # concrete ALGD codes declared anywhere in the module (one cipher code + one hash code is the common shape)
    codes_c = {f.crypto.algorithm for f in findings if "ALGD" in (f.metadata.confidence_reason or "") and f.crypto.algorithm in _CIPHER_FAMILIES | {"RSA"}}
    codes_h = {f.crypto.algorithm for f in findings if "ALGD" in (f.metadata.confidence_reason or "") and f.crypto.algorithm in _HASH_FAMILIES}
    for f in findings:
        if f.crypto.algorithm != "UNKNOWN" or f.metadata.library != "IBM-i-Cryptographic-Services":
            continue
        if f.crypto.api_type == "MESSAGE_DIGEST" and len(codes_h) == 1:
            f.crypto.algorithm = next(iter(codes_h))
            f.metadata.confidence_reason = (f.metadata.confidence_reason or "") + " — resolved from the module's ALGD0500 hash code"
            continue
        if f.crypto.api_type == "CIPHER_INSTANCE" and len(codes_c) == 1:
            f.crypto.algorithm = next(iter(codes_c))
            f.metadata.confidence_reason = (f.metadata.confidence_reason or "") + " — resolved from the module's ALGD0200 cipher code"
            continue
        ln = f.source.line_number
        lo, hi = max(0, ln - 13), min(len(lines), ln + 3)
        window = "\n".join(lines[lo:hi])
        want = _HASH_FAMILIES if f.crypto.api_type == "MESSAGE_DIGEST" else _CIPHER_FAMILIES | {"RSA"}
        hits = []
        for m in _ALGO_WINDOW.finditer(window):
            fam = _WINDOW_MAP.get(m.group(1).lower().replace(" ", "_"))
            if fam in want and fam not in hits:
                hits.append(fam)
        if len(hits) == 1:
            f.crypto.algorithm = hits[0]
            f.metadata.confidence_reason = (f.metadata.confidence_reason or "") + f" — resolved from '{hits[0]}' in the surrounding declarations"
        # ambiguous (>1) stays UNKNOWN: the ALGD initialiser rule reports the concrete code separately


def _expand_ibm_i_suites(path: Path, repo_root: Path | None, findings: list[RawFinding], language: str) -> list[RawFinding]:
    extra: list[RawFinding] = []
    have = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
    for f in findings:
        if f.metadata.library == "IBM-i-QSSLPCL":
            for token in re.split(r"[\s,]+", (f.crypto.raw_transformation or "").upper()):
                ver = _PCL.get(token.lstrip("*"))
                if ver and (f.source.line_number, ver.upper()) not in have:
                    have.add((f.source.line_number, ver.upper()))
                    extra.append(make_finding(file_path=path, repo_root=repo_root, line_number=f.source.line_number, language=language,
                                              api_type="KEY_AGREEMENT", algorithm=ver, purpose="NETWORK_ENCRYPTION", library="IBM-i-QSSLPCL",
                                              scanner_id=SCANNER_ID, confidence="HIGH", confidence_reason="QSSLPCL enabled protocol", raw_transformation=token))
            continue
        if f.metadata.library not in ("IBM-i-QSSLCSL",):
            continue
        raw = (f.crypto.raw_transformation or "").upper()
        for token in re.split(r"[\s,]+", raw):
            for rx, fam, api in _SUITE_TOKENS:
                if rx.search(token) and (f.source.line_number, fam.upper()) not in have:
                    have.add((f.source.line_number, fam.upper()))
                    extra.append(make_finding(file_path=path, repo_root=repo_root, line_number=f.source.line_number, language=language,
                                              api_type=api, algorithm=fam, purpose="NETWORK_ENCRYPTION", library="IBM-i-QSSLCSL",
                                              scanner_id=SCANNER_ID, confidence="MEDIUM", confidence_reason="QSSLCSL cipher-suite component",
                                              raw_transformation=token))
    return extra


def parse_rpg_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = file_path.suffix.lower()
    language = "CL" if suffix in (".clle", ".clp", ".cl", ".cllp", ".clle38") else "RPG"
    stripped = _strip_rpg_comments(text)
    seen: set = set()
    out = run_rules(file_path=file_path, repo_root=repo_root, text=stripped, rules=_RULES, language=language, scanner_id=SCANNER_ID,
                    confidence_reason="ibm-i-crypto-api", strip_comments=False, seen=seen)
    if re.search(r"\bEXEC\s+SQL\b", stripped, re.I):
        from scanner.parsers.sql_parser import _RULES as _SQL_RULES

        out += run_rules(file_path=file_path, repo_root=repo_root, text=stripped, rules=_SQL_RULES, language=language, scanner_id=SCANNER_ID,
                         confidence_reason="embedded-sql", strip_comments=False, seen=seen)
    _resolve_unknowns(text, out)  # comments are legitimate evidence for the algorithm name
    out += _expand_ibm_i_suites(file_path, repo_root, out, language)
    return out


_IBM_I_C_MARKER = re.compile(r"\bQc3[A-Z]\w+|\bQC3[A-Z]{5}\b|\bgsk_\w+|\bGSK_[A-Z0-9_]+")


def scan_ibm_i_in_c(file_path: Path, repo_root: Path | None, text: str, seen: set | None = None) -> list[RawFinding]:
    """ILE C / C++ on IBM i calls the same Qc3 / GSKit APIs (``QC3CALHA(...)``, ``gsk_environment_open``).

    Called by the registry after the generic C parser when the file mentions those APIs.
    """
    if not _IBM_I_C_MARKER.search(text):
        return []
    out = run_rules(file_path=file_path, repo_root=repo_root, text=text, rules=_RULES, language="C", scanner_id=SCANNER_ID,
                    confidence_reason="ibm-i-crypto-api", strip_comments=True, seen=seen if seen is not None else set())
    _resolve_unknowns(text, out)
    return out
