"""COBOL / mainframe crypto detector — IBM ICSF callable services (CSNB*/CSND*/CSNE*/CSNF*),
CCA verbs, PKCS#11 via ICSF (CSFP*), Encryption Facility, z/OS RACF password
algorithms, plus the rule-array literals that select the algorithm.

Core-banking cores are still COBOL (CICS/IMS/batch) and their cryptography is
almost entirely ICSF: PIN verification (CSNBPVR), CVV (CSNBCVV), key management
(CSNBKGN/KTB/KIM), data encryption (CSNBENC/CSNBSYE), MACs (CSNBMGN/CSNBHMG),
digests (CSNBOWH) and RSA/ECC (CSNDDSG/CSNDPKE). The verb fixes the family; the
rule array (a padded 8-byte literal such as ``'SHA-256 '``) fixes the algorithm.

Deliberately not reported: ``RECORD KEY`` / ``ALTERNATE KEY`` / ``SEARCH ... KEY IS``
(VSAM/table keys), ``PIC`` clauses that merely name a field ``PASSWORD``, ``HASH``
partitioning, EBCDIC/Base64 conversion, ``FUNCTION RANDOM`` outside a secret context.

Call shapes: ``CALL 'name'``, ``LINK  EP=name``, the HLASM macro form (the service name
as mnemonic, e.g. ``CSNBSYE  (RC,RS,...)``), ``SVC`` routines named after the service,
address-constant linkage (``LA R15,=V(CSNBSYG)``) and ``LINK  EPLOC=field`` resolved
through ``field  DC  CL8'CSNxxxx'``.  Register-indirect targets (``CALL (R3)`` /
``LINK EPLOC=(Rn)``) are not tracked: a service invoked through a register is reported
as unexamined, never as "no cryptography".  A service name in the label field followed
by ``DC``/``DS``/``EQU`` is a definition, not a call.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-cobol-scanner-v1.0"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.IGNORECASE), {**base, "library": library, **extra}


# --------------------------------------------------------------------------------------
# Statement-shape prefixes.  Every form below names the ICSF service in the statement
# itself; register-indirect targets (CALL (R3) / LINK EPLOC=(R3) / a name assembled at
# run time) are deliberately NOT guessed at — those files are reported as unexamined,
# never as "no cryptography".
#   CALL       CALL 'CSNBSYE' / CALL "CSNESYE" / CALL CSNBSYE-NAME
#   LINK       LINK  EP=CSNxxx — entry point named directly
#   macro      the service name is the assembler mnemonic (with or without a label):
#              CSNBSYE  (RC,RS,...) / PANPTR   CSNBPTR  (...)
#   SVC        ICSF routine via SVC — service name in the label field: CSNBMGN  SVC  255
#   V/A const  address-constant linkage: LA  R15,=V(CSNBSYG) — NOT a DC V(...) declaration
# LINK EPLOC=field is rewritten to EP='service' by _resolve_hlasm_eploc() below when the
# same source defines field as DC CL8'CSNxxx'.
_SOL = r"(?:(?<=\n)|\A)"  # start of line without re.M (inline flags must lead a pattern)
_PFX_CALL = r"\bCALL\s+['\"]?"
_PFX_LINK = r"\bLINK\b[^,\n]{0,60}\bEP(?:LOC)?\s*=\s*['\"]?"
_PFX_MACRO = _SOL + r"(?:[ \t]{2,12}|[A-Z@#$][A-Z0-9@#$]{0,7}[ \t]{1,12})"
_PFX_SVC = _SOL + r"[ \t]{0,8}(?=CSN[BDEF][A-Z0-9]{0,5}\b[ \t]{1,12}SVC\b)"
_PFX_VADDR = _SOL + r"[ \t]{0,12}(?:[A-Z@#$][A-Z0-9@#$]{0,7}[ \t]{1,12})?(?:LLGF|LLC|LLH|BASSM|BALR|BRASL|BRAS|BAS|BAL|LA|LG|LH|L)\b[^\n]{0,80}?[=]?(?:V|A)\(\s*['\"]?"
_PFX = rf"(?:{_PFX_CALL}|{_PFX_LINK}|{_PFX_MACRO}|{_PFX_SVC}|{_PFX_VADDR})"
_V = _PFX + r"CSN[BE]"   # CSNB* (31-bit) / CSNE* (64-bit) symmetric & PIN services
_VD = _PFX + r"CSN[DF]"  # CSND* / CSNF* PKA (RSA / ECC) services
_ICSF = "IBM-ICSF"
_RULE_LIT = r"['\"]"

_RULES: list[Rule] = [
    # ------------------------------------------------------------- symmetric data encryption
    _r(_V + r"(SYE|SYD|SAE|SAD)\b", _C, _ICSF, algorithm="AES", confidence="MEDIUM", confidence_reason="Symmetric Algorithm Encipher/Decipher — AES (DES via rule array)"),
    _r(_V + r"(ENC|DEC|CTT|CTT2|CTT3)\b", _C, _ICSF, algorithm="3DES", confidence="MEDIUM", confidence_reason="Encipher/Decipher/Ciphertext Translate — DES/TDES data keys"),
    _r(_V + r"(SYG)\b", _C, _ICSF, algorithm="AES", confidence="MEDIUM", confidence_reason="Symmetric Key Generate (AES/DES)"),
    _r(_V + r"(FPEE|FPED|FPET)\b", _C, _ICSF, algorithm="AES", confidence="HIGH", confidence_reason="Format-preserving encryption (VISA FPE / FF1 — AES based)"),
    _r(_V + r"(FLE|FLD)\b", _C, _ICSF, algorithm="AES", confidence="LOW", confidence_reason="Field Level Encipher (AES or DES by rule array)"),
    # ------------------------------------------------------------- digests / MACs
    _r(_V + r"(OWH|OWH1)\b", _D, _ICSF, algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="One-Way Hash — algorithm selected by the rule array literal"),
    _r(_V + r"(HMG|HMV)\b", _M, _ICSF, algorithm="HMAC", confidence="HIGH", confidence_reason="HMAC Generate/Verify — digest from rule array"),
    _r(_V + r"(MGN|MVR|MGN1|MGN2|MVR1|MVR2)\b", _M, _ICSF, algorithm="3DES", confidence="MEDIUM", confidence_reason="MAC Generate/Verify (ISO 9797 DES/TDES MAC unless AES CMAC rule)"),
    _r(_V + r"(SMG|SMV)\b", _M, _ICSF, algorithm="AES", mode="CMAC", confidence="HIGH", confidence_reason="Symmetric MAC Generate/Verify — AES CMAC"),
    _r(_V + r"(MDG)\b", _D, _ICSF, algorithm="MD5", confidence="MEDIUM", confidence_reason="MDC generate (DES-based modification detection code)"),
    # ------------------------------------------------------------- PIN / card verification (payments)
    _r(_V + r"(PGN|PVR|PTR|PTRE|EPB|CPE|CPA|PEX|PEXX|PIN|SPN|PBK|PCU|PFO|DPC|DPCG|DPMT|EPG|PVV|POW)\b", _C, _ICSF, algorithm="3DES", confidence="HIGH", confidence_reason="PIN block generate/translate/verify (TDES PIN keys; format 4 is AES)"),
    _r(_V + r"(PCN|PTRA|PTRE2|EPB2|PFO2)\b|\bISO-?4\b(?=[^\n]*PIN)|\bPINBLOCK-?FORMAT-?4\b|\bISO4\s+PIN\b", _C, _ICSF, algorithm="AES", confidence="HIGH", confidence_reason="ISO 9564 format-4 PIN block (AES)"),
    _r(_V + r"(CVG|CVV|CSG|CSV|DCM|DDC|ASC|ASV|TRV)\b", _M, _ICSF, algorithm="3DES", confidence="HIGH", confidence_reason="VISA CVV / CVC / iCVV generate-verify (TDES CVK)"),
    _r(_V + r"(AEV|ARGV|ARPC|EAC|EMVH|RCC)\b|\bEMV\s+(?:ARQC|ARPC|CRYPTOGRAM)\b", _M, _ICSF, algorithm="3DES", confidence="HIGH", confidence_reason="EMV cryptogram verification / ARPC generation (TDES session keys)"),
    _r(_V + r"(TRX)\b|\bZKA\b(?=[^\n]*(?:PIN|MAC|KEY))", _C, _ICSF, algorithm="3DES", confidence="MEDIUM"),
    # ------------------------------------------------------------- symmetric key management (CCA DES/AES key tokens)
    _r(_V + r"(KGN|KGN2|KTB|KTB2|KIM|KEX|KTR|KTR2|KYT|KYT2|KYTX|KPI|KPI2|KRC|KRC2|KRD|KRR|KRR2|KRW|KRW2|CKM|CKI|CKC|DKG|DKG2|DKM|DKX|SKI|SKI2|SKY|SKM|SBC|SBD|TBC|KET|KTP|KTP2|RKA|RKX|CVE|CVT|KDSL|RKL|PKX|MKP|MKP1|CKX|PCK|PKI|PKM)\b",
       _K, _ICSF, algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="CCA key token generate/import/export — DES or AES per key type literal"),
    _r(r"\b(?:DES|TDES|3DES)\s*-?\s*(?:KEY|KEK|DATA|PIN|MAC|EXPORTER|IMPORTER|IPINENC|OPINENC|PINGEN|PINVER|CIPHER)\b|\bKEY-?TYPE\b[^\n]*['\"](?:DATA|EXPORTER|IMPORTER|IPINENC|OPINENC|PINGEN|PINVER|MAC|MACVER|CIPHER|DECIPHER|ENCIPHER|CVARENC|DKYGENKY)\s*['\"]",
       _K, _ICSF, algorithm="3DES", confidence="MEDIUM", confidence_reason="CCA DES key type"),
    _r(r"\b(?:AES)\s*-?\s*(?:KEY|KEK|DATA|CIPHER|MAC|EXPORTER|IMPORTER|PINCALC|PINPROT|PINPRW|DKYGENKY)\b|\bKEY-?TYPE\b[^\n]*['\"](?:AESDATA|AESKEK|AESCIPHER|AESMAC|AESEXPORTER|AESIMPORTER)\s*['\"]|['\"]INTERNAL[ '\"][^\n]*['\"]AES\s*['\"]",
       _K, _ICSF, algorithm="AES", confidence="MEDIUM", confidence_reason="CCA AES key type"),
    _r(r"\bTR-?31\b|\bTR31\b|\bKEY-?BLOCK\b(?=[^\n]*(?:TR|IMPORT|EXPORT|WRAP))|\bKBPK\b", _K, _ICSF, algorithm="AES", confidence="LOW", confidence_reason="TR-31 key block (wrapped under TDES or AES KBPK)"),
    _r(r"\bDUKPT\b|\bKSN\b(?=[^\n]*(?:PIN|BDK|KEY))|\bBDK\b", _K, _ICSF, algorithm="3DES", confidence="MEDIUM", confidence_reason="DUKPT (TDES; AES DUKPT is X9.24-3)"),
    # ------------------------------------------------------------- RSA / ECC (CSND*)
    _r(_VD + r"(PKG|PKB|PKI|PKX|PKE|PKD|PKT|PKT2|PKTC|PKH|PKR|PKRC|PKRD|PKRR|PKRW|SYX|SYI|SYI2|SYG|SXD|SBC|SBD|SPKB|EDH|TBC|TBD|RKD|RKX|KTC|KTC2|DSG|DSV|RKL|PKRC|SYI2)\b",
       _S, _ICSF, algorithm="RSA", confidence="MEDIUM", confidence_reason="PKA callable service — RSA unless the rule array says ECC/ECDSA"),
    _r(r"['\"](?:ECC-PAIR|ECDSA|ECC)\s*['\"]|\bBRAINPOOL\b|\bPRIME-?256\b|\bPRIME-?384\b|\bPRIME-?521\b|\bP-?256\s+ECC\b", _S, _ICSF, algorithm="ECDSA", confidence="HIGH", confidence_reason="PKA rule-array ECC keyword"),
    _r(r"['\"](?:RSA-CRT|RSA-AESC|RSA-AESM|RSA-PRIV|RSA-PUBL|RSA-OPT|RSAMEVAR|PKCS-1\.[012]|PKCS-PSS|ZERO-PAD|X9\.31)\s*['\"]", _S, _ICSF, algorithm="RSA", confidence="HIGH", confidence_reason="PKA rule-array RSA keyword"),
    _r(r"['\"]PKOAEP2?\s*['\"]", _C, _ICSF, algorithm="RSA", confidence="HIGH", confidence_reason="RSA-OAEP key wrapping"),
    # ------------------------------------------------------------- rule-array algorithm literals (padded 8-byte keywords)
    _r(r"['\"](SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|SHA1|SHA256|SHA384|SHA512|MD5|RPMD-160|MDC-2|MDC-4|MDC-2PAD|MDC-4PAD|SHA3-256|SHA3-512|SHAKE128|SHAKE256)\s*['\"]", _D, "ICSF rule array", algo_from_group=1,
       algo_map={"sha-1": "SHA-1", "sha1": "SHA-1", "sha-224": "SHA-224", "sha-256": "SHA-256", "sha256": "SHA-256", "sha-384": "SHA-384", "sha384": "SHA-384", "sha-512": "SHA-512", "sha512": "SHA-512",
                 "md5": "MD5", "rpmd-160": "RIPEMD-160", "mdc-2": "MDC-2", "mdc-4": "MDC-4", "mdc-2pad": "MDC-2", "mdc-4pad": "MDC-4", "sha3-256": "SHA3-256", "sha3-512": "SHA3-512", "shake128": "SHAKE128", "shake256": "SHAKE256"}),
    _r(r"['\"](AES|DES|TDES|TDES-CBC|TDES-ECB|DES-CBC|DES-ECB|AES-CBC|AES-ECB|AES-GCM|AES-CTR|AES-CFB|AES-OFB|AES-XTS|CBC|ECB|CFB|OFB|GCM|X9\.23|PKCS-PAD|CUSP|IPS|ISO-0|ISO-1|ISO-2|ISO-3|ISO-4|ISO4|VISA-3|VISA-4|ANSIX9\.8|ECI-2|ECI-3|IBM-PIN|IBM-PINO|VISA-PVV|VISAPVV4|GBP-PIN|GBP-PINO|CVV-1|CVV-2|CVV-3|ICVV|CVC3|ARQC|ARPC|CMAC|HMAC)\s*['\"](?=[^\n]*)",
       _C, "ICSF rule array", algo_from_group=1, confidence="MEDIUM",
       algo_map={"aes": "AES", "aes-cbc": "AES", "aes-ecb": "AES", "aes-gcm": "AES", "aes-ctr": "AES", "aes-cfb": "AES", "aes-ofb": "AES", "aes-xts": "AES", "des": "DES", "tdes": "3DES", "tdes-cbc": "3DES", "tdes-ecb": "3DES", "des-cbc": "DES", "des-ecb": "DES",
                 "iso-0": "3DES", "iso-1": "3DES", "iso-2": "3DES", "iso-3": "3DES", "iso-4": "AES", "iso4": "AES", "visa-3": "3DES", "visa-4": "3DES", "ansix9.8": "3DES", "eci-2": "3DES", "eci-3": "3DES",
                 "ibm-pin": "3DES", "ibm-pino": "3DES", "visa-pvv": "3DES", "visapvv4": "3DES", "gbp-pin": "3DES", "gbp-pino": "3DES", "cvv-1": "3DES", "cvv-2": "3DES", "cvv-3": "3DES", "icvv": "3DES", "cvc3": "3DES", "arqc": "3DES", "arpc": "3DES",
                 "cmac": "AES", "hmac": "HMAC"}),
    # ------------------------------------------------------------- KGUP control statements (CSFIN: ADD/UPDATE LABEL(...) TYPE(...) ALGORITHM(...))
    _r(r"\b(?:ADD|UPDATE|RENAME)\b[^\n]*\bLABEL\([^)]+\)[^\n]*\bALGORITHM\((AES|DES)\)", _K, "IBM-ICSF-KGUP", algo_from_group=1, algo_map={"aes": "AES", "des": "3DES"}, confidence="HIGH", confidence_reason="KGUP key generation statement (DES algorithm = TDES CKDS key)"),
    _r(r"\b(?:ADD|UPDATE)\b[^\n]*\bLABEL\([^)]+\)(?![^\n]*\bALGORITHM\()[^\n]*\bTYPE\((?:EXPORTER|IMPORTER|IKEYXLAT|OKEYXLAT|PINGEN|PINVER|IPINENC|OPINENC|MAC|MACVER|DATAXLAT|CVARENC|CVARPINE|CVARXCVL|CVARXCVR|DATAM|DATAMV|DKYGENKY|KEYGENKY|CIPHER|DECIPHER|ENCIPHER|DATA)\)", _K, "IBM-ICSF-KGUP", algorithm="3DES", confidence="HIGH", confidence_reason="KGUP CKDS key type without ALGORITHM(AES) is a DES/TDES key"),
    # ------------------------------------------------------------- randomness
    _r(_V + r"(RNG|RNGL|RNG2)\b", _RNG, _ICSF, algorithm="CSPRNG", confidence="HIGH", confidence_reason="ICSF Random Number Generate (hardware DRBG)"),
    _r(r"\bFUNCTION\s+RANDOM\b(?=[^\n]*(?:PASS|PWD|SECRET|TOKEN|SALT|OTP|PIN|NONCE|SESSION))|\b[\w-]*?-?(?:PASS\w*|PWD|SECRET|TOKEN|SALT|OTP|PIN|NONCE|SESSION-?ID)\b[^\n]*\bFUNCTION\s+RANDOM\b", _RNG, "cobol-intrinsic", algorithm="PRNG", confidence="HIGH", confidence_reason="FUNCTION RANDOM is not cryptographically secure"),
    # ------------------------------------------------------------- PKCS#11 via ICSF (CSFP*) and Encryption Facility
    _r(_PFX + r"CSFP(?:GKP|GSK|PKS|PKV|PKE|PKD|HMG|HMV|OWH|SKE|SKD|PRF|TRC|TRD|TRL|WPK|UWK|DVK|GAV|SAV|TRL|SKI|SKE|DMK|GAV)\b", _K, "IBM-ICSF-PKCS11", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="ICSF PKCS#11 callable service — mechanism from CK_MECHANISM literal"),
    _r(r"\bCKM[-_](AES|DES3|DES|RSA|ECDSA|EC|SHA1|SHA256|SHA384|SHA512|MD5)[-_]?\w*", _C, "IBM-ICSF-PKCS11", algo_from_group=1,
       algo_map={"aes": "AES", "des3": "3DES", "des": "DES", "rsa": "RSA", "ecdsa": "ECDSA", "ec": "ECDSA", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}),
    _r(r"\bCSDFILEN\b|\bCSDFILDE\b|\bENCRYPTION\s+FACILITY\b|\bCSDFENC\b|\bCSDFDEC\b", _C, "IBM-Encryption-Facility", algorithm="AES", confidence="LOW", confidence_reason="Encryption Facility for z/OS (AES or TDES by parameter)"),
    _r(r"\bCSFEUTIL\b|\bCSFKGUP\b|\bCSFCONV\b|\bCSFPUTIL\b", _K, _ICSF, algorithm="UNKNOWN", confidence="LOW", confidence_reason="ICSF master-key / CKDS utility"),
    _r(r"\bCKDS\b|\bPKDS\b|\bTKDS\b|\bCSFKEYS\b|\bCSFSERV\b", _K, _ICSF, algorithm="UNKNOWN", confidence="LOW", confidence_reason="ICSF key data set / RACF class reference"),
    # ------------------------------------------------------------- RACF / z/OS password hashing
    _r(r"\bKDFAES\b", _KDF, "RACF", algorithm="AES", confidence="HIGH", confidence_reason="RACF KDFAES password algorithm (PBKDF2 + AES)"),
    _r(r"\bRACF\b[^\n]*\bDES\b|\bPASSWORD\s*\(\s*ALGORITHM\s*\(\s*(?:DES|LEGACY)\s*\)|\bALGORITHM\s*\(\s*(?:DES|LEGACY)\s*\)(?=[^\n]*PASSWORD)|\bNOALGORITHM\b", _KDF, "RACF", algorithm="DES", confidence="MEDIUM", confidence_reason="RACF legacy DES password masking"),
    _r(r"\bICHDEX01\b|\bICHEINTY\b", _KDF, "RACF", algorithm="DES", confidence="LOW", confidence_reason="RACF password encryption exit"),
    # ------------------------------------------------------------- DB2 for z/OS / CICS in COBOL
    _r(r"\bENCRYPT_TDES\s*\(", _C, "db2-zos", algorithm="3DES", confidence="HIGH"),
    _r(r"\bENCRYPT_AES\s*\(|\bDECRYPT_(?:CHAR|BIN|BIT|DB)\s*\(", _C, "db2-zos", algorithm="AES", confidence="HIGH"),
    _r(r"\bAT-?TLS\b|\bTTLS\b|\bSSL\s+YES\b|\bCICS\s+SSL\b|\bKEYRING\b", {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}, "zOS-AT-TLS", algorithm="TLS", confidence="MEDIUM"),
]


def _strip_hlasm_comments(text: str) -> str:
    """HLASM: ``*`` or ``.*`` in column 1 is a comment line; columns 73-80 are the identification area."""
    out = []
    for line in text.split("\n"):
        if line.startswith("*") or line.startswith(".*"):
            out.append(" " * len(line))
            continue
        if len(line) > 72:
            line = line[:72] + " " * (len(line) - 72)
        out.append(line)
    return "\n".join(out)


def _strip_cobol_comments(text: str) -> str:
    """Blank fixed-format comment lines (``*`` or ``/`` in column 7), floating ``*>`` comments and
    the sequence-number area (columns 1-6 / 73-80) that can contain arbitrary text."""
    out = []
    for line in text.split("\n"):
        if len(line) >= 7 and line[6] in "*/":
            out.append(" " * len(line))
            continue
        if len(line) > 72 and not line.lstrip().startswith(("*", "*>")):
            # fixed-format: keep columns 7-72, blank the identification area
            line = line[:72] + " " * (len(line) - 72)
        idx = line.find("*>")
        if idx >= 0:
            line = line[:idx] + " " * (len(line) - idx)
        out.append(line)
    return "\n".join(out)


_EPLOC_REF = re.compile(r"\bLINK\b([^\n]{0,60}?)\bEPLOC\s*=\s*['\"]?([A-Z@#$][A-Z0-9@#$]{0,7})", re.IGNORECASE)
_ENTRY_DC = re.compile(r"^[ \t]{0,8}([A-Z@#$][A-Z0-9@#$]{0,7})[ \t]+DC[ \t]+CL\s*8\s*['\"]((?:CSN[BDEF]|CSFP)[A-Z0-9]{2,5})['\"]",
                       re.IGNORECASE | re.MULTILINE)


def _resolve_hlasm_eploc(text: str) -> str:
    """Rewrite ``LINK  EPLOC=field`` to ``LINK  EP='CSNxxxx'`` when the same source defines
    ``field  DC  CL8'CSNxxxx'``.  A register-indirect ``EPLOC=(Rn)`` is not tracked — the
    honest answer for those is "unexamined", never "no cryptography"."""
    defs = {m.group(1).upper(): m.group(2).upper() for m in _ENTRY_DC.finditer(text)}
    if not defs:
        return text

    def _sub(m: re.Match) -> str:
        svc = defs.get(m.group(2).upper())
        return f"LINK{m.group(1)}EP='{svc}'" if svc else m.group(0)

    return _EPLOC_REF.sub(_sub, text)


def parse_cobol_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if file_path.suffix.lower() == ".asm":
        text = _resolve_hlasm_eploc(_strip_hlasm_comments(text))
    body = _strip_cobol_comments(text) if file_path.suffix.lower() != ".asm" else text
    findings = run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=body,
        rules=_RULES,
        language="COBOL",
        scanner_id=SCANNER_ID,
        confidence_reason="icsf-callable-service",
        strip_comments=False,
    )
    # A bare 3-letter 'DES' / 'AES' literal (PIC X(3) VALUE 'DES' — a DESK / description code) only names an algorithm
    # when the program actually talks to ICSF / an HSM: rule arrays, callable services, key labels or key data sets.
    if not _ICSF_SHAPE.search(body):
        findings = [f for f in findings if not (f.crypto.algorithm in {"DES", "AES"} and f.metadata is not None and f.metadata.library == "ICSF rule array"
                                                 and re.fullmatch(r"['\"](?:DES|AES)['\"]", (f.crypto.raw_transformation or "").strip()))]
    return findings


_ICSF_SHAPE = re.compile(r"\bCSN[BDEF][A-Z0-9]{2,4}\b|\bCSFP[A-Z0-9]{2,4}\b|\bICSF\b|\bRULE-?ARRAY\b|\bRULE-?COUNT\b|\bKEY-?LABEL\b|\bKEY-?IDENT\b|\bCKDS\b|\bPKDS\b|\bKEY-?TOKEN\b|\bCRYPTO\b|\bENCRYPT|\bDECRYPT|\bHSM\b|\bZPK\b|\bZMK\b|\bPIN-?BLOCK\b", re.I)
