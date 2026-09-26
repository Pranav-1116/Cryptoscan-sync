"""Key & certificate inventory ingestion — what the HSMs, KMSs and keystores actually hold.

Source-code scanning sees keys only where code *references* them. A bank's key estate lives in
ICSF key data sets, payShield LMK-encrypted key blocks, Luna/nShield/Utimaco partitions, cloud KMS,
Vault and keystores. Each of those can export a listing; this parser turns those exports into
findings (``source.type = KEY_INVENTORY``) with algorithm, key size, label, usage, state and dates,
so the inventory, the policy engine and the cascade see the *keys* and not just the calls.

Formats (all detected by content, not by file name):

* **ICSF** CKDS / PKDS / TKDS listings (KGUP ``LIST``, ``CSFKDSL``, panel exports, CSV) — LABEL, TYPE,
  ALGORITHM, key length, dates
* **TR-31 / ANSI X9.143 key-block headers** anywhere in a file (payShield, Atalla, Futurex, SafeNet
  exports) — version, usage, algorithm, mode, exportability
* **Thales Luna** ``cmu list`` / ``partition contents`` — label, object type, key size
* **Entrust nShield** ``nfkminfo -l`` / ``kmfile-dump`` — app / ident / type / size
* **Utimaco** ``csadm ListKeys`` and generic **PKCS#11** ``pkcs11-tool --list-objects``
* **AWS KMS** ``list-keys`` + ``describe-key`` JSON, **Azure Key Vault** ``az keyvault key list``,
  **GCP KMS** ``gcloud kms keys list --format=json``, **HashiCorp Vault** transit key JSON
* **Java keytool** ``-list -v`` and **RACDCERT LIST** (certificates: key algorithm, size, signature
  algorithm, validity)
* **openssl x509 -text** / certificate CSV exports (Venafi, AppViewX, DigiCert)

Nothing here reads key *values*; only metadata. Opt-in: ``CRYPTOSCAN_KEY_INVENTORY=1`` for the tree
walk, or ``scripts/ingest_key_inventory.py`` for a bank-provided drop folder.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "key-inventory-ingest-v1.0"
KEY_INVENTORY_EXT = {".kinv", ".keyinv", ".ckds", ".pkdsl", ".ckdsl"}
KEY_INVENTORY_ENV = "CRYPTOSCAN_KEY_INVENTORY"
SNIFF_EXT = {".txt", ".lst", ".out", ".json", ".csv", ".log", ".rpt", ".prt", ".list", ".dump"}

_K = ("KEY_PAIR_GENERATOR", "KEY_MANAGEMENT")
_S = ("KEY_GENERATOR", "KEY_MANAGEMENT")
_X = ("KEY_PAIR_GENERATOR", "CERTIFICATE_MANAGEMENT")

# ------------------------------------------------------------------------------------ vocabularies
_ICSF_TYPE = {
    "DATA": "3DES", "DATAXLAT": "3DES", "CIPHER": "3DES", "CIPHERXI": "3DES", "CIPHERXL": "3DES", "CIPHERXO": "3DES",
    "MAC": "3DES", "MACVER": "3DES", "PINGEN": "3DES", "PINVER": "3DES", "IPINENC": "3DES", "OPINENC": "3DES",
    "EXPORTER": "3DES", "IMPORTER": "3DES", "IKEYXLAT": "3DES", "OKEYXLAT": "3DES", "DKYGENKY": "3DES", "KEYGENKY": "3DES",
    "SECMSG": "3DES", "CVARENC": "3DES", "CVARXCVL": "3DES", "CVARXCVR": "3DES", "CVARPINE": "3DES",
    "AESDATA": "AES", "AES DATA": "AES", "AESCIPHER": "AES", "AES CIPHER": "AES", "AESMAC": "AES", "AES MAC": "AES",
    "AESEXPORTER": "AES", "AES EXPORTER": "AES", "AESIMPORTER": "AES", "AES IMPORTER": "AES", "AESPINCALC": "AES", "AESPINPROT": "AES",
    "AESPINPRW": "AES", "AESDKYGENKY": "AES", "AES DKYGENKY": "AES", "AESKEK": "AES",
    "HMAC": "HMAC", "CLRDES": "3DES", "CLRAES": "AES", "NULL": None,
    "RSA": "RSA", "RSA-CRT": "RSA", "RSA-AESC": "RSA", "RSA-AESM": "RSA", "ECC": "ECDSA", "ECC-AESC": "ECDSA", "QSA": "ML-DSA",
    "ML-DSA": "ML-DSA", "ML-KEM": "ML-KEM", "DILITHIUM": "ML-DSA", "CRYSTALS-DILITHIUM": "ML-DSA", "CRYSTALS-KYBER": "ML-KEM",
}
_ICSF_ALG = {"DES": "3DES", "TDES": "3DES", "3DES": "3DES", "AES": "AES", "HMAC": "HMAC", "RSA": "RSA", "ECC": "ECDSA", "EC": "ECDSA",
             "ECDSA": "ECDSA", "EDDSA": "ED25519", "ED25519": "ED25519", "ML-DSA": "ML-DSA", "ML-KEM": "ML-KEM", "QSA": "ML-DSA"}

# TR-31 header: version(1) length(4) usage(2) algorithm(1) mode(1) key-version(2) exportability(1) num-opt(2) reserved(2)
_TR31 = re.compile(r"(?<![A-Za-z0-9])([ABCD])(\d{4})([A-Z0-9]{2})([ADEHRST])([BCDEGNSTVXY])([A-Z0-9]{2})([ENS])(\d{2})(00|[0-9A-Z]{2})(?=[0-9A-F]{16,}|\b)")
_TR31_ALG = {"A": "AES", "D": "DES", "E": "ECDSA", "H": "HMAC", "R": "RSA", "S": "DSA", "T": "3DES"}
_TR31_USAGE = {
    "B0": "BDK (DUKPT base derivation)", "B1": "DUKPT initial key", "B2": "BDK (asymmetric)", "C0": "CVK (card verification)", "D0": "data encryption (symmetric)",
    "D1": "data encryption (asymmetric)", "D2": "data decryption", "E0": "EMV/chip issuer master key (application cryptogram)", "E1": "EMV IMK (secure messaging confidentiality)",
    "E2": "EMV IMK (secure messaging integrity)", "E3": "EMV IMK (data authentication)", "E4": "EMV IMK (dynamic numbers)", "E5": "EMV card personalisation",
    "E6": "EMV other", "E7": "EMV IMK (PIN)", "I0": "initialisation vector", "K0": "key encryption / wrapping", "K1": "TR-31 key block protection", "K2": "TR-34 asymmetric key",
    "K3": "asymmetric key agreement/wrapping", "M0": "ISO 16609 MAC (algorithm 1)", "M1": "ISO 9797-1 MAC algorithm 1", "M2": "ISO 9797-1 MAC algorithm 2", "M3": "ISO 9797-1 MAC algorithm 3",
    "M4": "ISO 9797-1 MAC algorithm 4", "M5": "ISO 9797-1 MAC algorithm 5", "M6": "ISO 9797-1 MAC algorithm 5 / CMAC", "M7": "HMAC", "M8": "ISO 9797-1 MAC algorithm 6",
    "P0": "PIN encryption", "P1": "PIN generation", "S0": "asymmetric signature", "S1": "asymmetric key agreement", "S2": "asymmetric CA", "V0": "PIN verification (KPV)",
    "V1": "PIN verification IBM 3624", "V2": "PIN verification VISA PVV", "V3": "PIN verification X9.132 alg 1", "V4": "PIN verification X9.132 alg 2",
}
_TR31_MODE = {"B": "encrypt+decrypt/wrap+unwrap", "C": "MAC generate+verify", "D": "decrypt/unwrap only", "E": "encrypt/wrap only", "G": "MAC generate only", "N": "no special restrictions",
              "S": "signature only", "T": "sign + decrypt", "V": "MAC verify only", "X": "key derivation", "Y": "key variant creation"}
_TR31_EXPORT = {"E": "exportable under trusted key", "N": "non-exportable", "S": "sensitive (exportable under any KEK)"}

_LUNA_TYPE = {"RSA": "RSA", "EC": "ECDSA", "ECDSA": "ECDSA", "AES": "AES", "DES3": "3DES", "DES2": "3DES", "DES": "DES", "GENERIC": "HMAC", "GENERIC_SECRET": "HMAC",
              "HMAC": "HMAC", "DSA": "DSA", "DH": "DH", "ED25519": "ED25519", "X25519": "X25519", "ML-DSA": "ML-DSA", "ML-KEM": "ML-KEM", "SM2": "SM2", "SM4": "SM4", "ARIA": "ARIA", "SEED": "SEED", "RC4": "RC4", "RC2": "RC2"}
_CLOUD_SPEC = {
    # AWS KMS KeySpec / CustomerMasterKeySpec
    "SYMMETRIC_DEFAULT": ("AES", 256), "RSA_2048": ("RSA", 2048), "RSA_3072": ("RSA", 3072), "RSA_4096": ("RSA", 4096),
    "ECC_NIST_P256": ("ECDSA", 256), "ECC_NIST_P384": ("ECDSA", 384), "ECC_NIST_P521": ("ECDSA", 521), "ECC_SECG_P256K1": ("ECDSA", 256),
    "HMAC_224": ("HMAC", 224), "HMAC_256": ("HMAC", 256), "HMAC_384": ("HMAC", 384), "HMAC_512": ("HMAC", 512), "SM2": ("SM2", 256),
    "ML_DSA_44": ("ML-DSA", 44), "ML_DSA_65": ("ML-DSA", 65), "ML_DSA_87": ("ML-DSA", 87),
    # GCP KMS versionTemplate.algorithm
    "GOOGLE_SYMMETRIC_ENCRYPTION": ("AES", 256), "AES_128_GCM": ("AES", 128), "AES_256_GCM": ("AES", 256), "AES_128_CBC": ("AES", 128), "AES_256_CBC": ("AES", 256),
    "AES_128_CTR": ("AES", 128), "AES_256_CTR": ("AES", 256),
    "RSA_SIGN_PSS_2048_SHA256": ("RSA-PSS", 2048), "RSA_SIGN_PSS_3072_SHA256": ("RSA-PSS", 3072), "RSA_SIGN_PSS_4096_SHA256": ("RSA-PSS", 4096), "RSA_SIGN_PSS_4096_SHA512": ("RSA-PSS", 4096),
    "RSA_SIGN_PKCS1_2048_SHA256": ("RSA", 2048), "RSA_SIGN_PKCS1_3072_SHA256": ("RSA", 3072), "RSA_SIGN_PKCS1_4096_SHA256": ("RSA", 4096), "RSA_SIGN_PKCS1_4096_SHA512": ("RSA", 4096),
    "RSA_SIGN_RAW_PKCS1_2048": ("RSA", 2048), "RSA_SIGN_RAW_PKCS1_3072": ("RSA", 3072), "RSA_SIGN_RAW_PKCS1_4096": ("RSA", 4096),
    "RSA_DECRYPT_OAEP_2048_SHA256": ("RSA-OAEP", 2048), "RSA_DECRYPT_OAEP_3072_SHA256": ("RSA-OAEP", 3072), "RSA_DECRYPT_OAEP_4096_SHA256": ("RSA-OAEP", 4096),
    "RSA_DECRYPT_OAEP_4096_SHA512": ("RSA-OAEP", 4096), "RSA_DECRYPT_OAEP_2048_SHA1": ("RSA-OAEP", 2048), "RSA_DECRYPT_OAEP_3072_SHA1": ("RSA-OAEP", 3072), "RSA_DECRYPT_OAEP_4096_SHA1": ("RSA-OAEP", 4096),
    "EC_SIGN_P256_SHA256": ("ECDSA", 256), "EC_SIGN_P384_SHA384": ("ECDSA", 384), "EC_SIGN_SECP256K1_SHA256": ("ECDSA", 256), "EC_SIGN_ED25519": ("ED25519", 255),
    "HMAC_SHA256": ("HMAC", 256), "HMAC_SHA1": ("HMAC", 160), "HMAC_SHA384": ("HMAC", 384), "HMAC_SHA512": ("HMAC", 512), "HMAC_SHA224": ("HMAC", 224),
    "PQ_SIGN_ML_DSA_65": ("ML-DSA", 65), "PQ_SIGN_SLH_DSA_SHA2_128S": ("SLH-DSA", 128), "PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256": ("SLH-DSA", 128),
    # Vault transit
    "aes128-gcm96": ("AES", 128), "aes256-gcm96": ("AES", 256), "chacha20-poly1305": ("ChaCha20-Poly1305", 256), "xchacha20-poly1305": ("ChaCha20-Poly1305", 256),
    "ed25519": ("ED25519", 255), "ecdsa-p256": ("ECDSA", 256), "ecdsa-p384": ("ECDSA", 384), "ecdsa-p521": ("ECDSA", 521),
    "rsa-2048": ("RSA", 2048), "rsa-3072": ("RSA", 3072), "rsa-4096": ("RSA", 4096), "hmac": ("HMAC", 256), "managed_key": ("UNKNOWN", None),
    "ml-dsa": ("ML-DSA", None), "hybrid": ("ML-KEM", None),
}
_AZ_KTY = {"RSA": "RSA", "RSA-HSM": "RSA", "EC": "ECDSA", "EC-HSM": "ECDSA", "oct": "AES", "oct-HSM": "AES", "OKP": "ED25519", "OKP-HSM": "ED25519"}
_CURVE_BITS = {"P-256": 256, "P-256K": 256, "P-384": 384, "P-521": 521, "secp256k1": 256, "prime256v1": 256, "secp384r1": 384, "secp521r1": 521, "brainpoolP256r1": 256, "brainpoolP384r1": 384, "brainpoolP512r1": 512, "Ed25519": 255, "X25519": 255}

_SIG_ALG = re.compile(r"\b(sha\d+)\s*(?:with)?\s*(rsa|ecdsa|dsa)(?:encryption|-pss)?\b|\b(md5|sha1)\s*(?:with)?\s*(rsa)\b|\b(ecdsa)-with-(sha\d+)\b|\brsassa-?pss\b", re.I)


def _norm_sha(tok: str) -> str:
    t = tok.upper().replace("SHA", "SHA-").replace("--", "-")
    return {"SHA-1": "SHA-1", "SHA-224": "SHA-224", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512", "MD5": "MD5"}.get(t, t)


def _sig_parts(text: str) -> list[tuple[str, str]]:
    """'SHA256withRSA' / 'sha1RSA' / 'ecdsa-with-SHA384' → [(SHA-256, RSA), …] flattened to (algorithm, role)."""
    out: list[tuple[str, str]] = []
    for m in _SIG_ALG.finditer(text):
        if m.group(1):
            out += [(_norm_sha(m.group(1)), "digest"), (m.group(2).upper(), "signature")]
        elif m.group(3):
            out += [(_norm_sha(m.group(3)), "digest"), ("RSA", "signature")]
        elif m.group(5):
            out += [("ECDSA", "signature"), (_norm_sha(m.group(6)), "digest")]
        else:
            out.append(("RSA-PSS", "signature"))
    return out


def _date(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip().strip('"')
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%Y%m%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S",
                "%b %d %H:%M:%S %Y %Z", "%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y", "%d %b %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    m = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", s)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None


def _expired(not_after: str | None) -> bool | None:
    if not not_after:
        return None
    try:
        return datetime.fromisoformat(not_after).date() < datetime.now(timezone.utc).date()
    except ValueError:
        return None


class _Rec:
    """One inventory entry before it becomes a finding."""

    def __init__(self, line: int, system: str, algorithm: str | None, api: tuple[str, str], **attrs: Any):
        self.line, self.system, self.algorithm, self.api = line, system, algorithm, api
        self.key_size: int | None = attrs.pop("key_size", None)
        self.raw: str | None = attrs.pop("raw", None)
        self.snippet: str = attrs.pop("snippet", "")[:200]
        self.attrs = {k: v for k, v in attrs.items() if v not in (None, "", [])}


# ------------------------------------------------------------------------------------ text formats
_ICSF_LINE = re.compile(r"\b(?:LABEL|KEY\s*LABEL)\s*[=:]?\s*([A-Z0-9.@#$_-]{1,64})\b.*?\b(?:TYPE|KEY\s*TYPE|KEYTYPE)\s*[=:]?\s*([A-Z][A-Z0-9 -]{2,14}?)\b(?=\s*(?:,|;|ALG|ALGORITHM|LEN|LENGTH|KEYLEN|BITS|CREATE|CREATED|LASTREF|LAST|$|\s{2,}))", re.I)
_ICSF_CSV = re.compile(r"^\s*([A-Z0-9.@#$_-]{1,64})\s*[,;|]\s*(DATA|MAC|MACVER|PINGEN|PINVER|IPINENC|OPINENC|EXPORTER|IMPORTER|CIPHER|DKYGENKY|KEYGENKY|AES\s?DATA|AES\s?CIPHER|AES\s?MAC|AES\s?EXPORTER|AES\s?IMPORTER|AESKEK|HMAC|RSA(?:-CRT|-AESC|-AESM)?|ECC(?:-AESC)?|QSA|ML-DSA|ML-KEM|CLRDES|CLRAES|SECMSG|CVARENC|NULL)\b", re.I)
_ICSF_FIELD = re.compile(r"\b(ALG(?:ORITHM)?|KEYLEN|KEY\s*LEN(?:GTH)?|LEN(?:GTH)?|BITS|MODULUS(?:\s*BITS)?|CURVE|CREATE(?:D)?(?:\s*DATE)?|LASTREF(?:ERENCED)?|LAST\s*(?:REF|USED)(?:ERENCED)?|LAST\s*USED|KEY\s*ORIGIN|STATE|STATUS|ARCHIVE[D]?|ACTIVE)\s*[=:]?\s*([A-Z0-9./:-]{1,20})", re.I)

_LUNA_LINE = re.compile(r"\b(?:label|Label)\s*[:=]?\s*(\S.{0,60}?)\s{2,}.*?\b(?:type|Type|Object Type)\s*[:=]?\s*([A-Za-z0-9_-]+)|^\s*(?:handle|Handle)\s*[:=]\s*\d+\s+(?:label|Label)\s*[:=]\s*(\S.{0,60}?)(?:\s{2,}|$)", re.I)
_LUNA_BLOCK_KEY = re.compile(r"^\s*(?:Object\s+)?(Label|Class|Key Type|Key Size|Modulus Bits|Type|Extractable|Private|Sensitive|Date|CKA_LABEL|CKA_KEY_TYPE|CKA_MODULUS_BITS|CKA_VALUE_LEN|CKA_EXTRACTABLE|CKA_CLASS)\s*[:=]\s*(.+?)\s*$", re.I)
_PKCS11_OBJ = re.compile(r"^\s*(Private|Public|Secret|Certificate)\s+Key\s+Object;?\s*(?:(RSA|EC|EC_EDWARDS|EC_MONTGOMERY|DSA|DH|AES|DES3|DES|GENERIC_SECRET|Generic secret|HMAC)\b)?(?:\s*(\d+)\s*bits?)?(?:\s*length\s*(\d+))?|^\s*Certificate Object;\s*type\s*=\s*X\.509", re.I)
_PKCS11_ATTR = re.compile(r"^\s*(label|ID|Usage|Access|Curve|subject)\s*:\s*(.+?)\s*$", re.I)
_NSHIELD = re.compile(r"^\s*(?:Key\s+)?AppName\s+(\S+)\s+Ident\s+(\S+)|^\s*(?:key\s+)?(?:type|Type)\s*[:=]?\s*(RSA|DSA|DH|ECDSA|ECDH|Ed25519|X25519|AES|DES3|DES2|Rijndael|HMACSHA\d+|Generic|KCDSA|ML-DSA|ML-KEM)(?:Private|Public)?\b(?:.*?\b(\d{3,4})\b\s*bits?)?|^\s*(?:name|Name|ident)\s*[:=]\s*(\S+)", re.I)
_UTIMACO = re.compile(r"^\s*(?:\d+\s+)?(?:Name|name)\s*[:=]?\s*(\S+)\s+.*?\b(?:Type|type|Algo|algo)\s*[:=]?\s*(RSA|ECDSA|ECDH|EC|AES|DES|DES3|HMAC|DSA|ML-DSA|ML-KEM|SLH-DSA|Kyber|Dilithium)\b(?:.*?\b(\d{3,4})\b)?", re.I)

_KEYTOOL_ALIAS = re.compile(r"^\s*Alias name:\s*(.+?)\s*$", re.I)
_KEYTOOL_FIELD = re.compile(r"^\s*(Entry type|Creation date|Owner|Issuer|Valid from|Signature algorithm name|Subject Public Key Algorithm|Serial number)\s*:\s*(.+?)\s*$", re.I)
_KEYTOOL_KEYALG = re.compile(r"(\d{3,4})-bit\s+(RSA|EC|DSA|EdDSA|Ed25519|Ed448|XDH|ML-DSA|ML-KEM)\s+key|Secret key entry.*?(AES|DESede|HmacSHA\d+)", re.I)

_RACF_LABEL = re.compile(r"^\s*Label:\s*(.+?)\s*$")
_RACF_FIELD = re.compile(r"^\s*(Status|Key Type|Key Size|Private Key Type|Private Key Size|Signing Algorithm|Start Date|End Date|Ring Owner|Certificate ID|Issuer's Name|Subject's Name)\s*:\s*(.+?)\s*$", re.I)

_X509_FIELD = re.compile(r"^\s*(Subject|Issuer|Not Before|Not After|Signature Algorithm|Public Key Algorithm|Public-Key|ASN1 OID|NIST CURVE|Serial Number)\s*:\s*(.*?)\s*$", re.I)
_CERT_CSV_HEAD = re.compile(r"(common\s*name|subject|cn)\b.*?(expir|valid\s*to|not\s*after)", re.I)

_RECORD_BREAK = re.compile(r"^\s*(?:\*{5,}|-{5,}|={5,}|Certificate\[\d+\]:|Alias name:|Label:|Object\s+\d+:|Handle:|Key\s+\d+:|Certificate:)", re.I)


def _detect(text: str) -> set[str]:
    """Which formats are plausibly present (cheap sniff; the line parsers are strict)."""
    fmts: set[str] = set()
    head = text[:200_000]
    up = head.upper()
    if "CKDS" in up or "PKDS" in up or "TKDS" in up or "KGUP" in up or "CSFKDSL" in up or re.search(r"\bLABEL\s*[=:]?\s*[A-Z0-9.]+.*\b(?:KEY\s*)?TYPE\s*[=:]?\s*(?:DATA|AES|MAC|PIN|EXPORTER|IMPORTER|RSA|ECC|HMAC)", up):
        fmts.add("icsf")
    if _TR31.search(head):
        fmts.add("tr31")
    if "CMU" in up or "PARTITION" in up and "OBJECT" in up or "CKA_LABEL" in up or "Luna" in head:
        fmts.add("luna")
    if "Key Object" in head or "pkcs11-tool" in head or "Certificate Object" in head:
        fmts.add("pkcs11")
    if "nfkminfo" in head or "AppName" in head or "kmfile" in head or "Security World" in head or "nShield" in head:
        fmts.add("nshield")
    if "csadm" in head or "Utimaco" in head or "CryptoServer" in head:
        fmts.add("utimaco")
    if "Alias name:" in head and ("Entry type:" in head or "Keystore type:" in head):
        fmts.add("keytool")
    if "RACDCERT" in up or ("Label:" in head and "Key Type:" in head and ("Ring Owner" in head or "Start Date:" in head or "Private Key" in head)):
        fmts.add("racdcert")
    if "Not After" in head and ("Subject:" in head or "Issuer:" in head):
        fmts.add("x509")
    if _CERT_CSV_HEAD.search(head.split("\n", 1)[0]):
        fmts.add("certcsv")
    if head.lstrip().startswith(("{", "[")):
        fmts.add("json")
    return fmts


def _parse_icsf(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    for ln, line in enumerate(lines, 1):
        m = _ICSF_LINE.search(line) or _ICSF_CSV.search(line)
        if not m:
            continue
        label, ktype = m.group(1), m.group(2).upper().strip()
        ktype = ktype.replace("  ", " ")
        fields = {k.upper().replace(" ", ""): v for k, v in _ICSF_FIELD.findall(line)}
        alg = None
        for k in ("ALGORITHM", "ALG"):
            if k in fields:
                alg = _ICSF_ALG.get(fields[k].upper())
        if alg is None:
            alg = _ICSF_TYPE.get(ktype) or _ICSF_TYPE.get(ktype.replace(" ", ""))
        if alg is None and ktype != "NULL":
            alg = "UNKNOWN"
        if ktype == "NULL":
            continue
        size = None
        for k in ("KEYLEN", "KEYLENGTH", "LEN", "LENGTH", "BITS", "MODULUS", "MODULUSBITS"):
            if k in fields and fields[k].isdigit():
                size = int(fields[k])
                if size in (8, 16, 24, 32) and alg in ("3DES", "AES", "DES", "HMAC"):
                    size *= 8  # byte lengths in KGUP output
                break
        if size is None and "CURVE" in fields:
            size = _CURVE_BITS.get(fields["CURVE"]) or (int(re.sub(r"\D", "", fields["CURVE"]) or 0) or None)
        if alg == "3DES" and size == 64:
            alg = "DES"
        api = _K if alg in ("RSA", "ECDSA", "ML-DSA", "ML-KEM", "ED25519") else _S
        recs.append(_Rec(ln, "ICSF", alg, api, key_size=size, raw=ktype, snippet=line, key_label=label, key_usage=ktype,
                         created=_date(fields.get("CREATE") or fields.get("CREATED") or fields.get("CREATEDATE")),
                         last_used=_date(fields.get("LASTREF") or fields.get("LASTREFERENCED") or fields.get("LASTUSED") or fields.get("LASTREFERENCED")),
                         state=(fields.get("STATE") or fields.get("STATUS") or ("ARCHIVED" if fields.get("ARCHIVED", "").upper() in ("Y", "YES") else None)),
                         key_store="CKDS" if api is _S else "PKDS"))
    return recs


def _parse_tr31(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    seen: set[tuple[str, str, str]] = set()
    for ln, line in enumerate(lines, 1):
        for m in _TR31.finditer(line):
            ver, _length, usage, alg_c, mode, kver, exp, _n, _res = m.groups()
            if usage not in _TR31_USAGE:
                continue
            alg = _TR31_ALG[alg_c]
            key = (usage, alg_c, mode)
            wrap = {"A": "TR-31 A (key variant binding, deprecated)", "B": "TR-31 B (TDEA key derivation binding)", "C": "TR-31 C (TDEA key variant binding)", "D": "TR-31 D (AES key derivation binding)"}[ver]
            size = None
            try:  # key block length lets us infer wrapped key length for symmetric keys
                total = int(_length)
                payload_hex = total - 16 - (8 if ver in "ABC" else 16) * 2  # header + MAC (hex chars)
                if alg in ("3DES", "DES", "AES") and payload_hex > 0:
                    key_bytes = payload_hex // 2 - 2  # 2-byte length field
                    if ver == "D":
                        key_bytes -= 16 if key_bytes > 32 else 0
                    size = {8: 64, 16: 128, 24: 192, 32: 256, 40: 256, 48: 256}.get(key_bytes, None)
                    if alg in ("3DES", "DES") and size == 64:
                        alg = "DES"
                    if alg == "3DES" and size == 256:
                        size = 192
            except ValueError:
                pass
            recs.append(_Rec(ln, "TR-31", alg, _S, key_size=size, raw=m.group(0)[:16], snippet=line,
                             key_usage=f"{usage} {_TR31_USAGE[usage]}", key_block_version=wrap, mode_of_use=_TR31_MODE.get(mode, mode),
                             exportability=_TR31_EXPORT.get(exp, exp), key_version=kver if kver != "00" else None,
                             weak_binding=ver == "A"))
            seen.add(key)
    return recs


def _parse_luna(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    cur: dict[str, str] = {}
    start = 0

    def flush():
        if not cur:
            return
        t = (cur.get("KEY TYPE") or cur.get("CKA_KEY_TYPE") or cur.get("TYPE") or "").upper().replace("CKK_", "")
        cls = (cur.get("CLASS") or cur.get("CKA_CLASS") or "").upper()
        alg = _LUNA_TYPE.get(t)
        if not alg and "CERT" in cls:
            alg = "X509"
        if not alg:
            return
        size = None
        for k in ("KEY SIZE", "MODULUS BITS", "CKA_MODULUS_BITS", "CKA_VALUE_LEN"):
            v = cur.get(k)
            if v and re.match(r"\d+", v):
                size = int(re.match(r"\d+", v).group(0))
                if k == "CKA_VALUE_LEN" or (size <= 64 and alg in ("AES", "3DES", "HMAC")):
                    size *= 8
                break
        recs.append(_Rec(start, "Luna", alg, _K if alg in ("RSA", "ECDSA", "DSA", "DH", "ED25519", "X25519", "ML-DSA", "ML-KEM", "SM2") else _S, key_size=size, raw=t or cls,
                         snippet=f"label={cur.get('LABEL') or cur.get('CKA_LABEL')} type={t}", key_label=cur.get("LABEL") or cur.get("CKA_LABEL"),
                         extractable=(cur.get("EXTRACTABLE") or cur.get("CKA_EXTRACTABLE") or "").lower() in ("1", "true", "yes") or None,
                         created=_date(cur.get("DATE"))))

    for ln, line in enumerate(lines, 1):
        if _RECORD_BREAK.match(line) and cur:
            flush(); cur = {}
        m = _LUNA_BLOCK_KEY.match(line)
        if m:
            if not cur:
                start = ln
            cur[m.group(1).upper()] = m.group(2)
            continue
        m = _LUNA_LINE.search(line)
        if m and (m.group(2) or m.group(3)):
            label = (m.group(1) or m.group(3) or "").strip()
            t = (m.group(2) or "").upper()
            alg = _LUNA_TYPE.get(t)
            if alg:
                size_m = re.search(r"\b(\d{3,4})\b", line[m.end():]) or re.search(r"\b(\d{3,4})\b", line)
                recs.append(_Rec(ln, "Luna", alg, _K if alg in ("RSA", "ECDSA", "DSA", "ED25519") else _S,
                                 key_size=int(size_m.group(1)) if size_m else None, raw=t, snippet=line, key_label=label))
    flush()
    return recs


def _parse_pkcs11(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    cur: _Rec | None = None
    for ln, line in enumerate(lines, 1):
        m = _PKCS11_OBJ.match(line)
        if m:
            if m.group(1) is None:  # Certificate Object
                cur = _Rec(ln, "PKCS#11", "X509", _X, raw="X.509", snippet=line, object_class="certificate")
                recs.append(cur)
                continue
            cls, t, bits, length = m.group(1), (m.group(2) or "").upper().replace(" ", "_"), m.group(3), m.group(4)
            alg = _LUNA_TYPE.get(t) or ("HMAC" if t == "GENERIC_SECRET" else None) or "UNKNOWN"
            if t.startswith("EC_"):
                alg = "ED25519" if t == "EC_EDWARDS" else "X25519"
            size = int(bits) if bits else (int(length) * 8 if length else None)
            cur = _Rec(ln, "PKCS#11", alg, _K if cls.lower() in ("private", "public") else _S, key_size=size, raw=t or cls, snippet=line, object_class=cls.lower())
            recs.append(cur)
            continue
        m = _PKCS11_ATTR.match(line)
        if m and cur is not None:
            k, v = m.group(1).lower(), m.group(2)
            if k == "label":
                cur.attrs["key_label"] = v
            elif k == "curve" and cur.key_size is None:
                cur.key_size = _CURVE_BITS.get(v)
            elif k in ("usage", "access"):
                cur.attrs[k] = v
    return recs


def _parse_nshield(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    cur: dict[str, Any] = {}
    start = 0

    def flush():
        if cur.get("type"):
            t = cur["type"].upper()
            alg = {"RIJNDAEL": "AES", "DES3": "3DES", "DES2": "3DES", "GENERIC": "HMAC", "ECDH": "ECDH", "KCDSA": "DSA"}.get(t) or ("HMAC" if t.startswith("HMAC") else _LUNA_TYPE.get(t, "UNKNOWN"))
            recs.append(_Rec(start, "nShield", alg, _K if alg in ("RSA", "DSA", "DH", "ECDSA", "ECDH", "ED25519", "X25519", "ML-DSA", "ML-KEM") else _S,
                             key_size=cur.get("size"), raw=cur["type"], snippet=f"app={cur.get('app')} ident={cur.get('ident')} type={cur['type']}",
                             key_label=cur.get("ident") or cur.get("name"), application=cur.get("app")))

    for ln, line in enumerate(lines, 1):
        m = _NSHIELD.match(line)
        if not m:
            if _RECORD_BREAK.match(line):
                flush(); cur = {}
            continue
        if m.group(1):
            flush(); cur = {"app": m.group(1), "ident": m.group(2)}; start = ln
        elif m.group(3):
            if cur.get("type"):
                flush(); cur = {k: v for k, v in cur.items() if k in ("app",)}; start = ln
            cur["type"] = m.group(3)
            if m.group(4):
                cur["size"] = int(m.group(4))
            elif (sm := re.search(r"\b(\d{3,4})\b", line)):
                cur["size"] = int(sm.group(1))
            if not cur.get("app"):
                start = ln
        elif m.group(5):
            cur["name"] = m.group(5)
    flush()
    return recs


def _parse_utimaco(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    for ln, line in enumerate(lines, 1):
        m = _UTIMACO.match(line)
        if not m:
            continue
        t = m.group(2).upper()
        alg = {"EC": "ECDSA", "DES3": "3DES", "KYBER": "ML-KEM", "DILITHIUM": "ML-DSA"}.get(t, t)
        recs.append(_Rec(ln, "Utimaco", alg, _K if alg in ("RSA", "ECDSA", "ECDH", "DSA", "ML-DSA", "ML-KEM", "SLH-DSA") else _S,
                         key_size=int(m.group(3)) if m.group(3) else None, raw=t, snippet=line, key_label=m.group(1)))
    return recs


def _parse_keytool(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    cur: dict[str, Any] = {}
    start = 0

    def flush():
        if not cur.get("alias"):
            return
        alg, size, etype = cur.get("keyalg"), cur.get("size"), (cur.get("entry type") or "").lower()
        api = _X if "trusted" in etype else _K if "privatekey" in etype.replace(" ", "") else _S if "secret" in etype else _K
        if alg is None:
            alg = "X509" if "trusted" in etype else "UNKNOWN"
        recs.append(_Rec(start, "keytool", alg, api, key_size=size, raw=cur.get("keyalg_raw") or etype, snippet=f"alias={cur['alias']} {etype}",
                         key_label=cur["alias"], entry_type=etype, subject=cur.get("owner"), issuer=cur.get("issuer"),
                         created=_date(cur.get("creation date")), not_before=cur.get("nb"), not_after=cur.get("na"), expired=_expired(cur.get("na")),
                         signature_algorithm=cur.get("signature algorithm name"), self_signed=(cur.get("owner") == cur.get("issuer")) if cur.get("owner") else None))
        for a, role in _sig_parts(cur.get("signature algorithm name") or ""):
            if role == "digest":
                recs.append(_Rec(start, "keytool", a, ("SIGNATURE", "CERTIFICATE_MANAGEMENT"), raw=cur.get("signature algorithm name"), snippet=f"alias={cur['alias']} sig={cur.get('signature algorithm name')}", key_label=cur["alias"], role="certificate signature digest"))

    for ln, line in enumerate(lines, 1):
        m = _KEYTOOL_ALIAS.match(line)
        if m:
            flush(); cur = {"alias": m.group(1)}; start = ln
            continue
        m = _KEYTOOL_FIELD.match(line)
        if m and cur:
            k, v = m.group(1).lower(), m.group(2)
            cur[k] = v
            if k == "valid from":
                mm = re.search(r"(.+?)\s+until:\s*(.+)$", v)
                if mm:
                    cur["nb"], cur["na"] = _date(mm.group(1)), _date(mm.group(2))
            if k == "subject public key algorithm":
                mm = _KEYTOOL_KEYALG.search(v)
                if mm:
                    cur["size"] = int(mm.group(1))
                    cur["keyalg"] = {"EC": "ECDSA", "EDDSA": "ED25519", "XDH": "X25519"}.get(mm.group(2).upper(), mm.group(2).upper())
                    cur["keyalg_raw"] = v
            continue
        mm = _KEYTOOL_KEYALG.search(line)
        if mm and cur and mm.group(3):
            cur["keyalg"] = {"DESEDE": "3DES"}.get(mm.group(3).upper(), "HMAC" if mm.group(3).upper().startswith("HMAC") else mm.group(3).upper())
    flush()
    return recs


def _parse_racdcert(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    cur: dict[str, Any] = {}
    start = 0

    def flush():
        if not cur.get("label"):
            return
        kt = (cur.get("key type") or cur.get("private key type") or "").upper()
        kt = re.sub(r"^(ICSF|PCICC|NON-ICSF)\s*", "", kt)
        alg = {"RSA": "RSA", "NISTECC": "ECDSA", "BPECC": "ECDSA", "DSA": "DSA", "ML-DSA": "ML-DSA", "DILITHIUM": "ML-DSA", "": "X509"}.get(kt, kt or "X509")
        size = cur.get("key size") or cur.get("private key size")
        recs.append(_Rec(start, "RACF", alg, _K if kt else _X, key_size=int(size) if size and str(size).isdigit() else None, raw=kt or "CERT", snippet=f"label={cur['label']} keytype={kt}",
                         key_label=cur["label"], state=cur.get("status"), subject=cur.get("subject's name"), issuer=cur.get("issuer's name"),
                         not_before=_date(cur.get("start date")), not_after=_date(cur.get("end date")), expired=_expired(_date(cur.get("end date"))),
                         signature_algorithm=cur.get("signing algorithm"), key_store="ICSF" if "ICSF" in (cur.get("private key type") or "").upper() else "RACF",
                         ring_owner=cur.get("ring owner")))
        for a, role in _sig_parts(cur.get("signing algorithm") or ""):
            if role == "digest":
                recs.append(_Rec(start, "RACF", a, ("SIGNATURE", "CERTIFICATE_MANAGEMENT"), raw=cur.get("signing algorithm"), snippet=f"label={cur['label']} sig={cur.get('signing algorithm')}", key_label=cur["label"], role="certificate signature digest"))

    for ln, line in enumerate(lines, 1):
        m = _RACF_LABEL.match(line)
        if m:
            flush(); cur = {"label": m.group(1)}; start = ln
            continue
        m = _RACF_FIELD.match(line)
        if m and cur:
            cur[m.group(1).lower()] = m.group(2)
    flush()
    return recs


def _parse_x509_text(lines: list[str]) -> list[_Rec]:
    recs: list[_Rec] = []
    cur: dict[str, Any] = {}
    start = 0

    def flush():
        if not cur.get("subject") and not cur.get("not after"):
            return
        pka = (cur.get("public key algorithm") or "").lower()
        alg = "RSA" if "rsa" in pka else "ECDSA" if "ec" in pka or "id-ecpublickey" in pka else "ED25519" if "ed25519" in pka else "DSA" if "dsa" in pka else "ML-DSA" if "ml-dsa" in pka or "dilithium" in pka else "X509"
        if pka.startswith("rsassapss"):
            alg = "RSA-PSS"
        size = cur.get("bits")
        if size is None and cur.get("curve"):
            size = _CURVE_BITS.get(cur["curve"])
        na = _date(cur.get("not after"))
        recs.append(_Rec(start, "X.509", alg, _K if alg != "X509" else _X, key_size=size, raw=cur.get("public key algorithm") or "certificate",
                         snippet=f"subject={cur.get('subject')} notAfter={na}", subject=cur.get("subject"), issuer=cur.get("issuer"),
                         not_before=_date(cur.get("not before")), not_after=na, expired=_expired(na), signature_algorithm=cur.get("signature algorithm"),
                         self_signed=(cur.get("subject") == cur.get("issuer")) if cur.get("subject") else None, serial=cur.get("serial number")))
        for a, role in _sig_parts(cur.get("signature algorithm") or ""):
            if role == "digest":
                recs.append(_Rec(start, "X.509", a, ("SIGNATURE", "CERTIFICATE_MANAGEMENT"), raw=cur.get("signature algorithm"), snippet=f"subject={cur.get('subject')} sig={cur.get('signature algorithm')}", subject=cur.get("subject"), role="certificate signature digest"))

    for ln, line in enumerate(lines, 1):
        if re.match(r"^\s*Certificate:\s*$", line) or line.startswith("-----BEGIN"):
            flush(); cur = {}; start = ln
            continue
        m = _X509_FIELD.match(line)
        if not m:
            continue
        k, v = m.group(1).lower(), m.group(2)
        if k == "public-key":
            mm = re.search(r"\((\d+)\s*bit\)", v)
            if mm:
                cur["bits"] = int(mm.group(1))
        elif k in ("asn1 oid", "nist curve"):
            cur["curve"] = v
        elif k == "signature algorithm" and "signature algorithm" in cur and cur.get("subject"):
            continue  # the trailing repeat after the TBS block
        elif k == "serial number" and not v:
            continue
        else:
            if k == "subject" and "subject" in cur and cur.get("not after"):
                flush(); cur = {}; start = ln
            if not cur:
                start = ln
            cur[k] = v
    flush()
    return recs


def _parse_cert_csv(lines: list[str]) -> list[_Rec]:
    import csv
    import io
    reader = csv.reader(io.StringIO("\n".join(lines)))
    try:
        header = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        return []

    def col(*names):
        for n in names:
            for i, h in enumerate(header):
                if n in h:
                    return i
        return None

    c_cn, c_exp, c_alg, c_size, c_sig, c_iss, c_state = col("common name", "subject", "cn"), col("expir", "valid to", "not after", "notafter"), col("key algorithm", "public key algorithm", "key type", "algorithm"), col("key size", "key length", "bits"), col("signature algorithm", "sig alg", "signature"), col("issuer", "ca"), col("status", "state")
    recs: list[_Rec] = []
    for ln, row in enumerate(reader, 2):
        if not row or c_cn is None or c_cn >= len(row):
            continue
        get = lambda i: row[i].strip() if i is not None and i < len(row) else None
        alg_raw = (get(c_alg) or "").upper()
        alg = "RSA" if "RSA" in alg_raw else "ECDSA" if "EC" in alg_raw else "ED25519" if "ED25519" in alg_raw else "DSA" if "DSA" in alg_raw else "X509"
        size = get(c_size)
        size = int(re.sub(r"\D", "", size)) if size and re.search(r"\d", size) else None
        na = _date(get(c_exp))
        recs.append(_Rec(ln, "certificate-inventory", alg, _K if alg != "X509" else _X, key_size=size, raw=alg_raw or "certificate", snippet=",".join(row)[:200],
                         subject=get(c_cn), issuer=get(c_iss), not_after=na, expired=_expired(na), signature_algorithm=get(c_sig), state=get(c_state)))
        for a, role in _sig_parts(get(c_sig) or ""):
            if role == "digest":
                recs.append(_Rec(ln, "certificate-inventory", a, ("SIGNATURE", "CERTIFICATE_MANAGEMENT"), raw=get(c_sig), snippet=",".join(row)[:200], subject=get(c_cn), role="certificate signature digest"))
    return recs


# ------------------------------------------------------------------------------------ JSON (cloud KMS / Vault)
def _walk(obj: Any, depth: int = 0):
    if depth > 8:
        return
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, depth + 1)


def _parse_json(text: str) -> list[_Rec]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    recs: list[_Rec] = []
    seen: set[str] = set()
    for d in _walk(data):
        # AWS KMS describe-key / list-keys
        if "KeyId" in d and ("KeySpec" in d or "CustomerMasterKeySpec" in d or "KeyState" in d or "KeyUsage" in d):
            spec = d.get("KeySpec") or d.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT"
            alg, size = _CLOUD_SPEC.get(spec, ("UNKNOWN", None))
            kid = d.get("Arn") or d.get("KeyId")
            if kid in seen:
                continue
            seen.add(kid)
            recs.append(_Rec(1, "AWS-KMS", alg, _K if alg in ("RSA", "ECDSA", "SM2", "ML-DSA") else _S, key_size=size, raw=spec, snippet=f"KeyId={d.get('KeyId')} KeySpec={spec} KeyState={d.get('KeyState')}",
                             key_label=d.get("Description") or d.get("KeyId"), key_id=kid, state=d.get("KeyState"), key_usage=d.get("KeyUsage"),
                             created=_date(str(d.get("CreationDate"))) if d.get("CreationDate") else None, origin=d.get("Origin"), key_store="AWS CloudHSM" if d.get("Origin") == "AWS_CLOUDHSM" else d.get("KeyManager"),
                             rotation_enabled=d.get("KeyRotationEnabled"), multi_region=d.get("MultiRegion"), deletion_date=_date(str(d.get("DeletionDate"))) if d.get("DeletionDate") else None))
        # Azure Key Vault
        elif ("kty" in d and ("kid" in d or "key_size" in d or "crv" in d)) or ("key" in d and isinstance(d.get("key"), dict) and "kty" in d["key"]):
            k = d["key"] if isinstance(d.get("key"), dict) else d
            kty = k.get("kty", "")
            alg = _AZ_KTY.get(kty, "UNKNOWN")
            size = k.get("key_size") or d.get("key_size") or _CURVE_BITS.get(k.get("crv") or d.get("crv") or "")
            if alg == "RSA" and size is None and k.get("n"):
                size = (len(k["n"]) * 6) // 8 * 8 // 8 * 8  # rough from base64url modulus
            kid = k.get("kid") or d.get("kid") or d.get("id")
            if kid in seen:
                continue
            seen.add(kid)
            attrs = d.get("attributes") or {}
            recs.append(_Rec(1, "Azure-KeyVault", alg, _K if alg in ("RSA", "ECDSA", "ED25519") else _S, key_size=size, raw=kty, snippet=f"kid={kid} kty={kty}",
                             key_label=(kid or "").rsplit("/", 2)[-2] if kid and "/keys/" in kid else d.get("name"), key_id=kid, state="Enabled" if attrs.get("enabled") else ("Disabled" if attrs.get("enabled") is False else None),
                             key_usage=",".join(k.get("key_ops") or []) or None, created=_date(str(attrs.get("created"))) if attrs.get("created") else None,
                             not_after=_date(str(attrs.get("exp") or attrs.get("expires"))) if attrs.get("exp") or attrs.get("expires") else None,
                             key_store="Azure Managed HSM" if kty.endswith("-HSM") else "Azure Key Vault", rotation_enabled=bool(d.get("rotationPolicy") or d.get("rotation_policy")) or None))
        # GCP KMS
        elif "versionTemplate" in d or ("purpose" in d and "name" in d and "cryptoKeys" in str(d.get("name"))):
            vt = d.get("versionTemplate") or {}
            algo = vt.get("algorithm") or d.get("algorithm") or "GOOGLE_SYMMETRIC_ENCRYPTION"
            alg, size = _CLOUD_SPEC.get(algo, ("UNKNOWN", None))
            name = d.get("name")
            if name in seen:
                continue
            seen.add(name)
            recs.append(_Rec(1, "GCP-KMS", alg, _K if alg in ("RSA", "RSA-PSS", "RSA-OAEP", "ECDSA", "ED25519", "ML-DSA", "SLH-DSA") else _S, key_size=size, raw=algo, snippet=f"name={name} algorithm={algo}",
                             key_label=(name or "").rsplit("/", 1)[-1], key_id=name, key_usage=d.get("purpose"), created=_date(str(d.get("createTime"))) if d.get("createTime") else None,
                             key_store={"HSM": "Cloud HSM", "SOFTWARE": "Cloud KMS software", "EXTERNAL": "Cloud EKM", "EXTERNAL_VPC": "Cloud EKM"}.get(vt.get("protectionLevel"), vt.get("protectionLevel")),
                             rotation_enabled=bool(d.get("rotationPeriod")) or None, rotation_period=d.get("rotationPeriod"), state=(d.get("primary") or {}).get("state")))
        # HashiCorp Vault transit (read transit/keys/<name>)
        elif "type" in d and ("min_decryption_version" in d or "supports_encryption" in d or "latest_version" in d or "deletion_allowed" in d):
            alg, size = _CLOUD_SPEC.get(d.get("type"), ("UNKNOWN", None))
            name = d.get("name") or "transit-key"
            if name in seen:
                continue
            seen.add(name)
            recs.append(_Rec(1, "Vault-transit", alg, _K if alg in ("RSA", "ECDSA", "ED25519", "ML-DSA") else _S, key_size=size, raw=d.get("type"), snippet=f"name={name} type={d.get('type')} latest_version={d.get('latest_version')}",
                             key_label=name, key_version=str(d.get("latest_version")) if d.get("latest_version") else None, exportable=d.get("exportable"),
                             rotation_enabled=bool(d.get("auto_rotate_period")) or None, min_decryption_version=d.get("min_decryption_version")))
        # Vault list output {"data":{"keys":[...]}}: names only → one UNKNOWN placeholder is worse than nothing; skip
    return recs


# ------------------------------------------------------------------------------------ entry point
def parse_key_inventory_text(text: str, *, hint: str | None = None) -> list[_Rec]:
    fmts = _detect(text)
    lines = text.splitlines()
    recs: list[_Rec] = []
    if "json" in fmts:
        recs += _parse_json(text)
    if "icsf" in fmts:
        recs += _parse_icsf(lines)
    if "tr31" in fmts:
        recs += _parse_tr31(lines)
    if "luna" in fmts:
        recs += _parse_luna(lines)
    if "pkcs11" in fmts:
        recs += _parse_pkcs11(lines)
    if "nshield" in fmts:
        recs += _parse_nshield(lines)
    if "utimaco" in fmts:
        recs += _parse_utimaco(lines)
    if "keytool" in fmts:
        recs += _parse_keytool(lines)
    if "racdcert" in fmts:
        recs += _parse_racdcert(lines)
    if "x509" in fmts and "keytool" not in fmts and "racdcert" not in fmts:
        recs += _parse_x509_text(lines)
    if "certcsv" in fmts:
        recs += _parse_cert_csv(lines)
    # one record per (line, algorithm, label)
    out, seen = [], set()
    for r in recs:
        key = (r.line, r.algorithm, r.attrs.get("key_label") or r.attrs.get("subject") or r.raw, r.attrs.get("role"))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def parse_key_inventory_file(file_path: Path, repo_root: Path | None = None, *, max_bytes: int = 100 * 1024 * 1024) -> list[RawFinding]:
    try:
        if file_path.stat().st_size > max_bytes:
            return []
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []
    for r in parse_key_inventory_text(text):
        alg = r.algorithm or "UNKNOWN"
        f = make_finding(
            file_path=file_path, repo_root=repo_root, line_number=r.line, language="KEY-INVENTORY", scanner_id=SCANNER_ID,
            api_type=r.api[0], algorithm=alg, purpose=r.api[1], library=r.system, raw_transformation=r.raw,
            confidence="HIGH" if alg != "UNKNOWN" else "LOW",
            confidence_reason=f"key inventory export ({r.system})" + (f"; label {r.attrs['key_label']}" if r.attrs.get("key_label") else ""),
            key_size=r.key_size,
        )
        f.source.type = "KEY_INVENTORY"
        f.source.code_snippet = r.snippet
        f.inventory = r.attrs  # extra field: label, usage, state, dates, exportability, key_store …
        findings.append(f)
    return findings


def key_inventory_enabled() -> bool:
    return os.environ.get(KEY_INVENTORY_ENV, "").lower() in ("1", "true", "yes")


def looks_like_key_inventory(path: Path) -> bool:
    """Cheap sniff for the tree walk (only consulted for SNIFF_EXT when the env flag is on)."""
    try:
        with path.open("rb") as fh:
            head = fh.read(64 * 1024).decode("utf-8", errors="replace")
    except OSError:
        return False
    return bool(_detect(head))
