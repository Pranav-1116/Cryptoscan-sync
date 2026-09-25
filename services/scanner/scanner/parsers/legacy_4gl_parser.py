"""Legacy bank languages that no mainstream scanner reads:

* Informix 4GL / Genero (``.4gl``, ``.per``): ``ENCRYPT_AES()`` / ``ENCRYPT_TDES()`` column
  encryption, ``SET ENCRYPTION PASSWORD``, Genero ``security.Digest`` / ``xml.Encryption``.
* PowerBuilder PowerScript exports (``.sru .srw .srf .sra .srd .pbl`` text exports):
  ``CrypterObject.SymmetricEncrypt(AES!, …)``, ``Hash(SHA256!, …)``, ``AsymmetricSign``.
* Progress OpenEdge ABL (``.p .w .i .cls``): ``SECURITY-POLICY:SYMMETRIC-ENCRYPTION-ALGORITHM``,
  ``ENCRYPT()/DECRYPT()``, ``MESSAGE-DIGEST("MD5", …)``, ``GENERATE-PBE-KEY``, socket ``-ssl``.
* HP NonStop TAL / TACL (``.tal .tacl .tacl.txt``): Atalla NSP command frames (``<32#…>``),
  SSLLIB ``SSLPROTOCOLS`` / ``CIPHERSUITES`` params, SAFEGUARD.
* SAS (``.sas``): ``ENCRYPT=AES`` dataset option, ``NETENCRYPTALGORITHM=``, ``SHA256()/MD5()``
  functions, ``PROC PWENCODE METHOD=SASxxx``, SSL options.
* Thales payShield console scripts / transcripts (``.hsm``): LMK and component commands.

All rule tables are precision-first: every pattern names a vendor API or option, never a bare
word. Unknown/dynamic algorithms are reported as UNKNOWN (which the inventory never counts).
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding
from scanner.parsers.rule_engine import Rule, run_rules

INFORMIX_EXT = {".4gl", ".per"}
POWERBUILDER_EXT = {".sru", ".srw", ".srf", ".sra", ".srd", ".srs", ".srm", ".srq", ".sru.txt"}
PROGRESS_EXT = {".p", ".w", ".i", ".cls"}
TANDEM_EXT = {".tal", ".tacl", ".ptal"}
SAS_EXT = {".sas"}
PAYSHIELD_CONSOLE_EXT = {".hsm"}
LEGACY_4GL_EXT = INFORMIX_EXT | POWERBUILDER_EXT | PROGRESS_EXT | TANDEM_EXT | SAS_EXT | PAYSHIELD_CONSOLE_EXT

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}

_HASHES = {"md5": "MD5", "sha1": "SHA-1", "sha-1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha-256": "SHA-256",
           "sha384": "SHA-384", "sha-384": "SHA-384", "sha512": "SHA-512", "sha-512": "SHA-512", "crc32": None}
_SYM = {"aes": "AES", "aes_cbc_128": "AES", "aes_cbc_192": "AES", "aes_cbc_256": "AES", "aes_ofb_128": "AES", "aes_ofb_192": "AES", "aes_ofb_256": "AES",
        "aes_cfb_128": "AES", "aes_cfb_256": "AES", "aes_ecb_128": "AES", "aes_ecb_256": "AES", "des_cbc_56": "DES", "des_ede3_cbc": "3DES",
        "des_ede3_cbc_168": "3DES", "des3": "3DES", "tripledes": "3DES", "des": "DES", "rc4": "RC4", "rc2": "RC2", "blowfish": "Blowfish"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE), {**base, "library": library, **extra}


_INFORMIX_RULES: list[Rule] = [
    _r(r"\bENCRYPT_AES\s*\(|\bDECRYPT_(?:CHAR|BINARY)\s*\((?=[^\n]*aes)", _C, "informix-builtin", algorithm="AES", confidence="HIGH", confidence_reason="Informix ENCRYPT_AES column encryption"),
    _r(r"\bENCRYPT_TDES\s*\(", _C, "informix-builtin", algorithm="3DES", confidence="HIGH", confidence_reason="Informix ENCRYPT_TDES column encryption"),
    _r(r"\bDECRYPT_(?:CHAR|BINARY)\s*\(", _C, "informix-builtin", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="Informix column decryption (AES or TDES per the encrypting call)"),
    _r(r"\bSET\s+ENCRYPTION\s+PASSWORD\b", _KDF, "informix-builtin", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="Informix session encryption password (drives ENCRYPT_AES/TDES)"),
    _r(r"\bsecurity\.Digest\.Create(?:Digest|DigestString)\s*\([^)]*[\"'](MD5|SHA1|SHA224|SHA256|SHA384|SHA512)[\"']", _D, "genero-security", algo_from_group=1, algo_map=_HASHES, confidence="HIGH"),
    _r(r"\bsecurity\.Digest\.CreateDigest\s*\(\s*[\"'](MD5|SHA1|SHA224|SHA256|SHA384|SHA512)[\"']", _D, "genero-security", algo_from_group=1, algo_map=_HASHES, confidence="HIGH"),
    _r(r"\bsecurity\.HMAC\.Create\s*\(\s*[\"'](MD5|SHA1|SHA256|SHA384|SHA512)[\"']", _M, "genero-security", algorithm="HMAC", confidence="HIGH"),
    _r(r"\bsecurity\.RandomGenerator\.Create(?:RandomString|RandomNumber|UUIDString)\b", {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}, "genero-security", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bxml\.Encryption\.(?:EncryptElement|EncryptString|DecryptElement)\b", _C, "genero-xml", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="Genero XML encryption (algorithm from the key object)"),
    _r(r"\bxml\.CryptoKey\.Create\s*\(\s*[\"'][^\"']*xmlenc#(aes128-cbc|aes192-cbc|aes256-cbc|tripledes-cbc|rsa-1_5|rsa-oaep-mgf1p)", _C, "genero-xml", algo_from_group=1,
       algo_map={"aes128-cbc": "AES", "aes192-cbc": "AES", "aes256-cbc": "AES", "tripledes-cbc": "3DES", "rsa-1_5": "RSA", "rsa-oaep-mgf1p": "RSA"}, confidence="HIGH"),
]

_PB_SYM = {"aes!": "AES", "des!": "DES", "tripledes!": "3DES", "rc2!": "RC2", "rc4!": "RC4", "blowfish!": "Blowfish"}
_PB_HASH = {"md5!": "MD5", "sha1!": "SHA-1", "sha224!": "SHA-224", "sha256!": "SHA-256", "sha384!": "SHA-384", "sha512!": "SHA-512", "sha3_256!": "SHA3-256"}
_POWERBUILDER_RULES: list[Rule] = [
    _r(r"\.Symmetric(?:Encrypt|Decrypt)\s*\(\s*(AES!|DES!|TripleDES!|RC2!|RC4!|Blowfish!)", _C, "pb-CrypterObject", algo_from_group=1, algo_map=_PB_SYM, confidence="HIGH"),
    _r(r"\.Symmetric(?:Encrypt|Decrypt)\s*\(", _C, "pb-CrypterObject", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="CrypterObject symmetric call with a non-literal algorithm"),
    _r(r"\.Hash\s*\(\s*(MD5!|SHA1!|SHA224!|SHA256!|SHA384!|SHA512!|SHA3_256!)", _D, "pb-CrypterObject", algo_from_group=1, algo_map=_PB_HASH, confidence="HIGH"),
    _r(r"\.Asymmetric(?:Sign|VerifySign)\s*\([^)\n]*?(MD5!|SHA1!|SHA224!|SHA256!|SHA384!|SHA512!)", _D, "pb-CrypterObject", algo_from_group=1, algo_map=_PB_HASH, confidence="HIGH"),
    _r(r"\.Asymmetric(?:Sign|VerifySign|Encrypt|Decrypt)\s*\(|\.AsymmetricGenerateKey\s*\(", _S, "pb-CrypterObject", algorithm="RSA", confidence="HIGH", confidence_reason="PowerBuilder CrypterObject asymmetric operations are RSA"),
    _r(r"\.SymmetricGenerateKey\s*\(\s*(AES!|DES!|TripleDES!|RC2!|RC4!|Blowfish!)", _K, "pb-CrypterObject", algo_from_group=1, algo_map=_PB_SYM, confidence="HIGH"),
    _r(r"\bCrypterObject\b", _K, "pb-CrypterObject", algorithm="UNKNOWN", confidence="LOW", confidence_reason="PowerBuilder CrypterObject in scope"),
    _r(r"\bof_(?:aes|des|3des|tdes)_?(?:encrypt|decrypt)\s*\(", _C, "pb-userobject", algorithm="UNKNOWN", confidence="LOW"),
]

_PROGRESS_RULES: list[Rule] = [
    _r(r"SECURITY-POLICY:SYMMETRIC-ENCRYPTION-ALGORITHM\s*=\s*[\"'](AES_[A-Z]+_\d+|DES_CBC_56|DES_EDE3_CBC|DES_EDE3_CBC_168|RC4_\d+)[\"']", _C, "openedge-abl",
       algo_from_group=1, algo_map={**_SYM, "rc4_40": "RC4", "rc4_56": "RC4", "rc4_128": "RC4"}, confidence="HIGH"),
    _r(r"SECURITY-POLICY:SYMMETRIC-ENCRYPTION-ALGORITHM\s*=", _C, "openedge-abl", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="ABL symmetric algorithm set from a non-literal"),
    _r(r"(?<![\w-])(?:ENCRYPT|DECRYPT)\s*\(", _C, "openedge-abl", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="ABL ENCRYPT()/DECRYPT() — algorithm from SECURITY-POLICY (default DES_CBC_56)"),
    _r(r"\bMESSAGE-DIGEST\s*\(\s*[\"'](MD5|SHA-1|SHA1|SHA-224|SHA-256|SHA-384|SHA-512)[\"']", _D, "openedge-abl", algo_from_group=1, algo_map=_HASHES, confidence="HIGH"),
    _r(r"\bMESSAGE-DIGEST\s*\(", _D, "openedge-abl", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bGENERATE-PBE-KEY\s*\(|\bGENERATE-PBE-SALT\b|SECURITY-POLICY:PBE-HASH-ALGORITHM|SECURITY-POLICY:PBE-KEY-ROUNDS", _KDF, "openedge-abl", algorithm="PBKDF2", confidence="HIGH", confidence_reason="ABL password-based key derivation (PKCS#5 PBKDF2)"),
    _r(r"\bGENERATE-RANDOM-KEY\b", {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}, "openedge-abl", algorithm="CSPRNG", confidence="HIGH"),
    _r(r"\bENCRYPT-AUDIT-MAC-KEY\b", _M, "openedge-abl", algorithm="HMAC", confidence="MEDIUM", confidence_reason="OpenEdge audit MAC key"),
    _r(r"[\"'][^\"'\n]*\s-ssl\b[^\"'\n]*[\"']|\B-sslverify\s+\d|\B-nohostverify\b|\bSSL-SERVER-NAME\b|\bNO-SESSION-REUSE\b", _TLS, "openedge-abl", algorithm="TLS", confidence="HIGH", confidence_reason="ABL socket/AppServer SSL connection parameters"),
    _r(r"\bSECURITY-POLICY:LOAD-DOMAINS\b|\bSET-CLIENT\s*\(|\bCREATE\s+CLIENT-PRINCIPAL\b", _K, "openedge-abl", algorithm="UNKNOWN", confidence="LOW", confidence_reason="OpenEdge sealed client-principal (HMAC-sealed token)"),
]

_TANDEM_RULES: list[Rule] = [
    # Atalla NSP command frames: <cmd#field#...#>
    _r(r"[\"']<(?:30|31|32|33|35|37|39|3D|3E|11|12|13|14|15|16|17|18|1A|1B|1E|1F|2E|1D|33|35|36|3A|3B|5D|5E|5F|75|76|77|78|79|7E|CE)#", _C, "Atalla-NSP", algorithm="3DES", confidence="MEDIUM", confidence_reason="Atalla NSP PIN / key-management command (AKB keys under a TDES MFK)"),
    _r(r"[\"']<(?:59|58|5B|5C|98|99)#", _M, "Atalla-NSP", algorithm="3DES", confidence="MEDIUM", confidence_reason="Atalla NSP MAC command (ISO 9797 retail MAC)"),
    _r(r"[\"']<(?:10E|10F|11E|11F|12E|12F|120|121|122|123|124|125)#", _S, "Atalla-NSP", algorithm="RSA", confidence="MEDIUM", confidence_reason="Atalla NSP RSA command family"),
    _r(r"[\"']<(?:93|9E|9F)#|\bAKB\b(?=[^\n]*(?:MFK|key))|\bMFK\b(?=[^\n]*(?:key|AKB))", _K, "Atalla-NSP", algorithm="3DES", confidence="LOW", confidence_reason="Atalla AKB / MFK (TDES master file key)"),
    _r(r"\bSEEP\b|\bSAFEGUARD\b(?=[^\n]*(?:password|PASSWORD|encrypt|ENCRYPT))", _KDF, "NonStop-Safeguard", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"^\s*PARAM\s+SSLPROTOCOLS\b|^\s*PARAM\s+SSLCOM\w*|\bSSLLIB\b|\$SYSTEM\.ZSSL\b|\bSSLPROXY\b|\bPROXYS\b(?=[^\n]*SSL)", _TLS, "NonStop-SSL", algorithm="TLS", confidence="HIGH", confidence_reason="NonStop SSL (SSLLIB) configuration"),
    _r(r"^\s*PARAM\s+CIPHERSUITES\s+[\"']?([A-Za-z0-9:_+!-]+)", _TLS, "NonStop-SSL", algorithm="TLS-CIPHERS", confidence="HIGH", raw_group=1, confidence_reason="NonStop SSL cipher list"),
    _r(r"^\s*PARAM\s+(?:SERVCERT|CLIENTCERT|KEYPASS|SERVKEY|CACERTS|TRUST)\b", _TLS, "NonStop-SSL", algorithm="TLS", confidence="HIGH", confidence_reason="NonStop SSL certificate / key parameters"),
]

_SAS_RULES: list[Rule] = [
    _r(r"\bencrypt\s*=\s*(aes|yes|rc2)\b", _C, "sas-dataset", algo_from_group=1, algo_map={"aes": "AES", "yes": "RC2", "rc2": "RC2"}, confidence="HIGH", confidence_reason="SAS data set encryption (ENCRYPT=YES is the legacy SAS proprietary/RC2-class cipher)"),
    _r(r"\bnetencryptalgorithm\s*=\s*\(?\s*([A-Za-z0-9_ ,]+)", _C, "sas-net", algorithm="UNKNOWN", confidence="HIGH", raw_group=1, confidence_reason="SAS/SECURE network encryption algorithm list"),
    _r(r"\b(sha256|sha1|md5)\s*\(", _D, "sas-function", algo_from_group=1, algo_map=_HASHES, confidence="HIGH"),
    _r(r"\bproc\s+pwencode\b[\s\S]{0,200}?\bmethod\s*=\s*(sas001|sas002|sas003|sas004|sas005)\b", _KDF, "sas-pwencode", algo_from_group=1,
       algo_map={"sas001": "BASE64", "sas002": "UNKNOWN", "sas003": "AES", "sas004": "AES", "sas005": "SHA-256"}, confidence="HIGH", confidence_reason="PROC PWENCODE method (SAS003/004 = AES-256, SAS005 = salted SHA-256)"),
    _r(r"\{SAS00[345]\}", _KDF, "sas-pwencode", algorithm="AES", confidence="MEDIUM", confidence_reason="SAS00x encoded password literal"),
    _r(r"\bsslcalistloc\s*=|\bsslcertloc\s*=|\bsslpvtkeyloc\s*=|\bsslminprotocol\s*=|\bsslmode\s*=|\bsslreqcert\b|\bssl_use_sni\b|\bssl\s*=\s*\d", _TLS, "sas-ssl", algorithm="TLS", confidence="HIGH"),
    _r(r"\bnetencrypt\b(?!algorithm)", _TLS, "sas-net", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="SAS/SECURE encryption required (algorithm from NETENCRYPTALGORITHM)"),
]


def _sas_net_expand(text: str, findings: list[RawFinding], file_path: Path, repo_root: Path | None) -> None:
    """NETENCRYPTALGORITHM=(AES, RC4) → one finding per algorithm."""
    for m in re.finditer(r"(?i)\bnetencryptalgorithm\s*=\s*\(?\s*([A-Za-z0-9_ ,]+)", text):
        line = text[: m.start()].count("\n") + 1
        for tok in re.split(r"[ ,]+", m.group(1).strip().lower()):
            algo = {"aes": "AES", "rc2": "RC2", "rc4": "RC4", "des": "DES", "tripledes": "3DES", "sasproprietary": "SAS-PROPRIETARY", "ssl": "TLS"}.get(tok)
            if algo:
                findings.append(make_finding(file_path=file_path, repo_root=repo_root, line_number=line, language="SAS", scanner_id=SCANNER_ID,
                                             api_type="KEY_AGREEMENT" if algo == "TLS" else "CIPHER_INSTANCE", algorithm=algo, purpose="NETWORK_ENCRYPTION",
                                             library="sas-net", raw_transformation=m.group(0)[:80], confidence="HIGH", confidence_reason="SAS/SECURE network encryption algorithm"))


# payShield console commands (2-letter, one per line). Only meaningful in a console script.
_CONSOLE_LMK = re.compile(r"^\s*(GK|LK|LO|LN|LA|LC|GC|EC|FK|KG|IK|CK|CS|CV|DM|GS|KE|KN|KM|KR|KS|KT|LM|LR|ND|VT|RC|GX|EX|FX|IX)\s*$", re.M)
_CONSOLE_MARK = re.compile(r"^\s*(?:A|GK|LK|LO|GC|EC|FK|CK|CS)\s*$", re.M)
_CONSOLE_AES_LMK = re.compile(r"^\s*(?:AES|key ?block|K)\s*$", re.I | re.M)


def _payshield_console(text: str, file_path: Path, repo_root: Path | None) -> list[RawFinding]:
    lines = [ln.strip() for ln in text.split("\n")]
    if sum(1 for ln in lines if re.fullmatch(r"[A-Z]{1,2}", ln)) < 3 or not _CONSOLE_MARK.search(text):
        return []
    aes_lmk = bool(_CONSOLE_AES_LMK.search(text))
    findings: list[RawFinding] = []
    seen: set[int] = set()
    for m in _CONSOLE_LMK.finditer(text):
        line = text[: m.start()].count("\n") + 1
        if line in seen:
            continue
        seen.add(line)
        cmd = m.group(1)
        findings.append(make_finding(
            file_path=file_path, repo_root=repo_root, line_number=line, language="PAYSHIELD-CONSOLE", scanner_id=SCANNER_ID,
            api_type="KEY_PAIR_GENERATOR", algorithm="AES" if aes_lmk else "3DES", purpose="KEY_MANAGEMENT",
            library="HSM/Thales-payShield-console", raw_transformation=cmd, confidence="MEDIUM",
            confidence_reason=("payShield console command on a key-block (AES) LMK" if aes_lmk else "payShield console command on a variant (TDES) LMK"),
        ))
    return findings


SCANNER_ID = "static-legacy-4gl-scanner-v1.0"
_ABL_SNIFF = re.compile(r"\bNO-UNDO\b|\bDEFINE\s+(?:VARIABLE|VAR|TEMP-TABLE|INPUT|OUTPUT|BUFFER)\b|\bEND\s+PROCEDURE\b|\bFOR\s+EACH\b|\bSECURITY-POLICY\b|\bUSING\s+Progress\.|\bBLOCK-LEVEL\s+ON\s+ERROR\b|\{[\w/.-]+\.i\}", re.I)
_PB_SNIFF = re.compile(r"^\$PBExportHeader\$|\bforward\b[\s\S]{0,200}\bglobal\s+type\b|\bend\s+(?:event|subroutine|function|type)\b|\bCrypterObject\b", re.I | re.M)


def _strip_comments(text: str, suffix: str) -> str:
    out = []
    for line in text.split("\n"):
        s = line.lstrip()
        if suffix in INFORMIX_EXT and (s.startswith("#") or s.startswith("--") or s.startswith("{")):
            out.append(" " * len(line)); continue
        if suffix in TANDEM_EXT and (s.startswith("!") or s.startswith("==") or s.startswith("--")):
            out.append(" " * len(line)); continue
        if suffix in PAYSHIELD_CONSOLE_EXT and s.startswith((";", "#", "//")):
            out.append(" " * len(line)); continue
        if suffix in POWERBUILDER_EXT and s.startswith("//"):
            out.append(" " * len(line)); continue
        for marker in ("//", "--") if suffix in INFORMIX_EXT | POWERBUILDER_EXT else ():
            i = line.find(marker)
            if i >= 0:
                line = line[:i] + " " * (len(line) - i)
        out.append(line)
    text = "\n".join(out)
    if suffix in PROGRESS_EXT | SAS_EXT:
        text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    if suffix in SAS_EXT:
        text = re.sub(r"(?m)^\s*\*[^;]*;", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    if suffix in TANDEM_EXT:
        text = re.sub(r"![^\n]*", lambda m: " " * len(m.group(0)), text)
    return text


def parse_legacy_4gl_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = file_path.suffix.lower()
    if suffix in PROGRESS_EXT and not _ABL_SNIFF.search(raw):
        return []  # .p/.w/.i/.cls are shared with Pascal, C preprocessor output, VB6, LaTeX
    if suffix in POWERBUILDER_EXT and suffix != ".sru.txt" and not _PB_SNIFF.search(raw):
        return []
    text = _strip_comments(raw, suffix)
    if suffix in PAYSHIELD_CONSOLE_EXT:
        return _payshield_console(text, file_path, repo_root)
    if suffix in INFORMIX_EXT:
        rules, language = _INFORMIX_RULES, "INFORMIX-4GL"
    elif suffix in POWERBUILDER_EXT:
        rules, language = _POWERBUILDER_RULES, "POWERBUILDER"
    elif suffix in PROGRESS_EXT:
        rules, language = _PROGRESS_RULES, "OPENEDGE-ABL"
    elif suffix in TANDEM_EXT:
        rules, language = _TANDEM_RULES, "TAL"
    else:
        rules, language = _SAS_RULES, "SAS"
    findings = run_rules(file_path=file_path, repo_root=repo_root, text=text, rules=rules, language=language,
                         scanner_id=SCANNER_ID, confidence_reason="legacy-4gl-api", strip_comments=False)
    if suffix in SAS_EXT:
        _sas_net_expand(text, findings, file_path, repo_root)
    return findings
