"""PL/I crypto detector — the same ICSF / CCA callable-service vocabulary as COBOL
(``CALL CSNBSYE(...)``, ``FETCH CSNBOWH``, ``DCL CSNBPVR ENTRY OPTIONS(ASM)``) with
PL/I comment syntax (``/* ... */``) and ``ENTRY`` declarations. Also covers
Enterprise PL/I calling DB2 (``EXEC SQL ... ENCRYPT_TDES``) and RACF macros.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.cobol_parser import _RULES as _ICSF_RULES  # shared verb / rule-array vocabulary
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-pli-scanner-v1.0"

_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.IGNORECASE), {**base, "library": library, **extra}


# PL/I spells the call without quotes: CALL CSNBSYE(RC, RS, ...); or declares it as an ENTRY.
_PLI_RULES: list[Rule] = [
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:SYE|SYD|SAE|SAD|SYG|FPEE|FPED|FLE|FLD)\b", _C, "IBM-ICSF", algorithm="AES", confidence="MEDIUM", confidence_reason="Symmetric Algorithm Encipher/Decipher (AES; DES via rule array)"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:ENC|DEC|CTT\d?)\b", _C, "IBM-ICSF", algorithm="3DES", confidence="MEDIUM", confidence_reason="Encipher/Decipher — DES/TDES data keys"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE]OWH1?\b", _D, "IBM-ICSF", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="One-Way Hash — algorithm from rule array"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:HMG|HMV)\b", {"api_type": "MAC", "purpose": "MAC_GENERATION"}, "IBM-ICSF", algorithm="HMAC"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:MGN\d?|MVR\d?)\b", {"api_type": "MAC", "purpose": "MAC_GENERATION"}, "IBM-ICSF", algorithm="3DES", confidence="MEDIUM"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:SMG|SMV)\b", {"api_type": "MAC", "purpose": "MAC_GENERATION"}, "IBM-ICSF", algorithm="AES", mode="CMAC"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:PGN|PVR|PTR|PTRE|EPB|CPE|CPA|PEX|PEXX|SPN|PBK|PCU|PFO|DPC|DPCG|DPMT|EPG|PVV)\b", _C, "IBM-ICSF", algorithm="3DES", confidence="HIGH", confidence_reason="PIN block generate/translate/verify (TDES PIN keys)"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:CVG|CVV|CSG|CSV|DCM|DDC|ASC|ASV|TRV)\b", {"api_type": "MAC", "purpose": "MAC_GENERATION"}, "IBM-ICSF", algorithm="3DES", confidence="HIGH", confidence_reason="CVV/CVC generate-verify"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:AEV|ARGV|ARPC|EAC|EMVH|RCC)\b", {"api_type": "MAC", "purpose": "MAC_GENERATION"}, "IBM-ICSF", algorithm="3DES", confidence="HIGH", confidence_reason="EMV cryptogram verification"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE](?:KGN\d?|KTB\d?|KIM|KEX|KTR\d?|KYT\w*|KPI\d?|KRC\d?|KRD|KRR\d?|KRW\d?|CKM|CKI|CKC|DKG\d?|DKM|DKX|SKI\d?|SKY|SKM|TBC|KET|KTP\d?|RKA|RKX|CVE|CVT|RKL|MKP\d?|CKX|PCK|T31[IOX]|T31[PR])\b", _K, "IBM-ICSF", algorithm="UNKNOWN", confidence="MEDIUM", confidence_reason="CCA key token generate/import/export"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[DF](?:PKG|PKB|PKI|PKX|PKE|PKD|PKT\w*|PKH|PKR\w*|SYX|SYI\d?|SYG|SXD|SBC|SBD|SPKB|EDH|TBC|TBD|RKD|RKX|KTC\d?|DSG|DSV|RKL)\b", {"api_type": "SIGNATURE", "purpose": "SIGNING"}, "IBM-ICSF", algorithm="RSA", confidence="MEDIUM", confidence_reason="PKA callable service — RSA unless rule array says ECC"),
    _r(r"\b(?:CALL|FETCH|DCL|DECLARE)\s+CSN[BE]RNG\w*\b", {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}, "IBM-ICSF", algorithm="CSPRNG"),
    _r(r"\bRANDOM\s*\(" + r"(?=[^\n;]*(?:PASS|PWD|SECRET|TOKEN|SALT|OTP|PIN|NONCE))|\b\w*(?:PASS\w*|PWD|SECRET|TOKEN|SALT|OTP|PIN|NONCE)\w*\s*=\s*[^;\n]*\bRANDOM\s*\(", {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}, "pli-builtin", algorithm="PRNG", confidence="HIGH", confidence_reason="RANDOM builtin is not cryptographically secure"),
]

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _strip_pli_comments(text: str) -> str:
    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    text = _BLOCK_COMMENT.sub(blank, text)
    # fixed-format margins (cols 1 and 73-80) may carry sequence numbers
    return "\n".join(l[:72] + " " * (len(l) - 72) if len(l) > 72 else l for l in text.split("\n"))


def parse_pli_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    text = _strip_pli_comments(text)
    seen: set = set()
    out = run_rules(file_path=file_path, repo_root=repo_root, text=text, rules=_PLI_RULES, language="PLI", scanner_id=SCANNER_ID,
                    confidence_reason="icsf-callable-service", strip_comments=False, seen=seen)
    # quoted-call forms, rule-array literals, RACF/DB2/TLS vocabulary shared with COBOL
    out += run_rules(file_path=file_path, repo_root=repo_root, text=text, rules=_ICSF_RULES, language="PLI", scanner_id=SCANNER_ID,
                     confidence_reason="icsf-callable-service", strip_comments=False, seen=seen)
    return out
