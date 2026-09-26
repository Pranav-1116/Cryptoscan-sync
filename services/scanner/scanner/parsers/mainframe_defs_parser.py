"""z/OS *definitions* that decide cryptography without a line of program code:

* CICS resource definitions (DFHCSDUP / RDO extracts): ``DEFINE TCPIPSERVICE ... SSL(YES)
  CIPHERS(352F0A)``, ``DEFINE URIMAP ... SCHEME(HTTPS)``, ``DEFINE IPCONN ... SSL(YES)``
* CICS SIT overrides: ``ENCRYPTION=STRONG``, ``MINTLSLEVEL=TLS12``, ``KEYRING=``
* IMS Connect HWSCFGxx: ``SSLPORT=``, ``SSLENVAR=``
* AT-TLS Policy Agent files: ``TTLSRule``, ``V3CipherSuites TLS_RSA_WITH_AES_128_CBC_SHA``,
  ``TLSv1.2 On`` / ``SSLv3 Off``

CICS ``CIPHERS()`` takes the hex cipher-suite codes; they are decoded to the symmetric
algorithm families so the inventory says "3DES on the IPIC link" rather than "0A".
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import Rule, run_rules

SCANNER_ID = "static-mainframe-defs-scanner-v1.0"
MAINFRAME_DEF_EXT = {".csd", ".rdo", ".sit", ".proclib", ".hwscfg", ".ttls", ".pagent"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "NETWORK_ENCRYPTION"}

# IANA cipher-suite code → symmetric family (the 2-hex form CICS uses for SSLv3/TLS1.0 suites,
# the 4-hex form for TLS 1.2 suites)
_SUITE_CODES = {
    "01": None, "02": None, "2C": None, "2D": None, "2E": None, "3B": None,  # NULL ciphers
    "03": "RC4", "04": "RC4", "05": "RC4", "18": "RC4",
    "06": "RC2",
    "08": "DES", "09": "DES", "0E": "DES", "0F": "DES",
    "0A": "3DES", "0D": "3DES", "10": "3DES", "13": "3DES", "16": "3DES",
    "2F": "AES", "30": "AES", "31": "AES", "32": "AES", "33": "AES", "35": "AES", "36": "AES", "37": "AES", "38": "AES", "39": "AES",
    "3C": "AES", "3D": "AES", "3E": "AES", "3F": "AES", "40": "AES", "67": "AES", "68": "AES", "69": "AES", "6A": "AES", "6B": "AES",
    "9C": "AES", "9D": "AES", "9E": "AES", "9F": "AES", "A2": "AES", "A3": "AES",
    "C003": "3DES", "C008": "3DES", "C00D": "3DES", "C012": "3DES",
    "C004": "AES", "C005": "AES", "C009": "AES", "C00A": "AES", "C00E": "AES", "C00F": "AES", "C013": "AES", "C014": "AES",
    "C023": "AES", "C024": "AES", "C025": "AES", "C026": "AES", "C027": "AES", "C028": "AES", "C029": "AES", "C02A": "AES",
    "C02B": "AES", "C02C": "AES", "C02D": "AES", "C02E": "AES", "C02F": "AES", "C030": "AES", "C031": "AES", "C032": "AES",
    "1301": "AES", "1302": "AES", "1303": "CHACHA20", "1304": "AES", "1305": "AES",
    "CCA8": "CHACHA20", "CCA9": "CHACHA20", "CCAA": "CHACHA20",
}


def decode_cics_ciphers(hex_codes: str) -> list[str]:
    """``"352F0A"`` → ``["AES", "3DES"]`` (order of first appearance, NULL suites dropped)."""
    codes = hex_codes.strip().upper()
    if not re.fullmatch(r"[0-9A-F]+", codes) or len(codes) % 2:
        return []
    for width in (2, 4):
        if len(codes) % width:
            continue
        chunks = [codes[i:i + width] for i in range(0, len(codes), width)]
        if all(c in _SUITE_CODES for c in chunks):
            out: list[str] = []
            for c in chunks:
                fam = _SUITE_CODES[c]
                if fam and fam not in out:
                    out.append(fam)
            return out
    return []


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE), {**base, "library": library, **extra}


_RULES: list[Rule] = [
    # CICS RDO
    _r(r"\bDEFINE\s+(?:TCPIPSERVICE|IPCONN|URIMAP|CORBASERVER|WEBSERVICE)\b[\s\S]{0,400}?\bSSL\s*\(\s*(?:YES|NO|CLIENTAUTH|ATTLSAWARE)\s*\)", _TLS, "CICS-RDO", algorithm="TLS", confidence="HIGH", confidence_reason="CICS resource SSL() attribute (an explicit TLS decision, including SSL(NO))"),
    _r(r"\bDEFINE\s+URIMAP\b[\s\S]{0,400}?\bSCHEME\s*\(\s*HTTPS\s*\)", _TLS, "CICS-RDO", algorithm="TLS", confidence="HIGH", confidence_reason="CICS URIMAP SCHEME(HTTPS)"),
    _r(r"\bCIPHERS\s*\(\s*[\w.\-]+\.xml\s*\)", _TLS, "CICS-RDO", algorithm="TLS", confidence="MEDIUM", confidence_reason="CICS cipher-suite specification file"),
    # CICS SIT
    _r(r"^\s*(?:ENCRYPTION|MINTLSLEVEL|MAXTLSLEVEL|SSLCACHE|SSLDELAY|MAXSSLTCBS|KEYRING|CRLPROFILE|NISTSP800131A)\s*=\s*\S", _TLS, "CICS-SIT", algorithm="TLS", confidence="HIGH", confidence_reason="CICS system initialization TLS parameter"),
    # IMS Connect
    _r(r"\bSSLPORT\s*=|\bSSLENVAR\s*=", _TLS, "IMS-Connect", algorithm="TLS", confidence="HIGH", confidence_reason="IMS Connect SSL port / environment"),
    # AT-TLS policy agent
    _r(r"^\s*(?:TTLSRule|TTLSEnvironmentAction|TTLSConnectionAction|TTLSGroupAction)\b", _TLS, "zOS-AT-TLS", algorithm="TLS", confidence="HIGH", confidence_reason="AT-TLS policy statement"),
    _r(r"^\s*(?:V3CipherSuites|V3CipherSuites4Char|CipherSuites)\s+(TLS_[A-Z0-9_]+)", _TLS, "zOS-AT-TLS", algorithm="TLS", confidence="HIGH", raw_group=1, confidence_reason="AT-TLS cipher suite"),
    _r(r"^\s*(?:SSLv2|SSLv3|TLSv1|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(?:On|Off)\b", _TLS, "zOS-AT-TLS", algorithm="TLS", confidence="HIGH", confidence_reason="AT-TLS protocol version switch"),
]

_CICS_CIPHERS = re.compile(r"\bCIPHERS\s*\(\s*([0-9A-Fa-f]{2,64})\s*\)")
_ATTLS_MARK = re.compile(r"^\s*TTLS(?:Rule|EnvironmentAction|GroupAction|CipherParms|ConnectionAction)\b", re.M)


def looks_like_attls_policy(text: str) -> bool:
    return bool(_ATTLS_MARK.search(text[:65536]))


def _strip_star_comments(text: str) -> str:
    out = []
    for line in text.split("\n"):
        s = line.lstrip()
        if s.startswith(("*", "#", "//")):
            out.append(" " * len(line))
        else:
            out.append(line)
    return "\n".join(out)


def parse_mainframe_defs_file(file_path: Path, repo_root: Path | None = None, text: str | None = None) -> list[RawFinding]:
    if text is None:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    text = _strip_star_comments(text)
    findings = run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=text,
        rules=_RULES,
        language="MAINFRAME-DEFS",
        scanner_id=SCANNER_ID,
        confidence_reason="mainframe-definition",
        strip_comments=False,
    )
    # CIPHERS(352F0A) → one CIPHER_INSTANCE finding per symmetric family
    from scanner.parsers.finding_factory import make_finding

    for m in _CICS_CIPHERS.finditer(text):
        line = text[: m.start()].count("\n") + 1
        for fam in decode_cics_ciphers(m.group(1)):
            findings.append(
                make_finding(
                    file_path=file_path,
                    repo_root=repo_root,
                    line_number=line,
                    language="MAINFRAME-DEFS",
                    scanner_id=SCANNER_ID,
                    api_type="CIPHER_INSTANCE",
                    algorithm=fam,
                    purpose="NETWORK_ENCRYPTION",
                    library="CICS-RDO",
                    raw_transformation=f"CIPHERS({m.group(1)})",
                    confidence="HIGH",
                    confidence_reason="CICS CIPHERS() hex cipher-suite code decoded",
                )
            )
    return findings
