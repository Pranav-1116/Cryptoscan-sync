"""Runtime evidence — crypto observed *in operation*, from logs the bank already has.

Static discovery answers "what could run"; this answers "what did run". Sources:

* **ICSF** — SMF type-82 / CSFSMF82 formatted reports and ``CSFxxxx`` console
  messages (``SERVICE=CSNBSYE``, ``ALGORITHM=AES``, ``KEY LABEL=…``).
* **RACF** — ``RACDCERT LIST`` output, ``IRRD…`` / ``ICH…`` messages with key type
  and size (``Key Type: RSA``, ``Key Size: 2048``, ``Signing Algorithm: sha256RSA``).
* **Thales payShield** — host audit / command logs (``Command: A0``, ``CMD=CW``).
* **JSSE** — ``-Djavax.net.debug=ssl`` output (``Negotiated protocol``,
  ``Negotiated cipher suite``, ``"cipher suite" : "TLS_…"``).
* **OpenSSL** — ``s_client`` / ``x509 -text`` transcripts (``Protocol  : TLSv1.2``,
  ``Cipher    : ECDHE-…``, ``Server Temp Key: X25519``, ``Signature Algorithm: sha256WithRSAEncryption``).
* **nginx / Apache** access logs with ``$ssl_protocol $ssl_cipher`` fields, HAProxy
  ``ssl_fc_protocol``/``ssl_fc_cipher`` fields.
* **OpenSSH** — ``sshd -d`` / ``ssh -vv`` (``kex: algorithm``, ``cipher: aes256-gcm@openssh.com``, ``host key: ssh-ed25519``).
* **z/OS Communications Server AT-TLS** — ``EZD1281I`` / ``TTLS`` negotiated cipher messages.

Logs are repetitive, so findings are **aggregated**: one finding per (source, algorithm)
with the first line number and an ``occurrences`` count. Every finding carries
``source.type = "RUNTIME_LOG"`` so the inventory can say "seen in production" versus
"present in source".
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "runtime-log-ingest-v1.0"
RUNTIME_LOG_EXT = {".log", ".trc", ".audit", ".out", ".txt.log", ".syslog"}
RUNTIME_LOG_ENV = "CRYPTOSCAN_RUNTIME_LOGS"

_TLS = ("KEY_AGREEMENT", "NETWORK_ENCRYPTION")
_C = ("CIPHER_INSTANCE", "ENCRYPTION")
_D = ("MESSAGE_DIGEST", "HASHING")
_S = ("SIGNATURE", "SIGNING")
_M = ("MAC", "MAC_GENERATION")
_K = ("KEY_PAIR_GENERATOR", "KEY_MANAGEMENT")

_ICSF_VERB = {
    "CSNBENC": "DES", "CSNBDEC": "DES", "CSNBENC1": "DES", "CSNBDEC1": "DES",  # 'DATA' keys — 3DES in practice, re-typed below
    "CSNBSYE": None, "CSNBSYD": None, "CSNBSAE": "AES", "CSNBSAD": "AES",
    "CSNBOWH": None, "CSNBOWH1": None, "CSNBMGN": "3DES", "CSNBMVR": "3DES", "CSNBHMG": "HMAC", "CSNBHMV": "HMAC",
    "CSNBPGN": "3DES", "CSNBPVR": "3DES", "CSNBPTR": "3DES", "CSNBEPG": "3DES", "CSNBCPE": "3DES", "CSNBCPA": "3DES", "CSNBPTR2": "3DES",
    "CSNBCVG": "3DES", "CSNBCVV": "3DES", "CSNBKGN": "3DES", "CSNBKGN2": "3DES", "CSNBKEX": "3DES", "CSNBKIM": "3DES", "CSNBKTC": "3DES", "CSNBKTC2": "3DES",
    "CSNDDSG": "RSA", "CSNDDSV": "RSA", "CSNDPKE": "RSA", "CSNDPKD": "RSA", "CSNDPKG": "RSA", "CSNDPKB": "RSA", "CSNDPKI": "RSA", "CSNDSYX": "RSA", "CSNDSYI": "RSA", "CSNDSYG": "RSA",
    "CSNDEDH": "ECDH", "CSNBRNG": "RNG", "CSNBRNGL": "RNG", "CSFPGSK": None, "CSFPSKE": None, "CSFPSKD": None, "CSFPOWH": None, "CSFPHMG": "HMAC", "CSFPPKS": None, "CSFPPKV": None,
}
_ICSF_ALG = {"AES": "AES", "DES": "3DES", "TDES": "3DES", "RSA": "RSA", "ECC": "ECDSA", "HMAC": "HMAC", "SHA-1": "SHA-1", "SHA1": "SHA-1", "SHA-256": "SHA-256", "SHA256": "SHA-256",
             "SHA-384": "SHA-384", "SHA-512": "SHA-512", "MD5": "MD5", "RIPEMD-160": "RIPEMD-160", "CLRAES": "AES", "CLRDES": "DES", "DATA": "3DES", "CIPHER": "3DES", "MAC": "3DES", "PINGEN": "3DES", "PINVER": "3DES", "IPINENC": "3DES", "OPINENC": "3DES", "EXPORTER": "3DES", "IMPORTER": "3DES"}
_SUITE_OPENSSL = re.compile(r"\b((?:ECDHE|DHE|ECDH|DH|RSA|PSK|ADH|AECDH|SRP)-[A-Z0-9-]*(?:AES|CHACHA20|3DES|DES|RC4|CAMELLIA|ARIA|SEED|NULL|GOST)[A-Z0-9-]*|(?:AES|CAMELLIA)(?:128|256)-(?:GCM-)?SHA(?:256|384)?|DES-CBC3-SHA|RC4-SHA|RC4-MD5|NULL-SHA(?:256)?|TLS_[A-Z0-9_]+_WITH_[A-Z0-9_]+|TLS_(?:AES_128_GCM_SHA256|AES_256_GCM_SHA384|CHACHA20_POLY1305_SHA256|AES_128_CCM_SHA256|AES_128_CCM_8_SHA256))\b")
_PROTO = re.compile(r"\b(TLSv1(?:\.[0-3])?|SSLv[23]|TLS\s?1\.[0-3]|TLS13|TLS12|TLS11|TLS10)\b")
_SSH_ALG = {"aes": "AES", "chacha20": "ChaCha20", "3des": "3DES", "arcfour": "RC4", "blowfish": "Blowfish", "cast128": "CAST5", "curve25519": "X25519", "ecdh-sha2": "ECDH", "diffie-hellman": "DH",
            "ssh-ed25519": "ED25519", "ssh-rsa": "RSA", "rsa-sha2": "RSA", "ecdsa-sha2": "ECDSA", "ssh-dss": "DSA", "sntrup761x25519": "X25519", "mlkem768x25519": "ML-KEM", "hmac-sha2": "HMAC", "hmac-sha1": "HMAC", "hmac-md5": "HMAC", "umac": "UMAC", "rsa": "RSA", "ed25519": "ED25519", "ecdsa": "ECDSA", "dsa": "DSA"}

# (source, regex, handler) — handler(match) -> list[(algorithm, api, purpose, confidence)]
_LINE_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("icsf-smf82", re.compile(r"\b(CSN[BDEF][A-Z0-9]{2,5}|CSFP[A-Z0-9]{2,4})\b(?=.*?(?:SERVICE|VERB|ICSF|SMF|RC=|RS=|RETURN\s+CODE|CSF))", re.I)),
    ("icsf-smf82", re.compile(r"\b(?:ALGORITHM|KEY\s*TYPE|KEYTYPE|ALG)\s*[=:]\s*([A-Z0-9-]+)\b(?=.*?(?:ICSF|CSF|CKDS|PKDS|TKDS|KEY\s*LABEL|SMF))|(?:ICSF|CKDS|PKDS|CSF).*?\b(?:ALGORITHM|KEY\s*TYPE|KEYTYPE|ALG)\s*[=:]\s*([A-Z0-9-]+)\b", re.I)),
    ("racf-racdcert", re.compile(r"\bKey\s+Type:\s*(RSA|NISTECC|BPECC|DSA|ML-DSA|Dilithium)\b|\bPrivate\s+Key\s+Type:\s*(?:ICSF|PCICC|Non-ICSF)?\s*(RSA|NISTECC|BPECC|DSA)\b|\bKey\s+Size:\s*(\d{3,4})\b|\bSign(?:ing|ature)\s+Algorithm:\s*(sha\d+RSA|sha\d+ECDSA|sha\d+withRSA|md5RSA|sha1RSA|ecdsa-with-SHA\d+|sha\d+WithRSAEncryption)", re.I)),
    ("payshield-audit", re.compile(r"\b(?:Command|CMD|Cmd|command\s+code|Host\s+command)\s*[:=]\s*[\"']?([A-Z][A-Z0-9])\b(?=.*?(?:HSM|payShield|Thales|Response|RSP|LMK|resp))", re.I)),
    ("jsse-debug", re.compile(r"Negotiated\s+(?:protocol(?:\s+version)?|cipher\s+suite)\s*:?\s*\"?([A-Za-z0-9_.-]+)|\"(?:cipher\s+suite|negotiated\s+protocol|protocol\s+version)\"\s*:\s*\"([A-Za-z0-9_.-]+)\"|\bCipher\s+suite\s*:\s*\"?(TLS_[A-Z0-9_]+)|\bSSLHandshake.*?(TLSv1(?:\.[0-3])?)\b|\bProtocol\s+version\s*:\s*\"?(TLSv1(?:\.[0-3])?)", re.I)),
    ("openssl-s_client", re.compile(r"^\s*(?:New|Reused),\s*(TLSv1(?:\.[0-3])?|SSLv3),\s*Cipher\s+is\s+([A-Z0-9_-]+)|^\s*Protocol\s*:\s*(TLSv1(?:\.[0-3])?|SSLv3)\b|^\s*Cipher\s*:\s*([A-Z0-9_-]{6,})\b|Server\s+Temp\s+Key:\s*([A-Za-z0-9-]+)(?:,\s*(\d+)\s*bits?)?|Peer\s+signature\s+type:\s*([A-Za-z0-9-]+)|Peer\s+signing\s+digest:\s*([A-Za-z0-9-]+)|Server\s+public\s+key\s+is\s+(\d+)\s+bit|Signature\s+Algorithm:\s*([A-Za-z0-9-]+)|Public\s+Key\s+Algorithm:\s*([A-Za-z0-9-]+)", re.I | re.M)),
    ("webserver-access", re.compile(r"\b(TLSv1(?:\.[0-3])?|SSLv3)\b[ \t\"]+" + _SUITE_OPENSSL.pattern)),
    ("openssh", re.compile(r"\bkex:\s*(?:algorithm|host key algorithm|server->client cipher|client->server cipher)\s*:?\s*([a-z0-9@.-]+)|\bkex:\s*(?:server->client|client->server)\s*(?:cipher:)?\s*([a-z0-9@.-]+)\s+MAC:\s*([a-z0-9@.<>-]+)|\bServer host key:\s*([a-z0-9@.-]+)|\bAccepted\s+publickey\s+for\s+\S+\s+from\s+\S+\s+port\s+\d+\s+ssh2:\s*(RSA|ED25519|ECDSA|DSA)\b", re.I)),
    ("attls", re.compile(r"\bEZD12\d\dI\b.*?(?:CIPHER|Cipher)\s*[=:]?\s*([0-9A-F]{2,4}|TLS_[A-Z0-9_]+)|\bTTLS\w*\b.*?\b(?:SSLV3|TLSV1(?:\.[0-3])?)\b|\bAT-TLS\b.*?\b(TLSv1(?:\.[0-3])?)\b", re.I)),
]
_ATTLS_HEX = {"2F": "TLS_RSA_WITH_AES_128_CBC_SHA", "35": "TLS_RSA_WITH_AES_256_CBC_SHA", "0A": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "05": "TLS_RSA_WITH_RC4_128_SHA", "3C": "TLS_RSA_WITH_AES_128_CBC_SHA256",
              "3D": "TLS_RSA_WITH_AES_256_CBC_SHA256", "9C": "TLS_RSA_WITH_AES_128_GCM_SHA256", "9D": "TLS_RSA_WITH_AES_256_GCM_SHA384", "C027": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "C028": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
              "C02F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "C030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "C02B": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "C02C": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "1301": "TLS_AES_128_GCM_SHA256", "1302": "TLS_AES_256_GCM_SHA384", "1303": "TLS_CHACHA20_POLY1305_SHA256"}

_PAYSHIELD_RSA = {"EI", "EO", "EW", "EY", "GI", "GK", "GO", "GW", "GY", "IK", "IO", "IU", "IW", "IY", "KY"}
_PAYSHIELD_KNOWN = {"A0", "A2", "A4", "A6", "A8", "AE", "AG", "AS", "AU", "AW", "B0", "BA", "BK", "BQ", "BU", "BW", "CA", "CC", "CE", "CG", "CI", "CK", "CM", "CO", "CQ", "CU", "CW", "CY", "DA", "DC", "DE", "DG", "DM", "DU", "EA", "EC", "EE", "FA", "FK", "FM", "G0", "GC", "GE", "GG", "GS", "GU", "HA", "HC", "IA", "IE", "JA", "JC", "JE", "JG", "JI", "JK", "KA", "KC", "KE", "KG", "KM", "KQ", "KU", "KW", "LI", "LK", "LN", "LO", "M0", "M2", "M4", "M6", "M8", "MA", "MC", "MS", "MU", "N0", "NC", "NE", "NG", "NO", "OA", "PA", "PC", "PE", "PG", "PM", "PV", "Q0", "Q2", "QA", "QC", "QE", "QK", "RA", "RC", "RI", "RY", "TA", "TD", "UA"}


def _norm_proto(tok: str) -> str | None:
    t = tok.upper().replace(" ", "")
    if t.startswith("TLS") or t.startswith("SSL"):
        return "TLS"
    return None


def _sig_alg(tok: str) -> list[tuple[str, tuple[str, str]]]:
    t = tok.lower()
    out: list[tuple[str, tuple[str, str]]] = []
    if "rsa" in t:
        out.append(("RSA", _S))
    if "ecdsa" in t or t.startswith("ecdsa"):
        out.append(("ECDSA", _S))
    if "ed25519" in t:
        out.append(("ED25519", _S))
    for h, name in (("sha1", "SHA-1"), ("sha256", "SHA-256"), ("sha384", "SHA-384"), ("sha512", "SHA-512"), ("md5", "MD5")):
        if h in t.replace("-", ""):
            out.append((name, _D))
    return out


def _events(source: str, m: re.Match[str], line: str) -> list[tuple[str, tuple[str, str], str, str | None]]:
    """→ [(algorithm, (api, purpose), confidence, raw)]."""
    ev: list[tuple[str, tuple[str, str], str, str | None]] = []
    g = [x for x in m.groups() if x]
    if source == "icsf-smf82":
        for tok in g:
            T = tok.upper()
            if T in _ICSF_VERB:
                alg = _ICSF_VERB[T]
                if alg is None:  # algorithm from an ALGORITHM= field on the same line
                    fm = re.search(r"\b(?:ALGORITHM|ALG|KEY\s*TYPE|KEYTYPE)\s*[=:]\s*([A-Z0-9-]+)", line, re.I)
                    alg = _ICSF_ALG.get(fm.group(1).upper()) if fm else None
                if T in ("CSNBENC", "CSNBDEC", "CSNBENC1", "CSNBDEC1"):
                    alg = "3DES"  # DATA keys are triple-length in every current CKDS
                api = _D if T in ("CSNBOWH", "CSNBOWH1", "CSFPOWH") else _M if alg == "HMAC" or T in ("CSNBMGN", "CSNBMVR") else _S if T[3] == "D" else _C
                ev.append((alg or "UNKNOWN", api, "HIGH", T))
            elif T in _ICSF_ALG:
                ev.append((_ICSF_ALG[T], _C, "HIGH", tok))
    elif source == "racf-racdcert":
        kt, pkt, ks, sa = m.group(1), m.group(2), m.group(3), m.group(4)
        t = (kt or pkt or "").upper()
        if t:
            ev.append(({"RSA": "RSA", "NISTECC": "ECDSA", "BPECC": "ECDSA", "DSA": "DSA", "ML-DSA": "ML-DSA", "DILITHIUM": "ML-DSA"}[t], _K, "HIGH", t))
        if ks:
            ev.append(("KEY-SIZE", _K, "HIGH", ks))  # attached to the preceding Key Type finding by the caller
        if sa:
            ev += [(a, api, "HIGH", sa) for a, api in _sig_alg(sa)]
    elif source == "payshield-audit":
        cmd = g[0].upper()
        if cmd in _PAYSHIELD_RSA:
            ev.append(("RSA", _S, "MEDIUM", cmd))
        elif cmd in _PAYSHIELD_KNOWN:
            aes = bool(re.search(r"\bkey\s*block\b|\bAES\b|\bLMK\s*ID\s*[=:]?\s*0?[1-9]\b|\bS1\b|\bscheme\s*[=:]?\s*S\b", line, re.I))
            ev.append(("AES" if aes else "3DES", _C, "MEDIUM", cmd))
    elif source in ("jsse-debug", "webserver-access", "attls"):
        for tok in g:
            if source == "attls" and re.fullmatch(r"[0-9A-F]{2,4}", tok):
                tok = _ATTLS_HEX.get(tok.upper(), tok)
            if _SUITE_OPENSSL.fullmatch(tok):
                ev.append(("TLS-CIPHERS", _TLS, "HIGH", tok))
            elif _norm_proto(tok):
                ev.append(("TLS", _TLS, "HIGH", tok))
        if source == "attls" and not ev:
            ev.append(("TLS", _TLS, "HIGH", m.group(0)[:40]))
    elif source == "openssl-s_client":
        for tok in g:
            if _SUITE_OPENSSL.fullmatch(tok):
                ev.append(("TLS-CIPHERS", _TLS, "HIGH", tok))
            elif _norm_proto(tok):
                ev.append(("TLS", _TLS, "HIGH", tok))
            elif tok.isdigit():
                continue
            elif tok.upper() in ("X25519", "X448"):
                ev.append(("X25519" if tok.upper() == "X25519" else "X448", _TLS, "HIGH", tok))
            elif tok.upper() in ("ECDH", "DH") or tok.upper().startswith(("P-", "SECP", "PRIME")):
                ev.append(("ECDH" if tok.upper() != "DH" else "DH", _TLS, "HIGH", tok))
            elif tok.upper().startswith(("X25519MLKEM", "MLKEM", "SECP256R1MLKEM")):
                ev.append(("ML-KEM", _TLS, "HIGH", tok))
            else:
                sig = _sig_alg(tok)
                if tok.upper().startswith("RSA") and not sig:
                    sig = [("RSA", _S)]
                if tok.lower() in ("rsaencryption", "id-ecpublickey"):
                    sig = [("RSA" if tok.lower() == "rsaencryption" else "ECDSA", _K)]
                ev += [(a, api, "HIGH", tok) for a, api in sig]
    elif source == "openssh":
        for tok in g:
            for prefix, alg in _SSH_ALG.items():
                if tok.lower().startswith(prefix) or tok.lower().split("-")[0] == prefix:
                    api = _M if alg in ("HMAC", "UMAC") else _K if alg in ("RSA", "ED25519", "ECDSA", "DSA") else _TLS if alg in ("X25519", "ECDH", "DH", "ML-KEM") else _C
                    ev.append((alg, api, "HIGH", tok))
                    break
    return ev


def parse_runtime_log_file(file_path: Path, repo_root: Path | None = None, *, max_bytes: int = 200 * 1024 * 1024) -> list[RawFinding]:
    try:
        size = file_path.stat().st_size
    except OSError:
        return []
    if size > max_bytes:
        return []
    agg: dict[tuple[str, str, str, str], dict] = {}
    last_key: tuple[str, str, str, str] | None = None
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for ln, line in enumerate(fh, 1):
            if len(line) > 4000:
                line = line[:4000]
            for source, rx in _LINE_RULES:
                for m in rx.finditer(line):
                    for alg, (api, purpose), conf, raw in _events(source, m, line):
                        if alg == "KEY-SIZE":  # RACDCERT prints Key Size on the line after Key Type
                            if last_key and last_key in agg:
                                agg[last_key]["key_size"] = int(raw)
                                # different sizes of the same key type are different findings
                                sized = last_key[:3] + (f"{last_key[3]}/{raw}",)
                                if sized not in agg:
                                    agg[sized] = dict(agg[last_key], n=1, line=ln, key_size=int(raw))
                                else:
                                    agg[sized]["n"] += 1
                            continue
                        key = (source, alg, api, raw or "")
                        slot = agg.get(key)
                        if slot is None:
                            agg[key] = {"line": ln, "n": 1, "raw": raw, "purpose": purpose, "conf": conf, "snippet": line.strip()[:200], "key_size": None}
                        else:
                            slot["n"] += 1
                        if source == "racf-racdcert" and api == _K[0]:
                            last_key = key
    findings: list[RawFinding] = []
    emitted: set[tuple[int, str, str]] = set()
    for (source, alg, api, raw), slot in sorted(agg.items(), key=lambda kv: kv[1]["line"]):
        if (slot["line"], alg, api) in emitted:  # same fact from two patterns on one line
            continue
        emitted.add((slot["line"], alg, api))
        if source == "racf-racdcert" and api == _K[0] and "/" not in raw and any(k[:3] == (source, alg, api) and "/" in k[3] for k in agg):
            continue  # superseded by the sized variant(s)
        f = make_finding(
            file_path=file_path, repo_root=repo_root, line_number=slot["line"], language="RUNTIME-LOG", scanner_id=SCANNER_ID,
            api_type=api, algorithm=alg, purpose=slot["purpose"], library=source, raw_transformation=slot["raw"],
            confidence=slot["conf"], confidence_reason=f"observed at runtime ({source}); {slot['n']} occurrence(s)",
            key_size=slot.get("key_size"),
        )
        f.source.type = "RUNTIME_LOG"
        f.source.code_snippet = slot["snippet"]
        f.occurrences = slot["n"]  # model allows extra fields
        findings.append(f)
    return findings


def runtime_logs_enabled() -> bool:
    return os.environ.get(RUNTIME_LOG_ENV, "").lower() in ("1", "true", "yes")
