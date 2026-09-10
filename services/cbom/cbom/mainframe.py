"""Mainframe discovery — z/OS crypto sources into the unified inventory.

Core-banking crypto concentrates in four z/OS places; each gets an extract
parser that emits the same finding shape the scanners produce, so mainframe
crypto flows into ONE Technology BOM:

1. **RACF**   — ``RACDCERT LIST`` output (rich parse: ring membership, trust
                status, key usage, expiry, signature chain).
2. **ICSF**   — key-inventory CSV (CKDS/PKDS label extracts) and plain
                key listings.
3. **DB2**    — TLS configuration extracts (``SSL_VERSIONS``/``SSL_CIPHERSPECS``/
                ``SSL_SVC_LABEL`` per database) — transport crypto the BOM
                otherwise never sees.
4. **CICS**   — ``TCPIPSERVICE`` CSD definitions (PORTNUMBER/PROTOCOL/
                SSLTYPE/CERTIFICATE/CIPHERS) — the CICS TLS edge.

``mainframe_assessment`` aggregates every finding into the supervisor-facing
view: coverage by subsystem, weak/expiring/quantum-vulnerable classes. Pure
functions only (no DB / I/O / FastAPI), mirroring ``banking.py`` doctrine.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

from cbom.banking import quantum_vulnerability

# z/OS source markers for the unified crypto_assets.source_language column.
SOURCE_RACF = "zos-racf"
SOURCE_ICSF = "zos-icsf"
SOURCE_DB2 = "zos-db2"
SOURCE_CICS = "zos-cics"

EXPIRY_WARN_DAYS = 180

_DB2_WEAK_CIPHER_TOKENS = ("DES", "RC4", "NULL", "EXPORT", "3DES")
_TLS_FLOOR = "TLSV1.2"


def _tls_rank(v: str) -> int:
    """Order TLS versions; unknown -> 9 (never below floor)."""
    return {"TLSV1": 1, "TLS1": 1, "TLSV10": 1, "TLSV11": 2,
            "TLSV1.1": 2, "TLSV12": 2, "TLSV1.2": 2,
            "TLSV13": 3, "TLSV1.3": 3}.get(v.strip().upper(), 9)


def _row(source: str, **fields: Any) -> dict[str, Any]:
    fields.setdefault("source", source.split("-")[1] if "-" in source else source)
    fields.setdefault("source_language", source)
    fields.setdefault("confidence", "HIGH")
    return fields


# --------------------------------------------------------------------------- #
# 1. RACF — RACDCERT LIST (rich)
# --------------------------------------------------------------------------- #

def normalize_racdcert_rich(text: str) -> list[dict[str, Any]]:
    """Rich parse of RACF ``RACDCERT LIST`` output.

    One block per ``Digital certificate information for`` header. Captures the
    ring membership (ring ID / SITE / CERTAUTH / PERSONAL), trust status,
    signing PCA, key usage, expiry and size. Non-recognized blocks are skipped
    rather than guessed.
    """
    assets: list[dict[str, Any]] = []
    for block in re.split(r"Digital certificate information for", text or "")[1:]:
        head = block.split(":", 1)[0]
        tokens = head.split()
        label = ""
        if tokens:
            wrap = re.search(r"label\(([A-Za-z0-9@#$.\-_]+)\)", tokens[-1], re.IGNORECASE)
            label = wrap.group(1) if wrap else tokens[-1].strip("'\"")
            if label.lower() in ("certificate", "auth", "site", "id") and len(tokens) >= 2:
                label = tokens[-2].strip("'\"")

        scope = "personal"
        head_l = head.lower()
        if "site" in head_l:
            scope = "site"
        elif "certauth" in head_l or "cert auth" in head_l:
            scope = "certauth"
        elif "ring" in head_l:
            scope = "ring"

        def grab(pattern: str) -> str:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        def grab_int(pattern: str) -> int | None:
            m = re.search(pattern, block, re.IGNORECASE)
            return int(m.group(1)) if m else None

        sig_alg = grab(r"Algorithm(?: Signature)?:\s*([A-Za-z0-9]+(?:With[A-Za-z0-9]+)?)")
        key_size = grab_int(r"(?:Certificate Key Size|Key Size)[:\s]+(\d+)")
        expiry_iso = ""
        expiry_date = None
        m = re.search(r"Expiration Date:?\s*(\d{4})[-/](\d{2})[-/](\d{2})", block)
        if m:
            try:
                expiry_date = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                expiry_iso = expiry_date.isoformat()
            except ValueError:
                expiry_date = None

        key_usage = sorted({u.strip().title()
                            for usage_line in re.findall(r"Key Usage:\s*([A-Za-z ,]+)", block)
                            for u in usage_line.replace(",", " ").split() if u.strip()})

        assets.append(_row(
            SOURCE_RACF,
            label=label,
            scope=scope,
            subject=grab(r"Subject:\s*(.+)"),
            issuer=grab(r"Issuer Name:\s*(.+)"),
            algorithm=(sig_alg.split("With")[-1] if sig_alg else "RSA").upper(),
            signature_algorithm=sig_alg.upper(),
            key_size=key_size,
            purpose="signature",
            status=grab(r"Status:?\s*([A-Z]+)").upper(),
            key_usage=key_usage,
            expires=expiry_iso,
            _expiry_date=expiry_date,
            file_path=f"racf://{label or 'certificate'}",
        ))
    return assets


# --------------------------------------------------------------------------- #
# 2. ICSF — CKDS/PKDS key inventory CSV (delegates to the banking parser)
# --------------------------------------------------------------------------- #

def normalize_icsf_keys(text: str) -> list[dict[str, Any]]:
    """ICSF key inventory — CSV with at least LABEL + ALGORITHM/KEYTYPE."""
    from cbom.banking import normalize_icsf_csv

    return normalize_icsf_csv(text)


# --------------------------------------------------------------------------- #
# 3. DB2 for z/OS — TLS configuration extract
# --------------------------------------------------------------------------- #

def normalize_db2_tls(text: str) -> list[dict[str, Any]]:
    """Parse DB2 TLS extracts into transport-crypto findings.

    Accepted shape — optional ``[database NAME]`` section headers plus
    ``KEY = VALUE`` configuration lines (as captured from
    ``db2 get dbm cfg`` / ``db2set -all`` / DSNZPARM dumps)::

        [database PAYDB]
        SSL_VERSIONS = TLSv1.2
        SSL_CIPHERSPECS = TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256
        SSL_SVC_LABEL = paydb-cert-2026

    Databases without any SSL keys still matter: they produce a finding with
    ``ssl_enabled=False`` so coverage gaps surface in the BOM.
    """
    findings: list[dict[str, Any]] = []
    section: dict[str, Any] = {}
    name = "DSNZPARM (subsystem default)"
    saw_section = False

    def flush() -> None:
        nonlocal section
        if not section and not saw_section:
            return
        versions = [v.strip().upper() for v in str(section.get("ssl_versions", "")).split(",") if v.strip()]
        ciphers = [c.strip().upper() for c in str(section.get("ssl_cipherspecs", "")).split(",") if c.strip()]
        ssl_on = bool(versions or ciphers or section.get("ssl_svc_label"))
        below_floor = [v for v in versions if _tls_rank(v) < _tls_rank(_TLS_FLOOR)]
        weak_ciphers = sorted({c for c in ciphers for tok in _DB2_WEAK_CIPHER_TOKENS if tok in c})
        findings.append(_row(
            SOURCE_DB2,
            database=name,
            ssl_enabled=ssl_on,
            tls_versions=versions,
            ciphers=ciphers,
            cert_label=str(section.get("ssl_svc_label", "") or ""),
            below_floor=below_floor,
            weak_ciphers=weak_ciphers,
            algorithm="TLS",
            key_size=None,
            purpose="key_exchange",
            file_path=f"db2://{name}",
            note="" if ssl_on else "no TLS keys found in the extract — transport possibly cleartext",
        ))
        section = {}

    for raw in (text or "").splitlines():
        line = raw.strip()
        sec = re.match(r"^\[database\s+(.+?)\]$", line, re.IGNORECASE)
        if sec:
            flush()
            name = sec.group(1).strip()
            saw_section = True
            continue
        kv = re.match(r"^([A-Za-z_ ]+?)\s*[:=]\s*(.*)$", line)
        if kv and kv.group(1).strip().upper().startswith("SSL"):
            section[kv.group(1).strip().lower()] = kv.group(2).strip()
    flush()
    return findings


# --------------------------------------------------------------------------- #
# 4. CICS TS — TCPIPSERVICE CSD extract
# --------------------------------------------------------------------------- #

def normalize_cics_tcpservice(text: str) -> list[dict[str, Any]]:
    """Parse CICS ``TCPIPSERVICE`` definitions into TLS-edge findings.

    Accepted shape — one definition per parenthesized attribute list::

        TCPIPSERVICE(PAYMENTS) GROUP(PAYG) PORTNUMBER(9443)
            PROTOCOL(https) SSLTYPE(clientauth) CERTIFICATE(PAYGW)
            CIPHERS(TLS_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_128_CBC_SHA)

    ``PROTOCOL(http)`` or missing SSLTYPE yields an unencrypted-endpoint
    finding so cleartext CICS surfaces are visible.
    """
    findings: list[dict[str, Any]] = []
    for m in re.finditer(
        r"TCPIPSERVICE\(([^)]+)\)(.*?)(?=TCPIPSERVICE\(|\Z)",
        text or "", re.IGNORECASE | re.DOTALL,
    ):
        name, body = m.group(1).strip(), m.group(2)

        def attr(key: str) -> str:
            a = re.search(rf"{key}\(([^)]*)\)", body, re.IGNORECASE)
            return a.group(1).strip() if a else ""

        protocol = attr("PROTOCOL").lower()
        port = attr("PORTNUMBER")
        ssltype = attr("SSLTYPE").lower()
        cert = attr("CERTIFICATE")
        ciphers = [c.strip().upper() for c in attr("CIPHERS").replace(",", " ").split() if c.strip()]
        encrypted = protocol == "https" or bool(ssltype)
        weak = sorted({c for c in ciphers for tok in _DB2_WEAK_CIPHER_TOKENS if tok in c})
        findings.append(_row(
            SOURCE_CICS,
            service=name,
            port=port,
            protocol=protocol,
            ssltype=ssltype,
            cert_label=cert,
            ciphers=ciphers,
            weak_ciphers=weak,
            encrypted=encrypted,
            algorithm="TLS",
            key_size=None,
            purpose="key_exchange",
            file_path=f"cics://{name}",
            note="" if encrypted else f"cics tcpservice {name} is cleartext ({protocol or 'no protocol'})",
        ))
    return findings


# --------------------------------------------------------------------------- #
# Aggregation — the mainframe control view
# --------------------------------------------------------------------------- #

def mainframe_assessment(
    findings: Iterable[Mapping[str, Any]],
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Aggregate z/OS findings into the supervisor-facing control view.

    Counts by source, flags cleartext/below-TLS1.2/weak-cipher transport,
    certificates expiring inside ``EXPIRY_WARN_DAYS`` and quantum-vulnerable
    public-key material (NIST IR 8547 classes via ``cbom.banking``).
    """
    rows = [dict(f) for f in findings]
    this_date = today or datetime.now(timezone.utc).date()
    by_source = {s: 0 for s in ("racf", "icsf", "db2", "cics")}
    cleartext: list[dict[str, Any]] = []
    weak_transport: list[dict[str, Any]] = []
    expiring: list[dict[str, Any]] = []
    quantum: list[dict[str, Any]] = []

    for f in rows:
        by_source[f.get("source", "")] = by_source.get(f.get("source", ""), 0) + 1
        src = f.get("source")
        if src in ("db2", "cics"):
            encrypted = f.get("ssl_enabled", f.get("encrypted", True))
            if not encrypted:
                cleartext.append({"location": f.get("file_path"), "note": f.get("note", "")})
            weak = f.get("weak_ciphers") or []
            below = f.get("below_floor") or []
            if weak or below:
                weak_transport.append({"location": f.get("file_path"),
                                       "weak_ciphers": weak, "below_floor": below})
        vuln = quantum_vulnerability(f.get("algorithm"), f.get("key_size"))
        if vuln["quantum_vulnerable"] and vuln["transition"] != "grover_impacted_no_deadline":
            quantum.append({"location": f.get("file_path"), "algorithm": f.get("algorithm"),
                            "key_size": f.get("key_size"), "transition": vuln["transition"],
                            "deadline": vuln["deadline"]})
        exp = f.get("_expiry_date")
        if isinstance(exp, date):
            days_left = (exp - this_date).days
            if days_left <= EXPIRY_WARN_DAYS:
                expiring.append({"location": f.get("file_path"), "expires": exp.isoformat(),
                                 "days_left": days_left})

    expiring.sort(key=lambda e: e["days_left"])
    return {
        "total_findings": len(rows),
        "by_source": {k: v for k, v in by_source.items() if v},
        "cleartext_endpoints": cleartext,
        "weak_transport": weak_transport,
        "certificates_expiring": expiring,
        "expiry_warn_days": EXPIRY_WARN_DAYS,
        "quantum_vulnerable": quantum,
        "subsystem_coverage": {
            "racf_certificates": by_source.get("racf", 0),
            "icsf_keys": by_source.get("icsf", 0),
            "db2_tls_configs": by_source.get("db2", 0),
            "cics_tls_endpoints": by_source.get("cics", 0),
        },
    }


INGEST_KINDS: dict[str, Any] = {
    "racdcert": normalize_racdcert_rich,
    "icsf_csv": normalize_icsf_keys,
    "db2_tls": normalize_db2_tls,
    "cics_tcpservice": normalize_cics_tcpservice,
}
