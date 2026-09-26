"""International banking jurisdictions — regulator packs, SWIFT CSP, key lifecycle.

Extends the platform from "a bank" to "an international banking group":

1. **Jurisdiction packs** (`JURISDICTION_PACKS`, `jurisdiction_pack`) — the
   supervisory landscape per jurisdiction a bank group operates in (EU/ECB+DORA,
   UK, US, Singapore, Hong Kong, Switzerland, India, Japan, Canada, UAE),
   each with the regulator names, the evidence artifacts this platform already
   produces, and dated milestones. Facts are conservative and flagged for
   verification — this is navigation, not legal advice.
2. **SWIFT CSP support** (`swift_cscf_assessment`) — the annual Customer
   Security Programme attestation needs exactly the evidence the platform
   produces (HSM policies, PKI lifecycle, transport encryption, custody
   segregation). Controls are theme-mapped with pointers to the CSCF version
   in force — control IDs are the bank's to pin, never invented here.
3. **Key lifecycle** (`key_lifecycle`) — NIST SP 800-57 key states over the
   unified inventory (ICSF/RACF/scanner rows): state classification,
   rotation-due flags where activation dates exist, expired/immediate-action
   registers. Conservative: missing dates mean "record activation date", not
   a fabricated pass.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

from cbom.banking import quantum_vulnerability

# --------------------------------------------------------------------------- #
# Jurisdiction packs
# --------------------------------------------------------------------------- #

_J = (
    {
        "code": "eu",
        "region": "European Union",
        "regulators": ["ECB (SSM)", "national competent authorities (NCAs)", "EBA"],
        "display": "European Union — ECB / DORA",
        "framework": "ecb",
        "languages": ["en", "de", "fr", "es", "it"],
        "milestones": [
            {"label": "DORA (Regulation (EU) 2022/2554) applies", "date": "2025-01-17",
             "note": "ICT risk management, register of information, TLPT — in force"},
            {"label": "ECB cyber resilience action plans", "date": "2026-10-31",
             "note": "supervisory letter to significant institutions"},
            {"label": "ECB quantum-risk follow-up letter", "date": None,
             "note": "pre-announced by the ECB Chair — cryptographic inventory "
                     "(CBOM), roadmap, HNDL and third-party readiness expected"},
            {"label": "NIST IR 8547: 112-bit public-key deprecated", "date": "2030-12-31",
             "note": "global crypto milestone referenced by EU supervisors"},
            {"label": "NIST IR 8547: quantum-vulnerable public-key disallowed", "date": "2035-12-31",
             "note": "migration must complete"},
        ],
        "artifacts": [
            "Cryptographic inventory: GET /api/v1/technology-bom",
            "HNDL register: GET /api/v1/banking/hndl",
            "Quantum roadmap: GET /api/v1/banking/roadmap",
            "Supervisory action plan: GET /api/v1/banking/action-plan/export (lang=de/fr/es/it)",
        ],
    },
    {
        "code": "uk",
        "region": "United Kingdom",
        "regulators": ["FCA", "PRA", "Bank of England"],
        "display": "United Kingdom — FCA / PRA",
        "framework": "fca",
        "languages": ["en"],
        "milestones": [
            {"label": "Operational resilience (PS21/3) — ongoing compliance", "date": None,
             "note": "important business services within impact tolerances; emerging "
                     "risk scenarios (incl. quantum) expected in testing"},
            {"label": "Critical third parties regime (FSMA 2023)", "date": "2025",
             "note": "FCA/PRA oversight of material third parties"},
        ],
        "artifacts": [
            "Scenario-test evidence: GET /api/v1/banking/action-plan",
            "Runtime verification: GET /api/v1/technology-bom/runtime-verify",
        ],
    },
    {
        "code": "us",
        "region": "United States",
        "regulators": ["Federal Reserve", "OCC", "FDIC", "NYDFS", "state agencies"],
        "display": "United States — Fed / OCC / NYDFS",
        "framework": "generic",
        "languages": ["en"],
        "milestones": [
            {"label": "NIST IR 8547 transition governs crypto timelines", "date": "2035-12-31",
             "note": "US federal crypto standard; examiners reference NIST guidance"},
            {"label": "NYDFS Part 500 amended requirements", "date": "2023-11-01",
             "note": "CISO accountability, MFA, 72h ransomware notice — in force"},
        ],
        "artifacts": [
            "Control evidence crosswalk: GET /api/v1/banking/compliance-crosswalk",
            "Admission gate: GET /api/v1/technology-bom/admission",
        ],
    },
    {
        "code": "sg",
        "region": "Singapore",
        "regulators": ["MAS"],
        "display": "Singapore — MAS",
        "framework": "generic",
        "languages": ["en"],
        "milestones": [
            {"label": "MAS Technology Risk Management Guidelines", "date": "2021-01-18",
             "note": "binding expectations for financial institutions"},
            {"label": "MAS quantum-readiness engagements", "date": None,
             "note": "industry outreach on PQC transition planning — track notices"},
        ],
        "artifacts": [
            "Technology risk evidence: GET /api/v1/banking/action-plan",
            "Inventory: GET /api/v1/technology-bom",
        ],
    },
    {
        "code": "hk",
        "region": "Hong Kong SAR",
        "regulators": ["HKMA"],
        "display": "Hong Kong — HKMA",
        "framework": "generic",
        "languages": ["en", "zh"],
        "milestones": [
            {"label": "HKMA cyber resilience assessment framework", "date": None,
             "note": "C-RAF maturity-based supervision"},
        ],
        "artifacts": ["Inventory + assurance: GET /api/v1/technology-bom/assurance"],
    },
    {
        "code": "ch",
        "region": "Switzerland",
        "regulators": ["FINMA"],
        "display": "Switzerland — FINMA",
        "framework": "generic",
        "languages": ["en", "de", "fr"],
        "milestones": [
            {"label": "FINMA Circular 2023/1 'Cyber risks'", "date": "2023-01-01",
             "note": "minimum controls for banks, in force"},
        ],
        "artifacts": ["Control crosswalk: GET /api/v1/banking/compliance-crosswalk"],
    },
    {
        "code": "in",
        "region": "India",
        "regulators": ["RBI", "SEBI", "IRDAI"],
        "display": "India — RBI",
        "framework": "rbi",
        "languages": ["en", "hi"],
        "milestones": [
            {"label": "RBI Master Direction on IT Governance, Risk and Controls", "date": "2023-04-01",
             "note": "comprehensive technology-risk obligations for regulated entities"},
            {"label": "RBI post-quantum readiness communications", "date": None,
             "note": "supervisory engagement on PQC transition — track circulars"},
        ],
        "artifacts": [
            "Inventory + roadmap: GET /api/v1/banking/roadmap",
            "Mainframe (core banking) coverage: GET /api/v1/banking/mainframe",
        ],
    },
    {
        "code": "jp",
        "region": "Japan",
        "regulators": ["JFSA (FSA)", "BOJ"],
        "display": "Japan — JFSA / BOJ",
        "framework": "generic",
        "languages": ["en", "ja"],
        "milestones": [
            {"label": "Cryptographic transition planning (Cabinet Office/Crypto-Math)", "date": None,
             "note": "Japan's crypto-agility movement — track JFSA guidance"},
        ],
        "artifacts": ["Roadmap: GET /api/v1/banking/roadmap"],
    },
    {
        "code": "ca",
        "region": "Canada",
        "regulators": ["OSFI", "Bank of Canada"],
        "display": "Canada — OSFI",
        "framework": "generic",
        "languages": ["en", "fr"],
        "milestones": [
            {"label": "OSFI Guideline B-13 Technology and Cyber Risk Management", "date": "2024-01-01",
             "note": "in force; includes cryptographic agility expectations"},
            {"label": "OSFI/BoC quantum-ready engagements", "date": None,
             "note": "PQC readiness outreach to FRFIs"},
        ],
        "artifacts": ["Action plan: GET /api/v1/banking/action-plan?framework=generic"],
    },
    {
        "code": "ae",
        "region": "United Arab Emirates",
        "regulators": ["CBUAE", "DFSA (DIFC)", "FSRA (ADGM)", "UAE Data Office (PDPL)"],
        "display": "UAE — CBUAE / DFSA (DIFC) / FSRA (ADGM) / UAE Data Office",
        "framework": "cbuae",
        "languages": ["en", "ar"],
        "milestones": [
            {"label": "DIFC Data Protection Law No. 5/2020 — in force", "date": "2020-07-01",
             "note": "GDPR-aligned regime in the Dubai International Financial Centre; Art. 23 technical "
                     "measures (pseudonymisation, encryption); 72h breach notification statutory; "
                     "private right of action since July 2025"},
            {"label": "ADGM Data Protection Regulations 2021 — in force", "date": "2021-08-14",
             "note": "Abu Dhabi free zone; GDPR-equivalent technical measures; 72h breach notification "
                     "statutory; fines up to USD 28M per offence"},
            {"label": "UAE Federal PDPL (Decree-Law No. 45/2021) — in force", "date": "2022-01-02",
             "note": "Mainland personal-data regime enforced by the UAE Data Office; Art. 20 names "
                     "encryption and pseudonymisation; 72h breach notification per Data Office guidance; "
                     "fines up to AED 5M; enforcement escalating from 2025; extraterritorial reach"},
            {"label": "CBUAE Cybersecurity Framework — 9 domains, in force", "date": None,
             "note": "Governance, risk management, architecture, identity management, third-party risk, "
                     "data & information protection, threat management, incident management, awareness; "
                     "applies to all licensed financial institutions (banks, exchange houses, finance "
                     "companies, payment service providers)"},
            {"label": "CBUAE Information Security Standards — ISO/IEC 27001-aligned, in force", "date": None,
             "note": "Annual third-party security assessment, quarterly vulnerability scanning, annual "
                     "penetration testing, MFA for privileged/remote/customer-facing access, 5-year log "
                     "retention, RTO 4h / RPO 1h for critical systems"},
            {"label": "DIFC private right of action under DP Law — live", "date": "2025-07-01",
             "note": "Data subjects may bring claims in DIFC courts; documented technical measures are "
                     "the primary defence — keep scan evidence current"},
            {"label": "Post-quantum: track CBUAE/DIFC/ADGM supervisory notices", "date": None,
             "note": "No UAE-specific PQC mandate published to date; NIST IR 8547 transition (public-key "
                     "algorithms deprecated after 2030, disallowed after 2035) remains the de-facto "
                     "reference examiners cite; HNDL register + migration roadmap are the expected evidence"},
        ],
        "artifacts": [
            "UAE policy rule pack: services/policy/rule_definitions/uae/ (CBUAE/DIFC/PDPL/ADGM rules, deterministic)",
            "Action plan pinned to this jurisdiction: GET /api/v1/banking/action-plan?jurisdiction=ae",
            "Supervisor reference document: GET /api/v1/banking/action-plan/export?jurisdiction=ae&format=html",
            "Control crosswalk: GET /api/v1/banking/compliance-crosswalk",
            "HSM fleet + quantum exposure: GET /api/v1/banking/hsm",
        ],
    },
)

JURISDICTION_PACKS: dict[str, dict[str, Any]] = {p["code"]: p for p in _J}


def jurisdiction_pack(code: str) -> dict[str, Any] | None:
    return JURISDICTION_PACKS.get((code or "").lower())


# --------------------------------------------------------------------------- #
# SWIFT Customer Security Programme (CSP) — CSCF evidence mapping
# --------------------------------------------------------------------------- #

def swift_cscf_assessment(
    state: Mapping[str, Any],
    *,
    hsm_fleet: Mapping[str, Any] | None = None,
    mainframe: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Map SWIFT CSCF control *themes* to the evidence this platform produces.

    The CSCF is versioned annually and control IDs shift between versions —
    this returns the theme, the platform evidence, and a status; the bank pins
    the exact control IDs from its CSCF version during independent assessment.
    """
    layers = (state or {}).get("layers") or {}
    cbom = (layers.get("cbom") or {}).get("components") or []
    certs = (layers.get("certificates") or {}).get("count") or 0
    fingerprint = (state or {}).get("fingerprint")

    fleet = hsm_fleet or {}
    custody_recorded = int(fleet.get("custody_recorded") or 0)
    fleet_total = int(fleet.get("total") or 0)
    pqc_ready = int(fleet.get("pqc_ready") or 0)

    mf = mainframe or {}
    cleartext = mf.get("cleartext_endpoints") or []
    weak_transport = mf.get("weak_transport") or []

    weak_legacy = 0
    quantum_pubkey = 0
    for comp in cbom:
        vuln = quantum_vulnerability(comp.get("algorithm"), comp.get("key_size"))
        if vuln["quantum_vulnerable"] and vuln["transition"] == "grover_impacted_no_deadline":
            weak_legacy += 1
        elif vuln["quantum_vulnerable"]:
            quantum_pubkey += 1

    def status_of(ok: bool, data: bool) -> str:
        if not data:
            return "unknown"     # no data yet — collect evidence
        return "satisfied" if ok else "gap"

    controls = [
        {
            "theme": "Hardware security modules — local policies & firmware",
            "status": status_of(fleet_total > 0 and pqc_ready == fleet_total and custody_recorded == fleet_total, fleet_total > 0),
            "evidence": f"{fleet_total} HSMs discovered; custody recorded on {custody_recorded}; PQC-ready {pqc_ready}",
            "detail": "CSCF requires documented HSM policy, tamper evidence and firmware control — pin to your CSCF version's HSM controls",
            "endpoint": "/api/v1/banking/hsm/deep",
        },
        {
            "theme": "PKI & certificate lifecycle management",
            "status": status_of(certs > 0, True),
            "evidence": f"{certs} certificates in the inventory",
            "detail": "Track expiries, issuers and trust anchors; RACF/CICS/DB2 certificate labels flow into the same inventory",
            "endpoint": "/api/v1/technology-bom?layer=certificates",
        },
        {
            "theme": "Transport encryption of the local infrastructure",
            "status": status_of(not cleartext and not weak_transport, bool(mf)),
            "evidence": f"{len(cleartext)} cleartext endpoints, {len(weak_transport)} weak/below-floor transport configs (z/OS DB2/CICS)",
            "detail": "Encryption in transit across the SWIFT infrastructure and connected backends",
            "endpoint": "/api/v1/banking/mainframe/assessment",
        },
        {
            "theme": "Cryptographic algorithm hygiene",
            "status": status_of(weak_legacy == 0, len(cbom) > 0),
            "evidence": f"{weak_legacy} weak-legacy instances (DES/3DES/RC4/MD5/SHA-1), {quantum_pubkey} quantum-vulnerable public-key instances",
            "detail": "Retire broken primitives; plan the PQC transition for signature infrastructure",
            "endpoint": "/api/v1/banking/roadmap",
        },
        {
            "theme": "Segregation of duties & key-ceremony control",
            "status": status_of(fleet_total > 0 and custody_recorded == fleet_total, fleet_total > 0),
            "evidence": "M-of-N split-knowledge recorded on HSM assets where declared",
            "detail": "Dual control / quorum on key generation, backup and restoration",
            "endpoint": "/api/v1/banking/hsm",
        },
        {
            "theme": "Evidence, audit trail & attestation support",
            "status": "satisfied" if fingerprint else "unknown",
            "evidence": f"BOM fingerprint {str(fingerprint)[:16]}…; signed evidence packages; hash-chained audit log",
            "detail": "Independent assessment and annual attestation need reproducible evidence",
            "endpoint": "/api/v1/technology-bom/evidence-package",
        },
    ]
    gaps = [c for c in controls if c["status"] == "gap"]
    unknown = [c for c in controls if c["status"] == "unknown"]
    return {
        "programme": "SWIFT Customer Security Programme (CSP)",
        "note": ("Control themes mapped to platform evidence; pin CSCF control IDs "
                 "from the version in force during independent assessment."),
        "controls": controls,
        "gaps": len(gaps),
        "unknown": len(unknown),
        "attestation_ready": not gaps and not unknown,
    }


# --------------------------------------------------------------------------- #
# Key lifecycle — NIST SP 800-57 states
# --------------------------------------------------------------------------- #

_STATE_MAP = {
    "ACTIVE": "active", "TRUST": "active", "OPERATIONAL": "active",
    "PRE-ACTIVATION": "pre_activation", "PREACTIVATION": "pre_activation",
    "INITIAL": "pre_activation", "PENDING": "pre_activation",
    "SUSPENDED": "suspended",
    "RETIRED": "deactivated", "DEACTIVATED": "deactivated", "INACTIVE": "deactivated",
    "COMPROMISED": "compromised",
    "DESTROYED": "destroyed", "ARCHIVED": "destroyed",
}

# Default cryptoperiod ceilings (years ACTIVE) — NIST SP 800-57 Part 1 Rev. 5
# recommends protecting against key exhaustion; configure per the bank's CPA.
_DEFAULT_MAX_ACTIVE_YEARS = {
    "symmetric": 2,
    "private_signing": 3,
    "public_key": 5,
    "default": 2,
}


def _key_class(algorithm: str) -> str:
    alg = (algorithm or "").upper()
    if alg in ("AES", "DES", "3DES", "TDES", "HMAC", "HMAC-SHA256", "CHACHA20") or alg.startswith("AES"):
        return "symmetric"
    if alg in ("RSA", "ECDSA", "DSA", "ED25519", "ED448"):
        return "private_signing"
    return "default"


def classify_key_state(status: str) -> str:
    return _STATE_MAP.get((status or "").strip().upper(), "unknown")


def key_lifecycle(
    keys: Iterable[Mapping[str, Any]],
    *,
    policy: Mapping[str, int] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Key lifecycle register over inventory rows (ICSF/RACF/scanner sources).

    Each key row: ``label``/``file_path``, ``algorithm``, ``key_size``,
    ``status`` (the extract's status string), optional ``activated_at`` /
    ``expires`` (ISO dates), ``source``. Rotation is only flagged when an
    activation date exists — otherwise the register says "record activation
    date", keeping the output honest.
    """
    this_date = today or datetime.now(timezone.utc).date()
    pol = {**_DEFAULT_MAX_ACTIVE_YEARS, **(policy or {})}
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}

    for k in keys:
        state = classify_key_state(str(k.get("status") or ""))
        counts[state] = counts.get(state, 0) + 1
        klass = _key_class(str(k.get("algorithm") or ""))
        row = {
            "location": k.get("file_path") or k.get("label") or "",
            "label": k.get("label") or "",
            "algorithm": k.get("algorithm") or "",
            "key_size": k.get("key_size"),
            "state": state,
            "class": klass,
            "expires": k.get("expires") or "",
            "rotation_status": "unknown",
            "detail": "",
        }
        if state == "compromised":
            row["detail"] = "IMMEDIATE ACTION — compromised key"
        if state == "unknown":
            row["detail"] = row["detail"] or "status not recorded in the extract — reconcile with the key custodian"
        exp = k.get("expires")
        if isinstance(exp, str) and len(exp) >= 10:
            try:
                ed = date.fromisoformat(exp[:10])
                days = (ed - this_date).days
                if days < 0:
                    row["state"] = row["state"] if row["state"] != "active" else "expired"
                    counts["expired"] = counts.get("expired", 0) + 1
                    row["detail"] = row["detail"] or f"expired {abs(days)} days ago"
                elif days <= 30:
                    row["rotation_status"] = "renewal_due"
                    row["detail"] = row["detail"] or f"expires in {days} days"
            except ValueError:
                pass
        act = k.get("activated_at")
        if isinstance(act, str) and len(act) >= 10:
            try:
                ad = date.fromisoformat(act[:10])
                years_active = (this_date - ad).days / 365.25
                ceiling = pol.get(klass, pol["default"])
                if years_active > ceiling:
                    row["rotation_status"] = "overdue"
                    row["detail"] = row["detail"] or f"active {years_active:.1f}y > {ceiling}y cryptoperiod"
                else:
                    row["rotation_status"] = "within_policy"
            except ValueError:
                pass
        if row["rotation_status"] == "unknown" and state in ("active", "expired"):
            row["rotation_status"] = "record_activation_date"
        rows.append(row)

    order = {"compromised": 0, "expired": 1, "deactivated": 2, "suspended": 3,
             "active": 4, "pre_activation": 5, "destroyed": 6, "unknown": 7}
    rows.sort(key=lambda r: (order.get(r["state"], 9), r["rotation_status"] != "overdue"))
    return {
        "standard": "NIST SP 800-57 Part 1 key states",
        "policy_defaults": {k: pol[k] for k in sorted(pol)},
        "total": len(rows),
        "by_state": counts,
        "compromised": counts.get("compromised", 0),
        "expired": counts.get("expired", 0),
        "rotation_overdue": sum(1 for r in rows if r["rotation_status"] == "overdue"),
        "activation_dates_missing": sum(1 for r in rows if r["rotation_status"] == "record_activation_date"),
        "keys": rows,
    }
