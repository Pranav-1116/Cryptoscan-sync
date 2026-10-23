"""Banking & Regulatory — the financial-institution layer over the Technology BOM.

Fills the four bank-readiness gaps in the same doctrine as ``assurance.py``:
pure, deterministic functions over the materialized BOM state (no DB / I/O /
FastAPI), so every rule is unit-testable and every consumer gets the same
answer.

1. **Quantum-vulnerability classification** (`quantum_vulnerability`) —
   NIST IR 8547 transition class per algorithm/key-size (deprecated after
   2030 / disallowed after 2035; symmetric hashes noted as Grover-impacted
   with no public-key deadline).
2. **HNDL register** (`hndl_register`) — Harvest-Now-Decrypt-Later exposure:
   quantum-vulnerable public-key crypto protecting data whose confidentiality
   horizon outlives the migration window (the exact register the ECB's
   announced quantum letter and UK FCA PS21/3 expect banks to produce).
3. **Migration roadmap** (`migration_roadmap`) — phase plan anchored on the
   IR 8547 milestones (2026 weak-legacy purge -> 2030 112-bit deprecation ->
   2035 disallowed), with actions and owners per phase.
4. **FIPS validation mapping** (`fips_validation`) — family-level FIPS 140
   validation status for a crypto module; conservative "unknown — lookup
   required" default, extensible from a supplied table (never fabricates
   certificate numbers).
5. **HSM fleet readiness** (`assess_hsm_fleet`) — per-HSM PQC readiness and
   FIPS status from hardware-asset records; only claims PQC capability when
   the asset itself declares it.
6. **Mainframe ingest parsers** (`normalize_racdcert`, `normalize_icsf_csv`)
   — turn z/OS security extracts (RACF ``RACDCERT LIST`` text, ICSF key
   inventory CSV) into the same crypto-asset rows the scanners produce, so
   mainframe crypto lands in ONE unified BOM.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

# --------------------------------------------------------------------------- #
# NIST IR 8547 transition classes (Initial Public Draft, Nov 2024)
# --------------------------------------------------------------------------- #
DEPRECATED_AFTER_2030 = "deprecated_after_2030"
DISALLOWED_AFTER_2035 = "disallowed_after_2035"
GROVER_IMPACTED = "grover_impacted_no_deadline"
NOT_VULNERABLE = "not_quantum_vulnerable"

# Public-key families that a cryptographically relevant quantum computer
# breaks (Shor). Key size decides the IR 8547 transition class:
# 112-bit security -> deprecated after 2030; >= 128-bit -> disallowed after
# 2035 (everything must be gone by 2035 either way).
_PQC_VULNERABLE_FAMILIES = (
    "RSA", "DSA", "ECDSA", "EC", "ECC", "ECDH", "EDDSA", "ED25519", "ED448",
    "DH", "DIFFIE-HELLMAN", "MQV", "SM2", "X25519", "X448",
)
_WEAK_LEGACY = ("DES", "3DES", "TDES", "RC4", "RC2", "MD5", "SHA1")

# Default data-confidentiality horizons (years) by crypto purpose, used when
# the caller does not supply a data classification. Banking-typical: payment
# keys and key-exchange material must stay confidential ~a decade.
_DEFAULT_HORIZONS = {
    "key_exchange": 10,
    "key transport": 10,
    "encryption": 10,
    "data encryption": 10,
    "signature": 7,
    "signing": 7,
    "authentication": 5,
}

_HNDL_THRESHOLD_YEARS = 5  # confidentiality horizon beyond which HNDL applies


def _norm(value: Any) -> str:
    return str(value or "").strip().upper()


def quantum_vulnerability(algorithm: str, key_size: int | None = None) -> dict[str, Any]:
    """Classify one algorithm (+ optional key size) per NIST IR 8547."""
    from shared_models.quantum_classify import quantum_verdict

    parsed = quantum_verdict(algorithm)
    if not parsed["recognized"] or (parsed["family"].endswith("-pqc") and parsed["status"] != "ALLOWED"):
        return {"family": parsed["algorithm"] or "UNKNOWN", "quantum_vulnerable": None,
            "transition": "unknown", "deadline": None, "requires_review": True,
            "note": "Unrecognized or nonapproved algorithm; neither resistance nor deployment readiness established"}
    alg = _norm(algorithm)
    # Signature bundles: "SHA256WITHRSA" / "SHA1WITHECDSA" — the family is the
    # tail; a weak hash head (SHA-1/MD5) is itself disqualifying today.
    if "WITH" in alg:
        hash_head, sig_tail = alg.split("WITH", 1)
        sig_tail = sig_tail.split("ANDMGF")[0]
        for weak in ("MD5", "SHA1"):
            if hash_head == weak or hash_head.startswith(weak):
                return {
                    "family": weak,
                    "quantum_vulnerable": True,
                    "transition": GROVER_IMPACTED,
                    "deadline": None,
                    "legacy": True,
                    "note": f"{weak} signature hash is already impaired — purge regardless of PQC",
                }
        base = sig_tail.strip()
    else:
        base = alg.split("WITH")[0].strip()
    for weak in _WEAK_LEGACY:
        if base == weak or base.startswith(weak + "-") or base.startswith(weak + " "):
            return {
                "family": weak,
                "quantum_vulnerable": True,
                "transition": GROVER_IMPACTED,
                "deadline": None,
                "legacy": True,
                "note": f"{weak} is already broken/impaired classically — purge regardless of PQC",
            }
    for family in _PQC_VULNERABLE_FAMILIES:
        if base == family or base.startswith(family + "-") or base.startswith(family + "WITH"):
            bits: int | None = None
            try:
                bits = int(key_size) if key_size is not None else None
            except (TypeError, ValueError):
                bits = None
            # Security class from KEY size: RSA/DSA/DH carry ~N/16 security bits
            # (2048 -> 112-bit, 3072 -> 128-bit); EC/Ed curves carry ~bits/2
            # (P-256 -> 128-bit, P-224 -> 112-bit). Unknown size defaults to the
            # 112-bit class so the item lands on the EARLIER deadline.
            if family in ("RSA", "DSA", "DH", "DIFFIE-HELLMAN", "MQV"):
                security = ">=128-bit" if (bits or 0) >= 3072 else "112-bit"
            else:
                security = ">=128-bit" if (bits is None or bits >= 256) else "112-bit"
            transition = DEPRECATED_AFTER_2030 if security == "112-bit" else DISALLOWED_AFTER_2035
            return {
                "family": family,
                "quantum_vulnerable": True,
                "transition": transition,
                "deadline": 2030 if transition == DEPRECATED_AFTER_2030 else 2035,
                "note": f"Shor-vulnerable public-key family ({security} class) — migrate to ML-DSA/ML-KEM",
            }
    if base.startswith("AES") or base.startswith("CHACHA"):
        return {
            "family": base.split("-")[0],
            "quantum_vulnerable": False,
            "transition": GROVER_IMPACTED,
            "deadline": None,
            "note": "symmetric — Grover halves margin; keep >=AES-128 (prefer 256)",
        }
    return {
        "family": base or "UNKNOWN",
        "quantum_vulnerable": False,
        "transition": NOT_VULNERABLE,
        "deadline": None,
        "note": "no known quantum break of this primitive class",
    }


# --------------------------------------------------------------------------- #
# HNDL register
# --------------------------------------------------------------------------- #

def _horizon_for(purpose: str, classified: Iterable[Mapping[str, Any]]) -> int:
    """Data-confidentiality horizon (years) for an asset's purpose."""
    purpose_n = _norm(purpose)
    for rule in classified:
        if _norm(rule.get("purpose")) == purpose_n or _norm(rule.get("asset")) == purpose_n:
            try:
                return int(rule.get("years") or _DEFAULT_HORIZONS.get(purpose_n.lower(), 5))
            except (TypeError, ValueError):
                continue
    return _DEFAULT_HORIZONS.get(purpose_n.lower(), 5)


def hndl_register(
    state: Mapping[str, Any],
    *,
    data_classes: Iterable[Mapping[str, Any]] | None = None,
    horizon_years: int = _HNDL_THRESHOLD_YEARS,
) -> dict[str, Any]:
    """Harvest-Now-Decrypt-Later exposure register over the materialized BOM.

    An asset is HNDL-exposed when a Shor-vulnerable public-key algorithm
    protects data whose confidentiality must outlive ``horizon_years``.
    Returns a prioritized register plus summary counts.
    """
    layers = (state or {}).get("layers") or {}
    cbom = (layers.get("cbom") or {}).get("components") or []
    classes = list(data_classes or [])
    entries: list[dict[str, Any]] = []
    unassessed: list[dict[str, Any]] = []

    for comp in cbom:
        vuln = quantum_vulnerability(comp.get("algorithm"), comp.get("key_size"))
        if vuln["quantum_vulnerable"] is None:
            unassessed.append({"bom_ref": comp.get("bom-ref") or "", "algorithm": comp.get("algorithm"), "reason": vuln["note"]})
            continue
        if not vuln["quantum_vulnerable"] or vuln["transition"] == GROVER_IMPACTED:
            continue
        purpose = comp.get("purpose") or ""
        if _norm(purpose) in {"SIGNATURE", "SIGNING", "VERIFY", "VERIFICATION"}:
            continue  # authenticity migration remains in roadmap, not HNDL ciphertext
        years = _horizon_for(purpose, classes)
        if years < horizon_years:
            continue
        deadline = vuln.get("deadline") or 2035
        years_left = deadline - datetime.now(timezone.utc).year
        exposure = "critical" if years >= 10 else "high"
        entries.append({
            "bom_ref": comp.get("bom-ref") or "",
            "algorithm": comp.get("algorithm") or "",
            "key_size": comp.get("key_size"),
            "purpose": purpose or "unspecified",
            "application": comp.get("application") or "",
            "asset": comp.get("asset") or "",
            "confidentiality_years": years,
            "transition": vuln["transition"],
            "deadline": deadline,
            "years_to_deadline": years_left,
            "exposure": exposure,
            "reason": (
                f"{comp.get('algorithm')} protects data with a {years}-year confidentiality "
                f"horizon but is {vuln['transition'].replace('_', ' ')} — decrypt-later risk today"
            ),
        })
    entries.sort(key=lambda e: (e["exposure"] != "critical", e["deadline"], -(e["confidentiality_years"])))
    by_exposure = {level: sum(1 for e in entries if e["exposure"] == level)
                   for level in ("critical", "high")}
    return {
        "threshold_years": horizon_years,
        "at_risk": True if entries else None if unassessed or not cbom else False,
        "assessment_complete": bool(cbom) and not unassessed,
        "unassessed": unassessed,
        "completeness_proven": False,
        "horizon_basis": "MODEL_DEFAULTS_UNLESS_CALLER_SUPPLIES_CLASSIFICATION",
        "total": len(entries),
        "by_exposure": by_exposure,
        "entries": entries,
    }


# --------------------------------------------------------------------------- #
# Migration roadmap (NIST IR 8547 anchored)
# --------------------------------------------------------------------------- #

_ROADMAP_PHASES = (
    {
        "phase": "P1",
        "window": "immediate",
        "deadline": 2027,
        "title": "Purge weak legacy + prove the inventory",
        "action": (
            "Retire DES/3DES/RC4/SHA-1 everywhere (admission gate FAIL), close BOM "
            "coverage gaps (mainframe, HSM, network, cloud) so the inventory is "
            "auditor-credible, and stand up continuous drift verification."
        ),
    },
    {
        "phase": "P2",
        "window": "by 2030",
        "deadline": 2030,
        "title": "Replace 112-bit public-key crypto (deprecated after 2030)",
        "action": (
            "Migrate RSA-2048/DSA-2048/DH-2048 (112-bit class) to >=128-bit classical "
            "or straight to ML-DSA/ML-KEM; begin hybrid key exchange on external TLS."
        ),
    },
    {
        "phase": "P3",
        "window": "by 2035",
        "deadline": 2035,
        "title": "Eliminate Shor-vulnerable crypto entirely (disallowed after 2035)",
        "action": (
            "Complete the move to ML-KEM/ML-DSA (FIPS 203/204) for all key "
            "establishment and signatures, including vendor/HSM fleets and long-lived "
            "signing roots."
        ),
    },
    {
        "phase": "P4",
        "window": "continuous",
        "deadline": None,
        "title": "Crypto-agility as an operating control",
        "action": (
            "Admission gate on every deploy, runtime drift watch, vendor readiness "
            "attestations, and an annually re-attested BOM for supervisors."
        ),
    },
)


def migration_roadmap(state: Mapping[str, Any], *, today: date | None = None) -> dict[str, Any]:
    """Phase plan from the materialized BOM, anchored on IR 8547 milestones."""
    layers = (state or {}).get("layers") or {}
    cbom = (layers.get("cbom") or {}).get("components") or []
    this_year = (today or datetime.now(timezone.utc).date()).year

    buckets: dict[str, dict[str, Any]] = {}
    weak_count = 0
    for comp in cbom:
        vuln = quantum_vulnerability(comp.get("algorithm"), comp.get("key_size"))
        if vuln["transition"] == GROVER_IMPACTED and vuln.get("legacy"):
            phase = "P1"
            weak_count += 1
        elif vuln["transition"] in (DEPRECATED_AFTER_2030,):
            phase = "P2"
        elif vuln["transition"] == DISALLOWED_AFTER_2035:
            phase = "P3"
        else:
            continue
        key = f"{vuln['family']}|{comp.get('key_size') or ''}"
        bucket = buckets.setdefault(key, {
            "phase": phase,
            "family": vuln["family"],
            "key_size": comp.get("key_size"),
            "transition": vuln["transition"],
            "deadline": vuln.get("deadline") or 2027,
            "count": 0,
            "applications": set(),
        })
        bucket["count"] += 1
        if comp.get("application"):
            bucket["applications"].add(comp["application"])

    phases: list[dict[str, Any]] = []
    for template in _ROADMAP_PHASES:
        items = []
        for key, b in sorted(buckets.items()):
            if b["phase"] != template["phase"]:
                continue
            years_left = (b["deadline"] - this_year) if b["deadline"] else None
            items.append({
                "family": b["family"],
                "key_size": b["key_size"],
                "transition": b["transition"],
                "instances": b["count"],
                "applications": sorted(b["applications"])[:10],
                "deadline": b["deadline"],
                "years_left": years_left,
                "overdue": bool(years_left is not None and years_left <= 0),
            })
        phases.append({**template, "items": items, "instance_count": sum(i["instances"] for i in items)})

    return {
        "anchor": "Historical NIST IR 8547 draft planning model; current applicability requires review",
        "deadline_basis": "HISTORICAL_DRAFT_PLANNING_REFERENCE_REVIEW_REQUIRED",
        "regulatory_approval": False,
        "generated_for_year": this_year,
        "phases": phases,
        "weak_legacy_instances": weak_count,
        "total_in_scope": sum(b["count"] for b in buckets.values()),
    }


# --------------------------------------------------------------------------- #
# FIPS 140 validation mapping
# --------------------------------------------------------------------------- #

# Family-level validation status only. Certificate numbers are filled in by
# the deploying bank from the NIST CMVP/_GFIPSearch_ for their exact module
# version — this table deliberately does NOT invent them.
_FIPS_BUILTIN: tuple[dict[str, Any], ...] = (
    {"match": "openssl fips provider", "status": "validated", "note": "OpenSSL FIPS Provider holds FIPS 140-3 validation (cert #4282 for 3.0); confirm your exact version"},
    {"match": "icsf", "status": "validated", "note": "IBM z/OS ICSF cryptographic modules carry FIPS 140 validations; confirm release level"},
    {"match": "thales luna", "status": "validated", "note": "Luna HSM family is FIPS 140-2/140-3 validated; firmware-dependent"},
    {"match": "utimaco", "status": "validated", "note": "Utimaco HSM family is FIPS 140-2/140-3 validated; firmware-dependent"},
    {"match": "ncipher", "status": "validated", "note": "nCipher/Entrust HSM family is FIPS 140-2/140-3 validated; firmware-dependent"},
    {"match": "gemalto", "status": "validated", "note": "Gemalto/Thales HSM family is FIPS 140-2/140-3 validated; firmware-dependent"},
    {"match": "tpm", "status": "validated", "note": "TPM 2.0 modules are commonly FIPS 140-2/140-3 validated; confirm the platform SKU"},
)


def fips_validation(
    module: str,
    algorithm: str | None = None,
    supplied: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Family/supplied lookup leads only; exact validation is not verified here."""
    mod = (module or "").strip().lower()
    if not mod:
        mod = "unknown"
    for rule in (supplied or {}).values() if isinstance(supplied, Mapping) else ():
        match = str(rule.get("match", "")).lower()
        if match and match in mod:
            return {
                "module": module,
                "algorithm": (algorithm or "").upper(),
                "status": "declared_not_verified",
                "declared_status": rule.get("status", "review"),
                "validation_verified": False,
                "cert": rule.get("cert", ""),
                "note": rule.get("note", ""),
                "source": "supplied",
            }
    for rule in _FIPS_BUILTIN:
        if rule["match"] in mod:
            return {
                "module": module,
                "algorithm": (algorithm or "").upper(),
                "status": "unknown",
                "family_match": True,
                "validation_verified": False,
                "cert": "",
                "note": "Family match only. Confirm exact module, firmware, operational environment, certificate scope and current CMVP status; validation not established.",
                "source": "builtin",
            }
    return {
        "module": module,
        "algorithm": (algorithm or "").upper(),
        "status": "unknown",
        "validation_verified": False,
        "cert": "",
        "note": "not in the built-in table — look up the exact module version at CMVP/GFIPSearch and record the certificate",
        "source": "none",
    }


# --------------------------------------------------------------------------- #
# HSM fleet readiness
# --------------------------------------------------------------------------- #

def _pqc_declared(hsm_info: Mapping[str, Any], capabilities: Mapping[str, Any]) -> tuple[str, str]:
    """A declaration/roadmap is a review lead, never verified readiness."""
    hay = " ".join(str(v) for v in (*hsm_info.values(), *capabilities.values())).upper()
    for marker in ("ML-KEM", "ML-DSA", "KYBER", "DILITHIUM", "FALCON", "SPHINCS", "LATTICE"):
        if marker in hay:
            return "declared_not_verified", f"unverified record mentions {marker}; capability/firmware/implementation not established"
    if hay.strip():
        return "not_declared", "hsm capabilities present but no PQC algorithm declared"
    return "unknown", "no capability data on the asset record"


def assess_hsm_fleet(
    hsms: Iterable[Mapping[str, Any]],
    *,
    fips_supplied: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """PQC + FIPS readiness per HSM from hardware-asset records.

    Rows come from the hardware inventory (``HardwareAsset``): manufacturer,
    model, firmware version and the ``hsm`` / ``crypto_capabilities`` JSON.
    """
    rows: list[dict[str, Any]] = []
    for h in hsms:
        hsm_info = h.get("hsm") or {}
        caps = h.get("crypto_capabilities") or h.get("capabilities") or {}
        if not isinstance(hsm_info, Mapping):
            hsm_info = {}
        if not isinstance(caps, Mapping):
            caps = {}
        firmware = (h.get("firmware") or {}).get("version") if isinstance(h.get("firmware"), Mapping) else h.get("firmware")
        model = h.get("model") or (hsm_info.get("model") if isinstance(hsm_info, Mapping) else "") or ""
        manufacturer = h.get("manufacturer") or ""
        module_name = f"{manufacturer} {model}".strip() or "unknown"
        pqc_status, pqc_evidence = _pqc_declared(hsm_info, caps)
        rows.append({
            "asset_id": h.get("asset_id") or h.get("id") or "",
            "manufacturer": manufacturer,
            "model": model,
            "firmware": firmware or "",
            "fips": fips_validation(module_name, supplied=fips_supplied),
            "pqc_status": pqc_status,
            "pqc_evidence": pqc_evidence,
            "gap": (
                "PQC capability unverified — obtain vendor evidence for exact firmware/mechanisms and a reviewed runtime exercise; declarations are not readiness"
                if pqc_status != "ready" else ""
            ),
        })
    rows.sort(key=lambda r: (r["pqc_status"] != "ready", r["fips"]["status"] != "validated"))
    ready = sum(1 for r in rows if r["pqc_status"] == "ready")
    validated = sum(1 for r in rows if r["fips"]["status"] == "validated")
    return {
        "total": len(rows),
        "pqc_ready": ready,
        "pqc_gap": len(rows) - ready,
        "pqc_declared_not_verified": sum(r["pqc_status"] == "declared_not_verified" for r in rows),
        "readiness_basis": "DECLARATIONS_ONLY_NO_RUNTIME_OR_CERTIFICATION_PROOF",
        "fips_validated_family": validated,
        "fips_unknown": len(rows) - validated,
        "ready_share": None,
        "hsms": rows,
    }


# --------------------------------------------------------------------------- #
# Mainframe ingest parsers (z/OS extracts -> crypto asset rows)
# --------------------------------------------------------------------------- #

def normalize_racdcert(text: str) -> list[dict[str, Any]]:
    """Parse RACF ``RACDCERT LIST`` output into crypto asset rows.

    Tolerant of the common field spellings; one block per certificate
    (``Digital certificate information for ...``). Each row carries the same
    shape the scanners emit (algorithm / key_size / purpose / location) so it
    flows into the unified BOM unchanged.
    """
    assets: list[dict[str, Any]] = []
    blocks = re.split(r"Digital certificate information for", text or "")
    for block in blocks[1:]:
        # Header remainder (" site certificate PAYMENTGW:",
        # " id(CERTAUTH) label(OLDROOT):") — unwrap a label(...) wrapper or
        # fall back to the last token before the trailing colon.
        head = block.split(":", 1)[0]
        tokens = head.split()
        label = ""
        if tokens:
            wrap = re.search(r"label\(([A-Za-z0-9@#$.\-_]+)\)", tokens[-1], re.IGNORECASE)
            label = wrap.group(1) if wrap else tokens[-1].strip("'\"")
            if label.lower() in ("certificate", "auth", "site", "id") and len(tokens) >= 2:
                label = tokens[-2].strip("'\"")
        subject_m = re.search(r"Subject:\s*(.+)", block)
        alg_m = re.search(r"Algorithm(?: Signature)?:\s*([A-Za-z0-9]+(?:With[A-Za-z0-9]+)?)", block, re.IGNORECASE)
        size_m = re.search(r"(?:Certificate Key Size|Key Size)[:\s]+(\d+)", block, re.IGNORECASE)
        exp_m = re.search(r"Expiration Date:?\s*(\d{4})[-/](\d{2})[-/](\d{2})", block)
        status_m = re.search(r"Status:?\s*([A-Z]+)", block)
        sig_alg = (alg_m.group(1) if alg_m else "").strip()
        # The BOM `algorithm` carries the crypto FAMILY (RSA/ECDSA), not the
        # hash: "SHA256WithRSA" -> RSA (full bundle kept in signature_algorithm).
        base_alg = sig_alg.split("With")[-1] if sig_alg else "RSA"
        key_size = int(size_m.group(1)) if size_m else None
        expiry = f"{exp_m.group(1)}-{exp_m.group(2)}-{exp_m.group(3)}" if exp_m else ""
        assets.append({
            "source": "racf",
            "source_language": "zos-racf",
            "label": label,
            "subject": (subject_m.group(1) if subject_m else "").strip(),
            "algorithm": base_alg.upper() or "UNKNOWN",
            "signature_algorithm": sig_alg.upper(),
            "key_size": key_size,
            "purpose": "signature",
            "status": (status_m.group(1) if status_m else "").upper(),
            "expires": expiry,
            "file_path": f"racf://{label or 'certificate'}",
            "confidence": "HIGH",
        })
    return assets


_ICSF_COLUMNS = ("label", "algorithm", "keybits", "usage", "status")


def normalize_icsf_csv(text: str) -> list[dict[str, Any]]:
    """Parse an ICSF key-inventory CSV extract into crypto asset rows.

    Expected header (case-insensitive, order-free):
    ``LABEL, ALGORITHM, KEYBITS, USAGE, STATUS`` — exactly what an ICSF
    panel/DCSS export or an RDz extract produces.
    """
    reader = csv.DictReader(io.StringIO(text or ""))
    if not reader.fieldnames:
        return []
    headers = {h.strip().lower().replace("_", ""): h for h in reader.fieldnames}
    if not {"label", "algorithm"} <= set(headers):
        return []
    assets: list[dict[str, Any]] = []
    for row in reader:
        get = lambda name: (row.get(headers.get(name, "")) or "").strip()  # noqa: E731
        label = get("label")
        algorithm = get("algorithm").upper() or "UNKNOWN"
        if not label and not algorithm:
            continue
        try:
            key_size = int(get("keybits")) if get("keybits") else None
        except ValueError:
            key_size = None
        usage = get("usage").lower() or "cipher"
        assets.append({
            "source": "icsf",
            "source_language": "zos-icsf",
            "label": label,
            "algorithm": algorithm,
            "key_size": key_size,
            "purpose": usage,
            "status": get("status").upper(),
            "file_path": f"icsf://{label or algorithm}",
            "confidence": "HIGH",
        })
    return assets


# --------------------------------------------------------------------------- #
# Combined banking surface
# --------------------------------------------------------------------------- #

def banking_overview(
    state: Mapping[str, Any],
    *,
    hsms: Iterable[Mapping[str, Any]] | None = None,
    mainframe_assets: Iterable[Mapping[str, Any]] | None = None,
    data_classes: Iterable[Mapping[str, Any]] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """One regulator-ready surface: HNDL + roadmap + HSM fleet + mainframe."""
    hndl = hndl_register(state, data_classes=data_classes)
    roadmap = migration_roadmap(state, today=today)
    fleet = assess_hsm_fleet(hsms or [])
    mf = list(mainframe_assets or [])
    return {
        "bank_acceptance": False,
        "discovery_completeness_proven": False,
        "hndl": {"at_risk": hndl["at_risk"], "total": hndl["total"], "by_exposure": hndl["by_exposure"],
                 "assessment_complete": hndl["assessment_complete"], "unassessed": hndl["unassessed"],
                 "horizon_basis": hndl["horizon_basis"]},
        "roadmap": {
            "anchor": roadmap["anchor"],
            "deadline_basis": roadmap["deadline_basis"],
            "regulatory_approval": False,
            "total_in_scope": roadmap["total_in_scope"],
            "weak_legacy_instances": roadmap["weak_legacy_instances"],
            "phases": [{"phase": p["phase"], "title": p["title"], "deadline": p["deadline"],
                        "instance_count": p["instance_count"]} for p in roadmap["phases"]],
        },
        "hsm": {"total": fleet["total"], "pqc_ready": fleet["pqc_ready"], "pqc_gap": fleet["pqc_gap"],
                "pqc_declared_not_verified": fleet["pqc_declared_not_verified"],
                "readiness_basis": fleet["readiness_basis"]},
        "mainframe": {"total": len(mf),
                      "by_source": {s: sum(1 for a in mf if a.get("source") == s)
                                    for s in ("racf", "icsf") if any(a.get("source") == s for a in mf)}},
    }
