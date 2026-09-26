"""Group governance — legal entities, cross-entity rollup, DORA register.

An international banking group runs many legal entities, each with its own
estate, supervisor and reporting duty. This module adds the entity dimension
over the unified inventory (pure transforms, no DB / I/O):

1. **LEI validation** (`validate_lei`) — ISO 17442 Legal Entity Identifier
   checksum (the real identifier banks are regulated under).
2. **Entity rollup** (`entity_rollup`) — crypto posture per legal entity from
   that entity's systems and their crypto assets.
3. **Group rollup** (`group_rollup`) — the board/supervisor view across
   entities: posture concentration by jurisdiction, worst entities, families
   that recur across the group (shared weak crypto = shared remediation).
4. **DORA register of information** (`dora_register_rows`) — ICT third-party
   arrangements shaped after the DORA register templates (Reg. (EU) 2022/2554
   art. 28 + RTS): provider, service, criticality, contract dates, data
   classes and the fields the bank must supply (contract ids, exit plans) are
   explicit ``bank_to_supply`` placeholders — never fabricated.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from cbom.banking import quantum_vulnerability

# --------------------------------------------------------------------------- #
# LEI — ISO 17442 (GYG checksum over the 20-char code)
# --------------------------------------------------------------------------- #

_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def validate_lei(lei: str) -> dict[str, Any]:
    """Validate a Legal Entity Identifier (ISO 17442), incl. the check digits.

    Returns ``{"valid": bool, "normalized": str, "error": str|None}``.
    ISO 7064 MOD 97-10: the 20-character LEI converted to digits must satisfy
    ``value mod 97 == 1`` (check digits are generated as ``98 - (body+"00")
    mod 97`` over the 18-char body). Structural validity says nothing about
    GLEIF registration status — record that separately.
    """
    raw = (lei or "").strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{20}", raw):
        return {"valid": False, "normalized": raw,
                "error": "an LEI is exactly 20 alphanumeric characters"}
    num = "".join(str(_CHARSET.index(c)) for c in raw)
    if int(num) % 97 != 1:
        return {"valid": False, "normalized": raw,
                "error": "check digits do not match (ISO 7064 mod 97-10)"}
    return {"valid": True, "normalized": raw, "error": None}


# --------------------------------------------------------------------------- #
# Entity registry model (persistence helpers at the bottom of this section)
# --------------------------------------------------------------------------- #

_REQUIRED_ENTITY_FIELDS = ("code", "name", "jurisdiction")


def normalize_entity(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate + normalize one legal-entity record (registry entry)."""
    missing = [f for f in _REQUIRED_ENTITY_FIELDS if not str(record.get(f) or "").strip()]
    if missing:
        raise ValueError(f"legal entity missing required fields: {missing}")
    code = str(record["code"]).strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{2,24}", code):
        raise ValueError("entity code: 2-24 chars of a-z 0-9 _ -")
    lei = validate_lei(str(record.get("lei") or ""))
    if record.get("lei") and not lei["valid"]:
        raise ValueError(f"invalid LEI: {lei['error']}")
    return {
        "code": code,
        "name": str(record["name"]).strip(),
        "jurisdiction": str(record["jurisdiction"]).strip().lower(),
        "lei": lei["normalized"] if lei["valid"] else "",
        "regulator": str(record.get("regulator") or "").strip(),
        "parent": str(record.get("parent") or "").strip().lower(),
        "country": str(record.get("country") or "").strip().upper(),
        "notes": str(record.get("notes") or "").strip(),
    }


# --------------------------------------------------------------------------- #
# Rollups
# --------------------------------------------------------------------------- #

def entity_rollup(
    entity: Mapping[str, Any],
    systems: Iterable[Mapping[str, Any]],
    assets_by_system: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Posture of ONE legal entity: its systems and their crypto assets.

    ``systems`` — rows already filtered to the entity; each has ``id``,
    ``name``, ``criticality``, ``legal_entity`` (assignment echo).
    ``assets_by_system`` — system_id -> crypto-asset component dicts
    (materialized CBOM row shape: algorithm, key_size, purpose).
    """
    this_date = today or datetime.now(timezone.utc).date()
    system_list = [dict(s) for s in systems]
    total = weak_legacy = quantum_pubkey = 0
    families: dict[str, int] = {}
    worst_system: dict[str, Any] | None = None

    for s in system_list:
        s_assets = list(assets_by_system.get(str(s.get("id")), []))
        s_weak = 0
        for a in s_assets:
            total += 1
            vuln = quantum_vulnerability(a.get("algorithm"), a.get("key_size"))
            if vuln.get("legacy") and vuln["quantum_vulnerable"]:
                weak_legacy += 1
                s_weak += 1
            elif vuln["quantum_vulnerable"]:
                quantum_pubkey += 1
            key = f"{a.get('algorithm') or '?'}{('-' + str(a['key_size'])) if a.get('key_size') else ''}"
            families[key] = families.get(key, 0) + 1
        if worst_system is None or s_weak > worst_system["weak_instances"]:
            worst_system = {"system": s.get("name"), "system_id": s.get("id"),
                            "weak_instances": s_weak}

    return {
        "entity": dict(entity),
        "systems": len(system_list),
        "crypto_instances": total,
        "weak_legacy_instances": weak_legacy,
        "quantum_vulnerable_public_key": quantum_pubkey,
        "top_families": sorted(families.items(), key=lambda kv: -kv[1])[:10],
        "worst_system": worst_system,
        "generated_for": this_date.isoformat(),
    }


def group_rollup(
    entity_rollups: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Board view across entity rollups.

    Adds group totals, per-jurisdiction concentration, the entities carrying
    the most weak/quantum exposure, and weak-crypto families that RECUR across
    entities (a shared platform weakness — fix once, report everywhere).
    """
    rollups = [dict(r) for r in entity_rollups]

    totals = {
        "entities": len(rollups),
        "systems": sum(r.get("systems", 0) for r in rollups),
        "crypto_instances": sum(r.get("crypto_instances", 0) for r in rollups),
        "weak_legacy_instances": sum(r.get("weak_legacy_instances", 0) for r in rollups),
        "quantum_vulnerable_public_key": sum(r.get("quantum_vulnerable_public_key", 0) for r in rollups),
    }

    by_jurisdiction: dict[str, dict[str, int]] = {}
    for r in rollups:
        j = str((r.get("entity") or {}).get("jurisdiction") or "unknown")
        agg = by_jurisdiction.setdefault(j, {"entities": 0, "crypto_instances": 0,
                                             "weak_legacy_instances": 0})
        agg["entities"] += 1
        agg["crypto_instances"] += r.get("crypto_instances", 0)
        agg["weak_legacy_instances"] += r.get("weak_legacy_instances", 0)

    exposure_rank = sorted(
        rollups,
        key=lambda r: -(r.get("weak_legacy_instances", 0) + r.get("quantum_vulnerable_public_key", 0)),
    )

    family_entities: dict[str, set[str]] = {}
    for r in rollups:
        for fam, _n in r.get("top_families", []):
            family_entities.setdefault(fam, set()).add(r["entity"]["code"])
    recurring = sorted(
        ((fam, sorted(codes)) for fam, codes in family_entities.items() if len(codes) > 1),
        key=lambda kv: -len(kv[1]),
    )

    return {
        "totals": totals,
        "by_jurisdiction": dict(sorted(by_jurisdiction.items(),
                                       key=lambda kv: -kv[1]["crypto_instances"])),
        "exposure_ranking": [
            {"entity": r["entity"]["code"], "name": r["entity"].get("name"),
             "jurisdiction": (r.get("entity") or {}).get("jurisdiction"),
             "weak": r.get("weak_legacy_instances", 0),
             "quantum": r.get("quantum_vulnerable_public_key", 0)}
            for r in exposure_rank[:10]
        ],
        "recurring_weak_families": [
            {"family": fam, "entities": codes, "entity_count": len(codes)}
            for fam, codes in recurring[:10]
        ],
    }


# --------------------------------------------------------------------------- #
# DORA — register of information (ICT third-party arrangements)
# --------------------------------------------------------------------------- #

# ICT service taxonomy condensed from the DORA RTS annexes; the bank pins the
# exact template codes when submitting to its NCA.
_DORA_SERVICE_BY_TYPE = {
    "hsm": "Cryptographic hardware (HSM)",
    "cloud": "Cloud computing (IaaS/PaaS/SaaS)",
    "pki": "PKI / certificate services",
    "network": "Network connectivity",
    "data": "Data hosting / processing",
    "software": "Software provision & maintenance",
    "managed": "Managed IT / security operations",
}

_CRITICAL_SET = ("CRITICAL", "MISSION-CRITICAL", "MISSION_CRITICAL", "HIGH")

_BANK_TO_SUPPLY = (
    "contract_id", "contract_start", "contract_end", "termination_notice_days",
    "exit_plan_ref", "subcontracting_chain", "data_location", "register_entity_code",
)


def dora_register_rows(
    vendors: Iterable[Mapping[str, Any]],
    *,
    entity_code: str = "",
) -> dict[str, Any]:
    """DORA register-of-information rows for ICT third-party arrangements.

    ``vendors`` — Vendor rows (name, vendor_type, criticality, integration_type,
    contract_end_date, data_classifications, security_contact). DORA-required
    fields the platform cannot know (contract ids, dates, exit plans,
    subcontracting chains) are emitted as explicit ``bank_to_supply`` entries
    so the register is complete-by-construction and honest by default.
    """
    rows: list[dict[str, Any]] = []
    today = datetime.now(timezone.utc).date()
    critical_expiring = 0
    for v in vendors:
        v = dict(v)
        service = _DORA_SERVICE_BY_TYPE.get(str(v.get("vendor_type") or "").lower(),
                                            str(v.get("vendor_type") or "ICT service"))
        contract_end = v.get("contract_end_date")
        days_to_end = None
        if isinstance(contract_end, datetime):
            days_to_end = (contract_end.date() - today).days
        elif isinstance(contract_end, date):
            days_to_end = (contract_end - today).days
        elif isinstance(contract_end, str) and len(contract_end) >= 10:
            try:
                days_to_end = (date.fromisoformat(contract_end[:10]) - today).days
            except ValueError:
                days_to_end = None
        criticality = str(v.get("criticality") or "").upper()
        is_critical = criticality in _CRITICAL_SET
        if is_critical and days_to_end is not None and 0 <= days_to_end <= 180:
            critical_expiring += 1
        row = {
            "provider_name": v.get("name") or "",
            "provider_lei": "",  # from the vendor's GLEIF record — bank to confirm
            "ict_service_type": service,
            "function_criticality": criticality or "UNCLASSIFIED",
            "contract_nature": str(v.get("integration_type") or ""),
            "contract_end_date": str(contract_end or ""),
            "days_to_contract_end": days_to_end,
            "data_classes": v.get("data_classifications") or [],
            "security_contact": v.get("security_contact") or "",
            "register_entity_code": entity_code,
            "bank_to_supply": {f: "" for f in _BANK_TO_SUPPLY if f != "register_entity_code"},
        }
        rows.append(row)
    rows.sort(key=lambda r: (
        r["function_criticality"] not in _CRITICAL_SET,
        r["days_to_contract_end"] is None,
        r["days_to_contract_end"] if r["days_to_contract_end"] is not None else 9e9,
    ))
    return {
        "regulation": "DORA (EU) 2022/2554 art. 28 — register of information",
        "note": ("Rows follow the register structure; contractual fields the "
                 "platform cannot know are marked bank_to_supply. Confirm the "
                 "exact NCA submission template/version before filing."),
        "entity_code": entity_code,
        "total": len(rows),
        "critical": sum(1 for r in rows if r["function_criticality"] in _CRITICAL_SET),
        "critical_expiring_180d": critical_expiring,
        "rows": rows,
    }


# --------------------------------------------------------------------------- #
# Entity registry persistence (file-backed, like the FIPS registry)
# --------------------------------------------------------------------------- #

def default_registry_path(base: str | Path | None = None) -> Path:
    """Registry location: CRYPTOSCAN_GROUP_ENTITIES override, else <root>/config."""
    override = os.environ.get("CRYPTOSCAN_GROUP_ENTITIES")
    if override:
        return Path(override)
    root = Path(base) if base else Path(os.environ.get("CRYPTOSCAN_ROOT") or Path.cwd())
    return root / "config" / "group_entities.json"


def load_entities(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the entity registry keyed by entity code ({} when absent/corrupt)."""
    p = Path(path) if path else default_registry_path()
    try:
        if p.is_file():
            data = json.loads(p.read_text())
            entries = data if isinstance(data, list) else data.get("entities", [])
            return {str(e["code"]).lower(): dict(e)
                    for e in entries if isinstance(e, Mapping) and e.get("code")}
    except (OSError, json.JSONDecodeError, TypeError, KeyError, ValueError):
        pass
    return {}


def save_entities(entries: Iterable[Mapping[str, Any]], path: str | Path | None = None) -> int:
    """Persist normalized entities (dedupe on code); writable fallback on RO fs."""
    p = Path(path) if path else default_registry_path()
    registry: dict[str, dict[str, Any]] = {}
    for e in entries:
        norm = normalize_entity(e)
        registry[norm["code"]] = norm
    payload = json.dumps(sorted(registry.values(), key=lambda r: r["code"]), indent=2)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(payload)
    except OSError:
        fallback = Path(os.environ.get("CRYPTOSCAN_HOME") or "/tmp") / "group_entities.json"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.write_text(payload)
    return len(registry)
