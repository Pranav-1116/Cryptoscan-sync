"""HSM fleet depth — PKCS#11-level discovery, PQC readiness, key custody.

Banks run their crown-jewel keys in HSMs (Thales Luna, Utimaco, Entrust
nCipher, IBM Crypto Express on z/OS). This module parses the standard
discovery artifacts admins already produce — no proprietary SDKs:

- ``pkcs11-tool --list-slots`` text (OpenSC)  → slots + token + firmware
- ``pkcs11-tool --list-objects`` text         → key objects per slot
- IBM Crypto Express (CEX) adapter records    → mainframe HSM fleet

...and assesses each adapter for PQC mechanism support (ML-KEM/ML-DSA),
firmware level and key-custody posture (M-of-N split knowledge). Pure
functions; the router feeds hardware-asset rows plus optional artifact text.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

# Vendor detection — (vendor, family pattern) over manufacturer/model text.
_VENDOR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("thales", r"luna|thales|proteccio|protectserver"),
    ("utimaco", r"utimaco|cryptoserver|securityserver"),
    ("entrust", r"ncipher|nshield|entrust"),
    ("ibm", r"crypto express|cex[0-9s]|ep11|icsf"),
    ("futurex", r"futurex|guardmaster|vectra"),
    ("amazon", r"cloudhsm"),
    ("google", r"cloud hsm|google.*hsm"),
)

# PQC mechanism markers a modern firmware would declare (PKCS#11 PQC draft
# mechanism names + common vendor spellings).
_PQC_MARKERS = ("ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "KYBER", "DILITHIUM",
                "FALCON", "SPHINCS", "LATTICE", "PQC")

# Firmware baselines where PQC support began shipping for major fleets
# (public vendor roadmap statements; advisory, not an audited fact).
_PQC_FIRMWARE_BASELINE = (
    (r"luna|thales", "7.8.0"),
    (r"cryptoserver|utimaco", "5.0"),
    (r"ncipher|nshield|entrust", "12.60"),
    (r"cex|crypto express", None),  # IBM announces per z/OS release, not firmware
)


def detect_vendor(manufacturer: str = "", model: str = "") -> dict[str, str]:
    """Vendor + family from free-text manufacturer/model fields."""
    hay = f"{manufacturer} {model}".lower()
    for vendor, pattern in _VENDOR_PATTERNS:
        if re.search(pattern, hay):
            return {"vendor": vendor, "family": (model or manufacturer).strip() or "unknown"}
    return {"vendor": "unknown", "family": (model or manufacturer).strip() or "unknown"}


def _version_at_least(version: str, baseline: str) -> bool:
    try:
        parts = tuple(int(p) for p in re.findall(r"\d+", version)[:3])
        base = tuple(int(p) for p in re.findall(r"\d+", baseline)[:3])
        while len(parts) < 3:
            parts += (0,)
        while len(base) < 3:
            base += (0,)
        return parts >= base
    except (ValueError, AttributeError):
        return False


_PQC_MARKERS_NORM = tuple(m.replace("-", "").replace("_", "") for m in _PQC_MARKERS)


def pqc_from_mechanisms(text: str) -> dict[str, Any]:
    """PQC readiness from a mechanism list (any free text listing mechanisms).

    Vendor/PKCS#11 spellings differ (``ML-KEM`` vs ``CKM_ML_KEM``) — matching
    ignores hyphen/underscore variants."""
    upper = (text or "").upper().replace("-", "").replace("_", "")
    found = sorted({m for m in _PQC_MARKERS_NORM if m in upper})
    if found:
        return {"pqc_status": "ready", "pqc_mechanisms": found,
                "evidence": f"declares {', '.join(found)}"}
    if upper.strip():
        return {"pqc_status": "not_declared", "pqc_mechanisms": [],
                "evidence": "mechanism list present, no PQC mechanisms"}
    return {"pqc_status": "unknown", "pqc_mechanisms": [],
            "evidence": "no mechanism data"}


def parse_pkcs11_slots(text: str) -> list[dict[str, Any]]:
    """Parse ``pkcs11-tool --list-slots`` output.

    Recognizes the OpenSC layout (labelled Slot blocks with token details and
    hardware/firmware versions). Unrecognized input returns [] — never guesses.
    """
    slots: list[dict[str, Any]] = []
    for block in re.split(r"(?=Slot \d+)", text or ""):
        if not re.match(r"Slot \d+", block or ""):
            continue

        def grab(pattern: str) -> str:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else ""

        slot_line = re.search(r"Slot (\d+)(?:\s*\((0x[0-9a-fA-F]+)\))?\s*:?\s*(.*)", block)
        slots.append({
            "slot": int(slot_line.group(1)) if slot_line else None,
            "slot_id": slot_line.group(2) if slot_line else "",
            "slot_description": (slot_line.group(3) if slot_line else "").strip(),
            "token_label": grab(r"token label\s*:\s*(.+)"),
            "token_manufacturer": grab(r"token manufacturer\s*:\s*(.+)"),
            "token_model": grab(r"token model\s*:\s*(.+)"),
            "token_serial": grab(r"token serial\s*:\s*(.+)"),
            "hardware_version": grab(r"hardware version\s*:\s*(.+)"),
            "firmware_version": grab(r"firmware version\s*:\s*(.+)"),
            "token_flags": grab(r"token flags\s*:\s*(.+)"),
        })
    return slots


def parse_pkcs11_objects(text: str) -> list[dict[str, Any]]:
    """Parse ``pkcs11-tool --list-objects`` output into a key inventory.

    Blocks look like::

        Slot 0:
          Private Key Object
            label:      pay-gateway-key
            ID:         a1b2c3
            Usage:      decrypt, sign
            Access:     sensitive
    """
    objects: list[dict[str, Any]] = []
    slot = None
    for line in (text or "").splitlines():
        s = re.match(r"\s*Slot (\d+)\s*:", line, re.IGNORECASE)
        if s:
            slot = int(s.group(1))
            continue
        kind = re.match(r"\s*(Private Key|Public Key|Secret Key|Certificate|Data) object", line, re.IGNORECASE)
        if kind:
            objects.append({"slot": slot, "kind": kind.group(1).title(),
                            "label": "", "id": "", "usage": [], "access": ""})
            continue
        if objects:
            attr = re.match(r"\s*(label|ID|Usage|Access|Subject)\s*:\s*(.+)", line, re.IGNORECASE)
            if attr:
                key, val = attr.group(1).lower(), attr.group(2).strip()
                entry = objects[-1]
                if key == "label":
                    entry["label"] = val
                elif key == "id":
                    entry["id"] = val
                elif key == "usage":
                    entry["usage"] = sorted(u.strip().lower() for u in re.split(r"[,;]", val) if u.strip())
                elif key == "access":
                    entry["access"] = val
    return objects


def parse_cex_adapters(text: str) -> list[dict[str, Any]]:
    """Parse IBM Crypto Express adapter records (HMC/ICSF inventory extracts).

    Lines like ``CEX8S.001  ONLINE  crypto  usage=ACCCEL`` or tabular
    ``CEX7S  003  ACTIVE  EP11`` are accepted; serial/card fields are mapped
    when present. Returns one row per adapter line that names a CEX device.
    """
    rows: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        m = re.search(r"(CEX\dS?)[.\s]+(\d{1,3})[.\s]+(\w+)", line, re.IGNORECASE)
        if not m:
            continue
        usage_m = re.search(r"(?:usage|mode)[=:]\s*(\w+)", line, re.IGNORECASE)
        rows.append({
            "adapter": m.group(1).upper(),
            "index": int(m.group(2)),
            "state": m.group(3).upper(),
            "usage": (usage_m.group(1).upper() if usage_m else ""),
            "domain": "",
        })
    return rows


def key_custody_status(record: Mapping[str, Any]) -> dict[str, Any]:
    """Split-knowledge / M-of-N custody posture from an asset record.

    Reads free-text or structured custody fields (``custody``,
    ``operator_card_set``, ``m_of_n``, ``split_knowledge``). Conservative:
    anything not explicitly recorded is ``unknown`` — auditors get an action
    item, never a fabricated pass.
    """
    hay = " ".join(str(v) for v in record.values() if isinstance(v, (str, int))).lower()
    m = re.search(r"(\d+)\s*-?\s*(?:of|/)\s*-?\s*(\d+)", hay)
    split_flag = any(tok in hay for tok in ("split knowledge", "m-of-n", "m of n", "dual control", "quorum"))
    if m and split_flag:
        k, n = int(m.group(1)), int(m.group(2))
        return {"custody_status": "quorum", "quorum": f"{k}-of-{n}",
                "evidence": "split-knowledge quorum recorded"}
    if split_flag:
        return {"custody_status": "split_knowledge", "quorum": "",
                "evidence": "split knowledge flagged, quorum not recorded"}
    return {"custody_status": "unknown", "quorum": "",
            "evidence": "no custody evidence on the record — record the M-of-N policy"}


def assess_hsm_deep(
    hsms: Iterable[Mapping[str, Any]],
    *,
    fips_supplied: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Fleet-deep assessment merging parsed artifacts with asset records.

    Each input row is a hardware-asset dict; optional ``slots_text``,
    ``objects_text`` and ``cex_text`` keys carry the PKCS#11/CEX artifacts to
    parse inline. Produces per-HSM readiness rows and fleet totals.
    """
    from cbom.banking import fips_validation

    rows: list[dict[str, Any]] = []
    for h in hsms:
        vendor = detect_vendor(str(h.get("manufacturer", "")), str(h.get("model", "")))
        firmware = ""
        fw = h.get("firmware")
        if isinstance(fw, Mapping):
            firmware = str(fw.get("version", "") or "")
        elif fw:
            firmware = str(fw)

        mech_text = " ".join(str(v) for v in (
            *(h.get("pqc_mechanisms") or [] if isinstance(h.get("pqc_mechanisms"), list) else []),
            *((h.get("crypto_capabilities") or {}) if isinstance(h.get("crypto_capabilities"), Mapping) else {}).values(),
            *((h.get("hsm") or {}) if isinstance(h.get("hsm"), Mapping) else {}).values(),
        ))
        pqc = pqc_from_mechanisms(mech_text)

        slot_rows = parse_pkcs11_slots(str(h.get("slots_text", "")))
        if slot_rows and not firmware:
            firmware = next((s["firmware_version"] for s in slot_rows if s["firmware_version"]), "")
        if slot_rows and pqc["pqc_status"] == "unknown":
            pqc = pqc_from_mechanisms(str(h.get("slots_text", "")))

        objects = parse_pkcs11_objects(str(h.get("objects_text", "")))
        cex = parse_cex_adapters(str(h.get("cex_text", "")))

        # Firmware-baseline advisory: near-PQC only when vendor publishes a PQC baseline.
        firmware_advisory = ""
        if pqc["pqc_status"] != "ready":
            for pattern, baseline in _PQC_FIRMWARE_BASELINE:
                if re.search(pattern, f"{h.get('manufacturer', '')} {h.get('model', '')}".lower()):
                    if baseline and firmware and not _version_at_least(firmware, baseline):
                        firmware_advisory = f"firmware {firmware} below PQC-capable baseline {baseline} — schedule upgrade"
                    elif baseline and not firmware:
                        firmware_advisory = f"PQC expected from {baseline}+ — record firmware version"
                    break

        module_name = f"{h.get('manufacturer', '')} {h.get('model', '')}".strip() or vendor["family"]
        custody = key_custody_status(h)
        rows.append({
            "asset_id": h.get("asset_id") or h.get("id") or "",
            "vendor": vendor["vendor"],
            "family": vendor["family"],
            "firmware": firmware,
            "pqc_status": pqc["pqc_status"],
            "pqc_mechanisms": pqc["pqc_mechanisms"],
            "firmware_advisory": firmware_advisory,
            "fips": fips_validation(module_name, supplied=fips_supplied),
            "custody": custody,
            "key_objects": len(objects),
            "key_labels": [o["label"] for o in objects if o.get("label")][:10],
            "cex_adapters": cex,
            "slots": slot_rows,
            "gap": "" if pqc["pqc_status"] == "ready" else (
                firmware_advisory or "PQC capability not declared — request vendor firmware plan"),
        })
    ready = sum(1 for r in rows if r["pqc_status"] == "ready")
    quorum = sum(1 for r in rows if r["custody"]["custody_status"] in ("quorum", "split_knowledge"))
    return {
        "total": len(rows),
        "pqc_ready": ready,
        "pqc_gap": len(rows) - ready,
        "custody_recorded": quorum,
        "custody_unknown": len(rows) - quorum,
        "by_vendor": {v: sum(1 for r in rows if r["vendor"] == v)
                      for v in sorted({r["vendor"] for r in rows})},
        "hsms": rows,
    }
