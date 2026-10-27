"""Vendor crypto questionnaire (generate + parse)."""

from __future__ import annotations

import re
from typing import Any

QUESTIONS = [
    {
        "id": "transit",
        "prompt": "What encryption do you use for data in transit?",
        "options": ["TLS 1.2", "TLS 1.3", "Other"],
    },
    {
        "id": "rest",
        "prompt": "What encryption do you use for data at rest?",
        "options": ["AES-256", "AES-128", "Other"],
    },
    {
        "id": "kms",
        "prompt": "How are encryption keys managed?",
        "options": ["HSM", "Cloud KMS", "Software", "Other"],
    },
    {
        "id": "pqc",
        "prompt": "Do you use post-quantum cryptography?",
        "options": ["Yes", "No", "Planned"],
    },
    {
        "id": "cbom",
        "prompt": "Can you provide a CBOM (Crypto Bill of Materials)?",
        "options": ["Yes", "No"],
    },
    {
        "id": "rotation",
        "prompt": "What is your crypto refresh/rotation policy?",
        "options": ["quarterly", "annually", "ad-hoc", "unknown"],
    },
]


def generate_questionnaire(vendor_name: str | None = None) -> dict[str, Any]:
    return {
        "vendor_name": vendor_name,
        "title": "CryptoScan vendor cryptography questionnaire",
        "questions": QUESTIONS,
    }


def _canonical_reported_algorithm(value: str) -> str | None:
    """Canonicalize supported answers without treating free text as fact."""
    raw = value.strip()
    if not raw:
        return None
    match = re.fullmatch(r"TLS\s*v?\s*1\.([0-3])", raw, re.IGNORECASE)
    if match:
        return f"TLS 1.{match.group(1)}"
    match = re.fullmatch(r"AES[-\s]?(128|256)(?:[-\s]?(GCM|CBC|CTR))?", raw, re.IGNORECASE)
    if match:
        return f"AES-{match.group(1)}" + (f"-{match.group(2).upper()}" if match.group(2) else "")
    match = re.fullmatch(r"(RSA|ECDSA|ED25519|CHACHA20)", raw, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    match = re.fullmatch(r"SHA[-\s]?(1|256|384|512)", raw, re.IGNORECASE)
    if match:
        return f"SHA-{match.group(1)}"
    return None


def parse_questionnaire(responses: dict[str, Any]) -> dict[str, Any]:
    transit = str(responses.get("transit") or responses.get("tls_version") or "")
    rest = str(responses.get("rest") or responses.get("encryption_algorithm") or "")
    kms = str(responses.get("kms") or responses.get("key_management") or responses.get("kms_type") or "")
    pqc = str(responses.get("pqc") or responses.get("pqc_adoption") or responses.get("pqc_status") or "No")
    cbom = responses.get("cbom") or responses.get("cbom_provided") or responses.get("cbom_attached")
    inventory = []
    transit_algorithm = _canonical_reported_algorithm(transit)
    rest_algorithm = _canonical_reported_algorithm(rest)
    if transit:
        inventory.append(
            {
                "crypto_use_case": "Data in transit",
                "algorithm": transit_algorithm,
                "algorithm_raw": transit if transit_algorithm is None else None,
                "discovery_method": "QUESTIONNAIRE",
                "evidence_source": "vendor_self_report",
                "visibility": "self_reported",
                "observed_usage": False,
                "confidence": "LOW",
                "pqc_ready": False,
            }
        )
    if rest:
        inventory.append(
            {
                "crypto_use_case": "Data at rest",
                "algorithm": rest_algorithm,
                "algorithm_raw": rest if rest_algorithm is None else None,
                "discovery_method": "QUESTIONNAIRE",
                "evidence_source": "vendor_self_report",
                "visibility": "self_reported",
                "observed_usage": False,
                "confidence": "LOW",
                "key_management": kms or None,
                "pqc_ready": False,
            }
        )
    pqc_status = "none"
    pqc_l = pqc.lower()
    if pqc_l in {"yes", "true", "deployed"}:
        pqc_status = "ready"
    elif pqc_l in {"planned", "roadmap"}:
        pqc_status = "planned"
    return {
        "vendor_name": responses.get("vendor_name"),
        "data_in_transit": transit,
        "data_at_rest": rest,
        "key_management": kms,
        "pqc_status": pqc_status,
        "cbom_provided": str(cbom).lower() in {"1", "true", "yes", "on"},
        "rotation": responses.get("rotation"),
        "inventory": inventory,
        "discovery_method": "QUESTIONNAIRE",
    }
