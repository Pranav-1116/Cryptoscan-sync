"""Conservative source labels, never an assertion that a deployment was observed.

Historical importers could overwrite scanner metadata while evidence links
survived. A marker therefore means REVIEW REQUIRED, not 'no evidence exists'.
The stored confidence and evidence are never changed by this read projection.
"""
from __future__ import annotations

import json
from typing import Any

IMPORT_SOURCE_BASIS = "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS"
LEGACY_SOURCE_BASIS = "LEGACY_IMPORT_REVIEW_REQUIRED"
ARCHIVED_DECLARATION = "ARCHIVED_DECLARATION"
RETAINED_MIXED_EVIDENCE = "RETAINED_MIXED_EVIDENCE"


def is_import(data: dict[str, Any]) -> bool:
    extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
    scan_id = extra.get("scan_id")
    return (isinstance(scan_id, str) and scan_id.startswith("cbom-ingest:")) or (
        '"cbom-ingest"' in json.dumps(data.get("scanner_ids"), default=str)
    ) or extra.get("cbom_import") is not None


def is_legacy_import(data: dict[str, Any]) -> bool:
    if not is_import(data):
        return False
    extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
    receipt = extra.get("cbom_import")
    return not (isinstance(receipt, dict) and isinstance(receipt.get("system_id"), str)
                and bool(receipt["system_id"]) and isinstance(receipt.get("document_sha256"), str)
                and len(receipt["document_sha256"]) == 64 and receipt.get("source_basis") == IMPORT_SOURCE_BASIS)


def project_import_provenance(data: dict[str, Any]) -> dict[str, Any]:
    if not is_import(data):
        return data
    result = dict(data)
    result["reported_confidence"] = data.get("reported_confidence", data.get("confidence"))
    result["confidence"] = "LOW"
    extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
    disposition = extra.get("legacy_cbom_disposition") or {}
    if isinstance(disposition, dict) and disposition.get("state") in {ARCHIVED_DECLARATION, RETAINED_MIXED_EVIDENCE}:
        result["source_disposition"] = disposition["state"]
    result["source_basis"] = LEGACY_SOURCE_BASIS if is_legacy_import(data) else IMPORT_SOURCE_BASIS
    return result
