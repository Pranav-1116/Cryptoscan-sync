"""Cross-instance scan transfer: export → move → verify → import.

For segmented deployments (e.g. a bank's isolated zone): export a scan and
its evidence records as one digest-verified JSON payload on instance A,
carry the file across the one-way boundary, verify and import it on
instance B. Integrity is checked twice — a payload digest over the whole
transfer and a records digest over the evidence chain — using the shared
canonical JSON hashing, so tampering is detected on arrival.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable, Mapping

from evidence.verification.stored_scan import verify_stored_scan
from shared_models.canonical import constant_time_eq, sha256_hex
from shared_models.safe_finding import safe_finding

TRANSFER_FORMAT = "cryptoscan-scan-transfer"
TRANSFER_VERSION = "1.1"

#: scan columns carried across the boundary (ids/timestamps are explicit,
#: internal bookkeeping columns are not)
SCAN_FIELDS = (
    "scan_start",
    "scan_end",
    "scanner_id",
    "scanner_version",
    "target_type",
    "target_location",
    "target_commit",
    "target_branch",
    "operator",
    "status",
    "statistics",
    "manifest_hash",
    "error_message",
)

#: evidence columns carried across the boundary
RECORD_FIELDS = (
    "evidence_id",
    "content_hash",
    "chain_hash",
    "chain_position",
    "previous_hash",
    "algorithm",
    "key_size",
    "mode",
    "padding",
    "purpose",
    "confidence",
    "is_hardcoded_key",
    "file_path",
    "line_number",
    "class_name",
    "method_name",
    "finding_data",
    "provenance",
    "normalized_crypto",
    "policy_evaluation",
    "compliance_status",
)

_RECORD_REQUIRED = ("evidence_id", "content_hash", "chain_hash", "chain_position", "algorithm", "confidence", "file_path", "line_number", "finding_data")


def export_transfer(*, scan: Mapping[str, Any], records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Build the transfer payload for one scan and its evidence records."""
    from shared_models.chrono import iso_utc

    rows = sorted(
        ({field: row.get(field) for field in RECORD_FIELDS} for row in records),
        key=lambda row: int(row.get("chain_position") or 0),
    )
    scan_id = str(scan.get("scan_id") or scan.get("id") or "")
    payload: dict[str, Any] = {
        "transfer_format": TRANSFER_FORMAT,
        "transfer_version": TRANSFER_VERSION,
        "exported_at": iso_utc(),
        "scan": {"scan_id": scan_id, **{field: scan.get(field) for field in SCAN_FIELDS}},
        "records": rows,
        "digests": {
            "record_count": len(rows),
            "records_digest": _records_digest(rows),
        },
    }
    payload["digests"]["payload_digest"] = sha256_hex(_undigested(payload))
    return payload


def _undigested(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "digests"} | {
        "digests": {key: value for key, value in (payload.get("digests") or {}).items() if key != "payload_digest"}
    }


def _records_digest(rows: list[Mapping[str, Any]]) -> str:
    return sha256_hex(
        [
            {
                "content_hash": str(row.get("content_hash") or ""),
                "chain_hash": str(row.get("chain_hash") or ""),
                "chain_position": int(row.get("chain_position") or 0),
            }
            for row in rows
        ]
    )


def verify_transfer(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Verify a transfer payload. Collects every problem, decides nothing."""
    errors: list[str] = []
    if str(payload.get("transfer_format") or "") != TRANSFER_FORMAT:
        errors.append(f"unsupported transfer_format: {payload.get('transfer_format')!r}")
    if str(payload.get("transfer_version") or "") != TRANSFER_VERSION:
        errors.append(f"unsupported transfer_version: {payload.get('transfer_version')!r}")
    scan = payload.get("scan")
    if not isinstance(scan, Mapping):
        if scan is not None:
            errors.append("scan must be an object")
        scan = {}
    scan_id = str(scan.get("scan_id") or "")
    if not scan_id:
        errors.append("missing scan.scan_id")

    digests = payload.get("digests")
    if not isinstance(digests, Mapping):
        if digests is not None:
            errors.append("digests must be an object")
        digests = {}
    expected_payload = str(digests.get("payload_digest") or "")
    if expected_payload:
        actual = sha256_hex(_undigested(payload))
        if not constant_time_eq(actual, expected_payload):
            errors.append("payload_digest mismatch: transfer was modified after export")
    else:
        errors.append("missing digests.payload_digest")

    rows = payload.get("records") or []
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        rows = []
        errors.append("records must be a list of objects")
    expected_records = str(digests.get("records_digest") or "")
    positions_valid = True
    if expected_records:
        try:
            actual = _records_digest(rows)
        except (TypeError, ValueError):
            positions_valid = False
            errors.append("invalid chain_position in transfer records")
        else:
            if not constant_time_eq(actual, expected_records):
                errors.append("records_digest mismatch: evidence records were modified after export")
    else:
        errors.append("missing digests.records_digest")
    try:
        count = int(digests.get("record_count", -1))
    except (TypeError, ValueError):
        count = -1
    if count != len(rows):
        errors.append("record_count mismatch: records were added or removed after export")

    for index, row in enumerate(rows):
        missing = [field for field in _RECORD_REQUIRED if row.get(field) is None]
        if missing:
            errors.append(f"record {index} missing required fields: {', '.join(missing)}")
        else:
            try:
                if safe_finding(row["finding_data"]) != row["finding_data"]:
                    errors.append(f"record {index} contains raw, non-transferable finding fields")
            except TypeError:
                errors.append(f"record {index} finding_data must be an object")

    try:
        ordered = sorted(rows, key=lambda row: int(row.get("chain_position") or 0)) if positions_valid else []
    except (TypeError, ValueError):
        ordered = []
        positions_valid = False
        errors.append("invalid chain_position in transfer records")
    positions = [int(row.get("chain_position") or 0) for row in ordered]
    if positions and positions != list(range(len(ordered))):
        errors.append("chain_position sequence is not contiguous from 0")
    for index in range(1, len(ordered)):
        expected_previous = str(ordered[index - 1].get("chain_hash") or "")
        actual_previous = str(ordered[index].get("previous_hash") or "")
        if expected_previous != actual_previous:
            errors.append(f"chain linkage broken at position {int(ordered[index].get('chain_position') or 0)}")
            break

    if positions_valid and scan_id and all(all(row.get(field) is not None for field in _RECORD_REQUIRED) for row in rows):
        verdict = verify_stored_scan(
            SimpleNamespace(id=scan_id, status=scan.get("status"),
                            manifest_hash=scan.get("manifest_hash")),
            [SimpleNamespace(id=row["evidence_id"], **{
                field: row.get(field) for field in
                ("content_hash", "chain_hash", "chain_position", "previous_hash", "finding_data")
            }) for row in rows],
        )
        if verdict["result"] not in {"PASS", "EMPTY"}:
            errors.extend(verdict["errors"] or [f"evidence integrity {verdict['result'].lower()}"])

    return {
        "valid": not errors,
        "errors": errors,
        "scan_id": scan_id or None,
        "record_count": len(rows),
        "format": TRANSFER_FORMAT,
        "version": str(payload.get("transfer_version") or ""),
    }


def records_for_import(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Records in chain order, restricted to the carried columns."""
    rows = sorted(payload.get("records") or [], key=lambda row: int(row.get("chain_position") or 0))
    return [{("id" if field == "evidence_id" else field): row.get(field)
             for field in RECORD_FIELDS} for row in rows]
