"""Scan transfer payloads: export → verify → import ordering, tamper detection."""

from __future__ import annotations

import copy
import hashlib

from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher
from evidence.pack.scan_transfer import (
    export_transfer,
    records_for_import,
    verify_transfer,
)


def _scan():
    return {
        "scan_id": "scan-42",
        "target_location": "https://git/bank/core.git",
        "target_type": "GIT_REPOSITORY",
        "status": "COMPLETED",
        "scanner_id": "scanner-v2",
        "statistics": {"total_findings": 3},
        "manifest_hash": hashlib.sha256("ev-0ev-1ev-2".encode()).hexdigest(),
    }


def _records(n=3):
    rows = []
    previous = None
    for index in range(n):
        algorithm = "RSA-2048" if index == 0 else "AES-256"
        finding = {"scanner_id": "unit", "source": {"file_path": f"src/file{index}.py",
                   "line_number": index + 1}, "crypto": {"algorithm": algorithm},
                   "metadata": {"confidence": "HIGH"}}
        content_hash = ContentHasher.compute_hash(finding)
        chain_hash = ChainHasher.compute_chain_hash(
            content_hash, previous_chain_hash=previous,
            scan_session_id="scan-42" if index == 0 else None,
        )
        rows.append(
            {
                "evidence_id": f"ev-{index}",
                "content_hash": content_hash,
                "chain_hash": chain_hash,
                "chain_position": index,
                "previous_hash": previous,
                "algorithm": algorithm,
                "confidence": "HIGH",
                "file_path": f"src/file{index}.py",
                "line_number": index + 1,
                "finding_data": finding,
                "compliance_status": "PASS" if index else "FAIL",
                "policy_evaluation": {"rules_evaluated": []},
                "file_extra_ignored": "not carried",
            }
        )
        previous = chain_hash
    # shuffle order: export must sort by chain_position
    return list(reversed(rows))


def test_roundtrip_verifies_and_orders():
    payload = export_transfer(scan=_scan(), records=_records())
    verdict = verify_transfer(payload)
    assert verdict["valid"] is True and verdict["errors"] == []
    assert verdict["scan_id"] == "scan-42" and verdict["record_count"] == 3
    rows = records_for_import(payload)
    assert [row["chain_position"] for row in rows] == [0, 1, 2]
    assert rows[1]["previous_hash"] == rows[0]["chain_hash"]
    assert "file_extra_ignored" not in rows[0]  # allowlist only


def test_tampered_record_content_detected():
    payload = export_transfer(scan=_scan(), records=_records())
    tampered = copy.deepcopy(payload)
    tampered["records"][0]["algorithm"] = "AES-256"  # not covered by records_digest
    verdict = verify_transfer(tampered)
    assert verdict["valid"] is False
    assert any("payload_digest mismatch" in error for error in verdict["errors"])


def test_tampered_chain_field_detected_twice():
    payload = export_transfer(scan=_scan(), records=_records())
    tampered = copy.deepcopy(payload)
    tampered["records"][1]["content_hash"] = "f" * 64
    verdict = verify_transfer(tampered)
    assert verdict["valid"] is False
    errors = " | ".join(verdict["errors"])
    assert "records_digest mismatch" in errors and "payload_digest mismatch" in errors


def test_removed_record_detected():
    payload = export_transfer(scan=_scan(), records=_records())
    tampered = copy.deepcopy(payload)
    tampered["records"] = tampered["records"][:-1]
    tampered["digests"]["record_count"] = len(tampered["records"])
    verdict = verify_transfer(tampered)
    assert verdict["valid"] is False
    assert any("records_digest mismatch" in error for error in verdict["errors"])


def test_broken_chain_linkage_detected():
    payload = export_transfer(scan=_scan(), records=_records())
    tampered = copy.deepcopy(payload)
    tampered["records"][2]["previous_hash"] = "0" * 59 + "zz"
    # keep digests consistent so only the linkage check can catch it
    from evidence.pack.scan_transfer import _records_digest

    tampered["digests"]["records_digest"] = _records_digest(tampered["records"])
    verdict = verify_transfer(tampered)
    assert verdict["valid"] is False
    assert any("chain linkage broken" in error for error in verdict["errors"])


def test_wrong_format_and_missing_digests():
    verdict = verify_transfer({"transfer_format": "other", "transfer_version": "9", "records": []})
    assert verdict["valid"] is False
    assert any("transfer_format" in error for error in verdict["errors"])
    payload = export_transfer(scan=_scan(), records=_records())
    payload["digests"].pop("payload_digest")
    assert verify_transfer(payload)["valid"] is False


def test_scan_id_missing_is_an_error():
    payload = export_transfer(scan={**_scan(), "scan_id": ""}, records=_records())
    verdict = verify_transfer(payload)
    assert verdict["valid"] is False
    assert any("scan.scan_id" in error for error in verdict["errors"])


def test_malformed_transfer_fields_are_rejected_not_raised():
    payload = export_transfer(scan=_scan(), records=_records())
    payload["records"][0]["chain_position"] = "invalid"
    verdict = verify_transfer(payload)
    assert verdict["valid"] is False
    assert any("chain_position" in error for error in verdict["errors"])


def test_resigned_payload_cannot_hide_missing_manifest_evidence():
    from evidence.pack.scan_transfer import _undigested
    from shared_models.canonical import sha256_hex

    payload = export_transfer(scan=_scan(), records=_records())
    payload["records"].pop()
    payload["digests"]["record_count"] = len(payload["records"])
    from evidence.pack.scan_transfer import _records_digest

    payload["digests"]["records_digest"] = _records_digest(payload["records"])
    payload["digests"]["payload_digest"] = sha256_hex(_undigested(payload))
    verdict = verify_transfer(payload)
    assert verdict["valid"] is False
    assert any("manifest" in error for error in verdict["errors"])


def test_resigned_payload_cannot_hide_changed_finding_content():
    from evidence.pack.scan_transfer import _undigested
    from shared_models.canonical import sha256_hex

    payload = export_transfer(scan=_scan(), records=_records())
    payload["records"][0]["finding_data"]["scanner_id"] = "altered"
    payload["digests"]["payload_digest"] = sha256_hex(_undigested(payload))
    verdict = verify_transfer(payload)
    assert verdict["valid"] is False
    assert any("content hash mismatch" in error for error in verdict["errors"])
