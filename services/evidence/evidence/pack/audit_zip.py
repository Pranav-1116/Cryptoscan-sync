"""CRA / NIST evidence zip assembled from already-computed JSON blobs."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Mapping

from evidence.pack.standalone_verifier import STANDALONE_VERIFIER_SOURCE

README = """CryptoScan audit pack
=====================

This archive is meant to be handed to an auditor without giving them
database access. Every claim about a cryptographic site can be checked
from the files in this zip.

How this maps to common regimes
-------------------------------
EU Cyber Resilience Act (CRA) Annex I
  - evidence-pack.json is the cryptographic inventory with integrity
    hashes (identify what crypto the product uses, and prove the list
    was not edited after the scan).
  - cbom.json is a CycloneDX 1.5 Cryptographic Bill of Materials.
  - work-orders.json is the remediation backlog for known-weak crypto.

NIST SP 800-131A / CSF Identify + Protect
  - policy.json cites the rule pack (hash + standard_reference) that
    produced each FAIL.
  - work-orders.json maps each failing algorithm+purpose to an approved
    replacement (AES-256-GCM, SHA-256, ECDH / ML-KEM, ...).
  - agility.json tells you how much of the estate is a string-literal
    Cipher.getInstance(...) vs a factory you can retarget.

Purpose-aware CI gate
  - gate.json is the merge decision. A new MD5 hash is a warning; a
    new DES encryptor is a blocker. SARIF is in gate.sarif.json.

Verify this pack
----------------
    python verify_pack.py evidence-pack.json
    python verify_pack.py evidence-pack.json --secret <instance SECRET_KEY>

The verifier is self-contained. It recomputes the SHA-256 chain:

    chain[0] = SHA256(content_hash[0] + scan_id)
    chain[n] = SHA256(content_hash[n] + chain[n-1])

and, if you have the issuing secret, the HMAC-SHA256 signature.
"""


def _dump(payload: Any) -> bytes:
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def build_audit_zip(
    *,
    evidence_pack: Mapping[str, Any],
    cbom: Mapping[str, Any] | None = None,
    work_orders: Mapping[str, Any] | None = None,
    agility: Mapping[str, Any] | None = None,
    gate: Mapping[str, Any] | None = None,
    sarif: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    materials: Mapping[str, Any] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    issued = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", README + f"\nIssued: {issued}\n")
        archive.writestr("verify_pack.py", STANDALONE_VERIFIER_SOURCE)
        archive.writestr("evidence-pack.json", _dump(evidence_pack))
        if cbom is not None:
            archive.writestr("cbom.json", _dump(cbom))
        if work_orders is not None:
            archive.writestr("work-orders.json", _dump(work_orders))
        if agility is not None:
            archive.writestr("agility.json", _dump(agility))
        if gate is not None:
            archive.writestr("gate.json", _dump(gate))
        if sarif is not None:
            archive.writestr("gate.sarif.json", _dump(sarif))
        if policy is not None:
            archive.writestr("policy.json", _dump(policy))
        if materials is not None:
            archive.writestr("materials.json", _dump(materials))
    return buffer.getvalue()
