"""The independent, unified estate HBOM generator (§4.4, round 71).

One deterministic document over persisted hardware rows: per-asset
identity, firmware/TPM/HSM posture, evidence references (agent,
timestamps, fingerprint, the recorded evidence IDs), content-addressed
by SHA-256 over its canonical serialization and anchored to the
estate's latest observation — never a wall clock. No dependency edges
are invented; an empty estate renders an empty document with a note.
"""

from __future__ import annotations

import copy

from cbom.hbom import (
    HBOM_FORMAT,
    anchor_as_of,
    compute_hbom_hash,
    generate_hbom,
    hbom_hash_matches,
    to_cyclonedx,
    to_json,
)

ROW_A = {
    "asset_id": "hw-hsm-1",
    "agent_id": "agent-dc-1",
    "manufacturer": "Utimaco",
    "model": "CryptoServer",
    "device_type": "hsm",
    "serial_reference": "SER-0001",
    "hardware_revision": "C",
    "current_fingerprint": "f" * 64,
    "previous_fingerprint": "e" * 64,
    "first_seen": "2026-10-01T08:00:00+00:00",
    "last_seen": "2026-10-10T09:30:00+00:00",
    "last_verified": "2026-10-10T09:31:00+00:00",
    "last_firmware_check": "2026-10-09T00:00:00+00:00",
    "last_crypto_check": "2026-10-10T09:30:00+00:00",
    "last_change": "firmware",
    "firmware": {"version": "4.21.2"},
    "tpm": None,
    "hsm": {"fips_mode": True},
    "capabilities": {"rng": True},
    "crypto_capabilities": {"rsa": [2048, 4096]},
    "previous_state": {"big": "blob"},
    "evidence_history": ["ev-h1", "ev-h2"],
    "risk_score": 40,
    "risk_level": "MEDIUM",
}

ROW_B = {
    "asset_id": "hw-tpm-1",
    "agent_id": "agent-branch-7",
    "manufacturer": "Infineon",
    "model": "SLB9665",
    "device_type": "tpm",
    "serial_reference": None,
    "hardware_revision": None,
    "current_fingerprint": "a" * 64,
    "previous_fingerprint": None,
    "first_seen": "2026-10-02T10:00:00+00:00",
    "last_seen": "2026-10-12T11:00:00+00:00",
    "last_verified": None,
    "last_firmware_check": None,
    "last_crypto_check": None,
    "last_change": None,
    "firmware": None,
    "tpm": {"spec": "2.0"},
    "hsm": None,
    "capabilities": None,
    "crypto_capabilities": None,
    "previous_state": None,
    "evidence_history": ["ev-t1"],
    "risk_score": 10,
    "risk_level": "LOW",
}


def test_document_shape_identity_posture_and_evidence():
    doc = generate_hbom([ROW_A, ROW_B], environment="banking-prod")
    assert doc["bomFormat"] == HBOM_FORMAT
    assert doc["specVersion"] == "1.0"
    # ordered by asset_id: "hw-hsm-1" sorts before "hw-tpm-1"
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == ["hw:hw-hsm-1", "hw:hw-tpm-1"]

    hsm = doc["components"][0]
    assert hsm["name"] == "Utimaco CryptoServer"
    assert hsm["identity"]["serial_reference"] == "SER-0001"
    assert hsm["identity"]["current_fingerprint"] == "f" * 64
    assert hsm["security_modules"] == {"hsm": {"fips_mode": True}}
    assert hsm["firmware"] == {"details": {"version": "4.21.2"},
                               "last_checked": "2026-10-09T00:00:00+00:00"}
    assert hsm["evidence"]["source"].startswith("live hardware inventory")
    assert hsm["evidence"]["agent_id"] == "agent-dc-1"
    assert hsm["evidence"]["evidence_ids"] == ["ev-h1", "ev-h2"]
    assert hsm["evidence"]["last_seen"] == "2026-10-10T09:30:00+00:00"

    tpm = doc["components"][1]
    assert tpm["security_modules"] == {"tpm": {"spec": "2.0"}}
    assert tpm["evidence"]["last_verified"] is None
    assert tpm["evidence"]["evidence_ids"] == ["ev-t1"]

    # fleet aggregates are derived from the same components
    assert doc["hsm_fleet"] == {"count": 1, "asset_ids": ["hw-hsm-1"]}
    assert doc["tpm_fleet"] == {"count": 1, "asset_ids": ["hw-tpm-1"]}
    meta = doc["metadata"]
    assert meta["component_count"] == 2
    assert meta["hsm_count"] == 1
    assert meta["tpm_count"] == 1
    assert meta["device_types"] == {"hsm": 1, "tpm": 1}
    assert meta["environment"] == "banking-prod"


def test_deterministic_and_order_invariant_with_content_addressing():
    one = generate_hbom([ROW_A, ROW_B], environment="prod")
    two = generate_hbom([ROW_B, ROW_A], environment="prod")
    assert one == two  # row order never shifts the document
    assert one["content_hash"] == two["content_hash"]
    assert len(one["content_hash"]) == 64
    # the anchor is the latest observation across the estate
    assert one["metadata"]["as_of"] == "2026-10-12T11:00:00+00:00"
    assert anchor_as_of([ROW_A, ROW_B]) == "2026-10-12T11:00:00+00:00"
    # the hash covers the document exactly as served (content_hash excluded)
    body = {k: v for k, v in one.items() if k != "content_hash"}
    import hashlib

    from shared_models.canonical import canonical_json

    assert one["content_hash"] == hashlib.sha256(
        canonical_json(body).encode("utf-8")).hexdigest()
    assert hbom_hash_matches(one, one["content_hash"]) is True
    # canonical serialization is stable and JSON
    assert to_json(one) == canonical_json(body | {"content_hash": one["content_hash"]})


def test_any_state_change_moves_the_hash():
    base = generate_hbom([ROW_A, ROW_B], environment="prod")
    changed_row = dict(ROW_A, firmware={"version": "4.22.0"})
    changed = generate_hbom([changed_row, ROW_B], environment="prod")
    assert changed["content_hash"] != base["content_hash"]
    # a NEW observation moves the anchor and the hash
    later = generate_hbom([dict(ROW_B, last_seen="2026-10-13T00:00:00+00:00"), ROW_A],
                          environment="prod")
    assert later["metadata"]["as_of"] == "2026-10-13T00:00:00+00:00"
    assert later["content_hash"] != base["content_hash"]
    # environment is part of the addressed content
    other_env = generate_hbom([ROW_A, ROW_B], environment="staging")
    assert other_env["content_hash"] != base["content_hash"]


def test_explicit_anchor_overrides_derivation_but_stays_deterministic():
    doc = generate_hbom([ROW_A], environment="prod", as_of="2026-01-01T00:00:00+00:00")
    again = generate_hbom([ROW_A], environment="prod", as_of="2026-01-01T00:00:00+00:00")
    assert doc["metadata"]["as_of"] == "2026-01-01T00:00:00+00:00"
    assert doc["content_hash"] == again["content_hash"]


def test_empty_estate_is_honest_not_fabricated():
    doc = generate_hbom([], environment="prod")
    assert doc["components"] == []
    assert doc["metadata"]["component_count"] == 0
    assert doc["metadata"]["as_of"] is None
    assert doc["hsm_fleet"]["count"] == 0
    notes = " ".join(doc["metadata"]["notes"])
    assert "empty, not fabricated" in notes
    # still content-addressed: two empty estates hash identically
    assert doc["content_hash"] == generate_hbom([], environment="prod")["content_hash"]


def test_dependencies_are_declared_empty_not_invented():
    doc = generate_hbom([ROW_A], environment="prod")
    assert doc["dependencies"] == []
    assert any("not invented" in n or "by declaration" in n
               for n in doc["metadata"]["notes"])


def test_row_bookkeeping_fields_do_not_shift_the_hash():
    base = generate_hbom([ROW_A], environment="prod")
    # tenant bookkeeping / prior-state blobs are NOT document facts
    noisy = dict(ROW_A, tenant_id="tenant-77", id="row-99",
                 created_at="2026-10-01T00:00:00+00:00",
                 updated_at="2026-10-14T00:00:00+00:00",
                 previous_state={"another": "blob"})
    noisy_doc = generate_hbom([noisy], environment="prod")
    assert noisy_doc["content_hash"] == base["content_hash"]


def test_cyclonedx_export_is_deterministic_and_traceable():
    doc = generate_hbom([ROW_A, ROW_B], environment="banking-prod")
    cd = to_cyclonedx(doc)
    assert cd["bomFormat"] == "CycloneDX"
    assert cd["specVersion"] == "1.5"
    # timestamp is the document's own anchor — never a wall clock
    assert cd["metadata"]["timestamp"] == doc["metadata"]["as_of"]
    assert cd["metadata"]["timestamp"] != "None" or doc["metadata"]["as_of"] is None
    props = {p["name"]: p["value"] for p in cd["metadata"]["properties"]}
    assert props["cryptoscan:hbom-content-hash"] == doc["content_hash"]
    assert props["environment"] == "banking-prod"
    by_ref = {c["bom-ref"]: c for c in cd["components"]}
    assert by_ref["hw:hw-hsm-1"]["type"] == "device"
    assert by_ref["hw:hw-hsm-1"]["version"] == "4.21.2"
    hsm_props = {p["name"]: p["value"] for p in by_ref["hw:hw-hsm-1"]["properties"]}
    assert hsm_props["hsm"] == "true"
    assert hsm_props["serial"] == "SER-0001"
    assert hsm_props["asset_id"] == "hw-hsm-1"
    tpm_props = {p["name"]: p["value"] for p in by_ref["hw:hw-tpm-1"]["properties"]}
    assert tpm_props.get("hsm") is None
    # deterministic: same document, same export
    assert to_cyclonedx(doc) == to_cyclonedx(doc)
    # empty estate exports honestly too
    empty = to_cyclonedx(generate_hbom([], environment="prod"))
    assert empty["components"] == []
    assert empty["metadata"]["timestamp"] is None


def test_hash_check_detects_mutation():
    doc = generate_hbom([ROW_A, ROW_B], environment="prod")
    tampered = copy.deepcopy(doc)
    tampered["components"][0]["manufacturer"] = "NotInfineon"
    assert hbom_hash_matches(tampered, doc["content_hash"]) is False
    # recomputing over the mutated document yields a different address
    assert compute_hbom_hash(tampered) != doc["content_hash"]
