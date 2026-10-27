"""Platform scope enforcement — the honest boundaries are tested, not just docs.

Three guarantees:
1. The scope manifest is self-consistent (unique ids, all invariants present).
2. The codebase stays inside the boundaries: no module path or docstring
   declares an out-of-scope capability (mainframe, COBOL, malware,
   endpoint agents, behavior analytics).
3. The evidence layer never carries key material / secret values:
   shared models and the evidence-pack builder use strict field whitelists.

These tests walk the repository, so they double as a regression net for any
future service that tries to drift outside the declared scope.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared_models.platform_scope import (
    BANNED_DOC_PHRASES,
    BANNED_PATH_TOKENS,
    FORBIDDEN_EVIDENCE_FIELDS,
    NON_GOALS,
    INVARIANTS,
    COVERED_AREAS,
    scope_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVICE_ROOTS = [REPO_ROOT / "services", REPO_ROOT / "shared"]


def _iter_python_files():
    for root in SERVICE_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if any(part in {"__pycache__", "node_modules", ".venv"} for part in path.parts):
                continue
            yield path


class TestScopeManifest:
    def test_manifest_shape(self):
        manifest = scope_manifest()
        assert manifest["platform"] == "CryptoScan"
        assert manifest["schema_version"] == 1
        for key in ("mission", "covered_areas", "non_goals",
                    "access_model", "invariants"):
            assert key in manifest

    def test_unique_area_ids(self):
        ids = [area["id"] for area in COVERED_AREAS]
        assert len(ids) == len(set(ids))

    def test_unique_non_goal_ids(self):
        ids = [goal["id"] for goal in NON_GOALS]
        assert len(ids) == len(set(ids))

    def test_all_invariants_present(self):
        invariant_ids = {inv["id"] for inv in INVARIANTS}
        for required in ("read-only-collection", "evidence-chained",
                         "metadata-only", "deterministic-policy",
                         "honest-status"):
            assert required in invariant_ids

    def test_metadata_only_invariant_mentions_key_material(self):
        meta = next(inv for inv in INVARIANTS if inv["id"] == "metadata-only")
        assert "never" in meta["detail"].lower()
        assert "key material" in meta["detail"].lower()

    def test_every_non_goal_has_label_and_detail(self):
        for goal in NON_GOALS:
            assert goal["label"]
            assert len(goal["detail"]) > 20

    def test_covered_areas_cover_the_four_verticals(self):
        joined = " ".join(area["label"] for area in COVERED_AREAS).lower()
        for keyword in ("network", "container", "cloud", "ot/ics",
                        "payment hsm", "vendor"):
            assert keyword in joined


class TestCodebaseStaysInScope:
    def test_no_out_of_scope_module_paths(self):
        violations = []
        for path in _iter_python_files():
            rel = str(path.relative_to(REPO_ROOT)).lower()
            for token in BANNED_PATH_TOKENS:
                if token in rel:
                    violations.append(f"{rel} (token '{token}')")
        assert violations == [], (
            "out-of-scope module paths found: " + ", ".join(violations)
        )

    def test_no_out_of_scope_docstring_declarations(self):
        violations = []
        for path in _iter_python_files():
            # tests and the boundary manifest itself legitimately *name* the
            # boundaries to define/document them — they are not declarations
            # of capability, so they are not scanned
            rel = path.relative_to(REPO_ROOT)
            if any(part == "tests" for part in rel.parts):
                continue
            if rel.name == "platform_scope.py":
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            docstring = text.lstrip()
            if not docstring.startswith(('"""', "'''")):
                continue
            end = docstring.find('"""', 3) if docstring.startswith('"""') \
                else docstring.find("'''", 3)
            if end == -1:
                continue
            head = docstring[:end].lower()
            for phrase in BANNED_DOC_PHRASES:
                if phrase in head:
                    violations.append(f"{rel} ('{phrase}')")
        assert violations == [], (
            "out-of-scope declarations found: " + ", ".join(violations)
        )


class TestEvidenceNeverCarriesKeyMaterial:
    def test_shared_models_have_no_forbidden_fields(self):
        from shared_models.evidence import EvidenceRecordDTO
        from shared_models.finding import CryptoInfo, SourceLocation

        models = [EvidenceRecordDTO, CryptoInfo, SourceLocation]
        violations = []
        for model in models:
            for field_name in model.model_fields:
                if any(tok in field_name.lower() for tok in FORBIDDEN_EVIDENCE_FIELDS):
                    violations.append(f"{model.__name__}.{field_name}")
        assert violations == []

    def test_evidence_pack_uses_strict_whitelist(self):
        """Build a pack from records carrying fake secrets; nothing leaks."""
        from evidence.pack.evidence_pack import build_evidence_pack

        secret_carriers = [
            {
                "evidence_id": "e1",
                "chain_position": 0,
                "algorithm": "AES",
                "mode": "GCM",
                "key_size": 256,
                "purpose": "ENCRYPTION",
                "file_path": "src/x.java",
                "line_number": 5,
                "compliance_status": "FAIL",
                "content_hash": "a" * 64,
                "chain_hash": "b" * 64,
                "private_key_pem": "-----BEGIN PRIVATE KEY----- hunter2",
                "secret_value": "sup3r-s3cret",
                "finding_data": {"raw_source": "key = 's3cret'"},  # not whitelisted
            }
        ]
        pack = build_evidence_pack(
            scan={"scan_id": "s1", "target_location": "local://x",
                  "extra_metadata": {"api_key": "sk-live-123"}},
            records=secret_carriers,
        )
        dump = str(pack)
        for forbidden in ("hunter2", "sup3r-s3cret", "s3cret",
                          "sk-live-123", "PRIVATE KEY"):
            assert forbidden not in dump, f"leaked {forbidden!r} into evidence pack"

    def test_pack_records_only_whitelisted_fields(self):
        from evidence.pack.evidence_pack import build_evidence_pack

        pack = build_evidence_pack(
            scan={"scan_id": "s1"},
            records=[{
                "evidence_id": "e1", "chain_position": 0,
                "algorithm": "DES", "content_hash": "c" * 64,
                "chain_hash": "d" * 64, "sneaky": "NOPE",
            }],
        )
        record = pack["records"][0]
        assert "sneaky" not in record
        assert "finding_data" not in record
        assert record["algorithm"] == "DES"

    def test_scan_block_only_whitelisted_fields(self):
        from evidence.pack.evidence_pack import build_evidence_pack

        pack = build_evidence_pack(
            scan={"scan_id": "s1", "target_location": "x",
                  "api_token": "tok-123", "connection_string": "conn"},
            records=[],
        )
        scan = pack["scan"]
        assert "api_token" not in scan
        assert "connection_string" not in scan
        assert scan["scan_id"] == "s1"

    def test_transfer_payload_whitelisted_too(self):
        from evidence.pack.scan_transfer import export_transfer

        payload = export_transfer(
            scan={"scan_id": "s1", "api_token": "tok-123"},
            records=[{
                "evidence_id": "e1", "chain_position": 0,
                "algorithm": "RSA", "content_hash": "e" * 64,
                "chain_hash": "f" * 64, "secret_value": "hunter2",
            }],
        )
        dump = str(payload)
        assert "tok-123" not in dump
        assert "hunter2" not in dump
        assert payload["scan"]["scan_id"] == "s1"
