"""Worker pipeline tests — previously untested stages.

Covers stage_agility, stage_business_enrich, stage_clone, stage_container_scan,
stage_evidence, stage_load, stage_normalize, stage_policy, stage_scan.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_agility import execute as agility_stage
from worker.pipeline.stage_business_enrich import execute as business_stage
from worker.pipeline.stage_clone import execute as clone_stage
from worker.pipeline.stage_container_scan import execute as container_stage
from worker.pipeline.stage_evidence import execute as evidence_stage
from worker.pipeline.stage_load import execute as load_stage
from worker.pipeline.stage_normalize import execute as normalize_stage
from worker.pipeline.stage_policy import execute as policy_stage
from worker.pipeline.stage_scan import execute as scan_stage


def _ctx(tmp_path: Path, **overrides) -> PipelineContext:
    base = dict(
        job_id="j1",
        target_repo="local://test-fixture",
        target_branch="main",
        triggered_by="tester",
        workspace_dir=str(tmp_path),
        repo_path=str(tmp_path),
        scan_id="scan-1",
    )
    base.update(overrides)
    return PipelineContext(**base)


class FakeSession:
    """Minimal session: execute() -> scalars, get(), add(), flush()."""

    def __init__(self, rows=None):
        self._rows = list(rows or [])
        self.added = []
        self.flushed = 0

    def execute(self, _query):
        return SimpleNamespace(scalars=lambda: list(self._rows))

    def get(self, _model, _pk):
        return None

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        self.flushed += 1


def _evidence_row(eid: str, algorithm: str = "DES", **extra) -> SimpleNamespace:
    return SimpleNamespace(
        id=eid,
        algorithm=algorithm,
        key_size=extra.get("key_size", 56),
        mode=extra.get("mode", "ECB"),
        padding=extra.get("padding", "PKCS5Padding"),
        purpose=extra.get("purpose", "ENCRYPTION"),
        is_hardcoded_key=extra.get("is_hardcoded_key", False),
        confidence=extra.get("confidence", "HIGH"),
        file_path=extra.get("file_path", "src/Pay.java"),
        line_number=extra.get("line_number", 7),
        compliance_status="UNKNOWN",
        finding_data=extra.get("finding_data", {"scanner_id": "s"}),
        policy_evaluation={},
        normalized_crypto={},
    )


# ── stage_scan ──────────────────────────────────────────────────────────

class TestStageScan:
    def test_scans_local_directory_and_populates_meta(self, tmp_path: Path):
        (tmp_path / "Pay.java").write_text(
            "class Pay {\n"
            "  void go() {\n"
            "    Cipher c = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");\n"
            "    SecretKeySpec k = new SecretKeySpec(key, \"DES\");\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        ctx = scan_stage(_ctx(tmp_path))
        assert ctx.findings
        assert ctx.scan_meta["scanner_id"]
        assert ctx.scan_meta["scan_start"]
        assert ctx.scan_meta["target_type"] == "LOCAL_DIRECTORY"
        assert ctx.scan_meta["operator"] == "tester"
        assert "statistics" in ctx.scan_meta
        # results file written into the workspace
        assert Path(ctx.scan_meta["scan_results_file"]).exists()
        assert ctx.scan_meta["observation_count"] >= 0


# ── stage_clone ─────────────────────────────────────────────────────────

class TestStageClone:
    def test_uses_injected_cloner(self, tmp_path: Path):
        dest = tmp_path / "repo"
        dest.mkdir()
        (dest / "README.md").write_text("hi", encoding="utf-8")
        cloner = MagicMock()
        cloner.clone.return_value = "abc123def"
        ctx = clone_stage(_ctx(tmp_path, target_repo="https://github.com/x/y.git"),
                          cloner=cloner)
        cloner.clone.assert_called_once()
        assert ctx.repo_path == str(dest)
        assert ctx.target_commit == "abc123def"

    def test_falls_back_to_commit_when_dest_missing(self, tmp_path: Path):
        cloner = MagicMock()
        cloner.clone.return_value = str(tmp_path / "elsewhere")
        ctx = clone_stage(_ctx(tmp_path), cloner=cloner)
        assert ctx.repo_path == str(tmp_path / "elsewhere")


# ── stage_load ──────────────────────────────────────────────────────────

class TestStageLoad:
    def _good_records(self) -> list[dict]:
        return [
            {
                "evidence_id": "e1",
                "content_hash": "a" * 64,
                "chain_hash": "b" * 64,
                "chain_position": 0,
                "previous_hash": None,
                "algorithm": "DES",
                "finding": {"crypto": {"algorithm": "DES"}},
            },
            {
                "evidence_id": "e2",
                "content_hash": "c" * 64,
                "chain_hash": "d" * 64,
                "chain_position": 1,
                "previous_hash": "b" * 64,
                "algorithm": "AES",
                "finding": {"crypto": {"algorithm": "AES"}},
            },
        ]

    def test_loads_scan_and_evidence(self, tmp_path: Path, monkeypatch):
        session = FakeSession()
        loaded = SimpleNamespace(id="scan-1")
        monkeypatch.setattr(
            "db.loader.evidence_loader.EvidenceLoader",
            lambda s: SimpleNamespace(load=lambda **kw: loaded),
        )
        ctx = _ctx(tmp_path)
        ctx.evidence_records = self._good_records()
        ctx.manifest = {"manifest_id": "m1"}
        result = load_stage(ctx, session)
        assert result.scan_id == "scan-1"
        assert session.flushed >= 1

    def test_persists_container_scan(self, tmp_path: Path, monkeypatch):
        session = FakeSession()
        loaded = SimpleNamespace(id="scan-2")
        monkeypatch.setattr(
            "db.loader.evidence_loader.EvidenceLoader",
            lambda s: SimpleNamespace(load=lambda **kw: loaded),
        )
        ctx = _ctx(tmp_path)
        ctx.evidence_records = self._good_records()
        ctx.container_result = {"packages": [], "libraries": [], "vulnerabilities": []}
        load_stage(ctx, session)
        container_scans = [o for o in session.added
                           if type(o).__name__ == "ContainerScan"]
        assert container_scans

    def test_rejects_bad_chain_positions(self, tmp_path: Path):
        ctx = _ctx(tmp_path)
        ctx.evidence_records = self._good_records()
        ctx.evidence_records[1]["chain_position"] = 5
        with pytest.raises(RuntimeError, match="pre-load verification failed"):
            load_stage(ctx, FakeSession())


# ── stage_container_scan ────────────────────────────────────────────────

class TestStageContainerScan:
    def test_no_manifest_noop(self, tmp_path: Path):
        (tmp_path / "plain.txt").write_text("nothing here", encoding="utf-8")
        ctx = container_stage(_ctx(tmp_path))
        assert ctx.container_result == {}

    def test_missing_root_noop(self, tmp_path: Path):
        ctx = container_stage(_ctx(tmp_path, repo_path=str(tmp_path / "nope")))
        assert ctx.container_result == {}

    def test_detects_package_json_manifest(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"name": "app", "dependencies": {"crypto-js": "^4.0.0"}}',
            encoding="utf-8",
        )
        ctx = container_stage(_ctx(tmp_path))
        assert "packages" in ctx.container_result
        assert "libraries" in ctx.container_result
        assert ctx.scan_meta["container"]["packages"] >= 0

    def test_dockerfile_marker_triggers_scan(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\nRUN pip install pycryptodome\n",
            encoding="utf-8",
        )
        ctx = container_stage(_ctx(tmp_path))
        assert "packages" in ctx.container_result


# ── stage_evidence ──────────────────────────────────────────────────────

class TestStageEvidence:
    def test_builds_chain_and_manifest(self, tmp_path: Path):
        findings = [
            {"source": {"file_path": "a.java", "line_number": 1},
             "crypto": {"algorithm": "DES"},
             "metadata": {"scanner_id": "s"}},
            {"source": {"file_path": "b.java", "line_number": 2},
             "crypto": {"algorithm": "AES"},
             "metadata": {"scanner_id": "s"}},
        ]
        ctx = _ctx(tmp_path)
        ctx.findings = findings
        evidence_stage(ctx)
        assert len(ctx.evidence_records) == 2
        for record in ctx.evidence_records:
            assert record["content_hash"]
            assert record["chain_hash"]
        assert ctx.manifest["total_findings"] == 2
        assert ctx.manifest["first_chain_hash"]
        assert ctx.manifest["last_chain_hash"]

    def test_class_wrapper(self, tmp_path: Path):
        from worker.pipeline.stage_evidence import StageEvidence

        ctx = _ctx(tmp_path)
        ctx.findings = []
        out = StageEvidence().execute(ctx)
        assert out.manifest["total_findings"] == 0


# ── stage_normalize ─────────────────────────────────────────────────────

class TestStageNormalize:
    def test_normalizes_rows(self, tmp_path: Path):
        session = FakeSession([_evidence_row("e1", "DES"), _evidence_row("e2", "AES")])
        ctx = normalize_stage(_ctx(tmp_path), session)
        row = session._rows[0]
        assert row.normalized_crypto["algorithm"] in ("DES", "3DES")
        assert session.flushed == 1
        assert ctx is not None

    def test_normalize_unknown_keeps_algorithm(self, tmp_path: Path):
        session = FakeSession([_evidence_row("e1", "COMPLETELY-MADE-UP-ALGO")])
        normalize_stage(_ctx(tmp_path), session)
        row = session._rows[0]
        assert row.normalized_crypto["algorithm"] == "UNKNOWN"
        assert row.algorithm == "COMPLETELY-MADE-UP-ALGO"


# ── stage_policy ────────────────────────────────────────────────────────

class TestStagePolicy:
    def test_evaluates_rows_and_sets_status(self, tmp_path: Path):
        session = FakeSession([_evidence_row("e1", "DES", purpose="ENCRYPTION")])
        ctx = policy_stage(_ctx(tmp_path), session)
        row = session._rows[0]
        assert row.policy_evaluation
        assert row.compliance_status in ("PASS", "FAIL", "WARN", "UNKNOWN")
        assert session.flushed == 1
        assert ctx is not None

    def test_injects_compliance_scopes(self, tmp_path: Path):
        row = _evidence_row("e1", "AES")
        row.finding_data = {}
        session = FakeSession([row])
        ctx = _ctx(tmp_path, compliance_scopes=["PCI_DSS"])
        policy_stage(ctx, session)
        assert row.finding_data["compliance_scopes"] == ["PCI_DSS"]


# ── stage_agility / stage_business_enrich — degraded paths ──────────────

class TestStageAgility:
    def test_no_session_noop(self, tmp_path: Path):
        ctx = _ctx(tmp_path, system_id="sys-1")
        out = agility_stage(ctx, session=None)
        assert out is ctx
        assert out.scan_meta == {}

    def test_unavailable_imports_noop(self, tmp_path: Path, monkeypatch):
        for name in ("agility.readiness", "agility.system_score",
                     "db.models.system", "db.repositories.maturity_repository",
                     "db.repositories.system_repository"):
            monkeypatch.setitem(sys.modules, name, None)
        ctx = _ctx(tmp_path, system_id="sys-1")
        out = agility_stage(ctx, session=FakeSession())
        assert out is ctx


class TestStageBusinessEnrich:
    def test_no_session_noop(self, tmp_path: Path):
        ctx = _ctx(tmp_path)
        out = business_stage(ctx, session=None)
        assert out is ctx
        assert ctx.scan_meta == {}

    def test_unavailable_imports_noop(self, tmp_path: Path, monkeypatch):
        for name in ("api.graph_builder", "business_context.core.enricher",
                     "db.models.crypto_asset"):
            monkeypatch.setitem(sys.modules, name, None)
        ctx = _ctx(tmp_path)
        out = business_stage(ctx, session=FakeSession())
        assert out is ctx
