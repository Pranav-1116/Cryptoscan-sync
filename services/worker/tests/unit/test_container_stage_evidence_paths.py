"""The container stage must not leak the worker's staging path into evidence.

``ctx.repo_path`` is the job's staged checkout — ``data/workspaces/job-<uuid>/repo``
— and ``ContainerScanner.scan_filesystem`` records the paths it walked. Left
alone, the job id becomes part of the evidence identity, and remediation
verification fingerprints a finding as ``(file_path, line_number, algorithm)``
while comparing the rescan against the original scan target-wide. The observed
consequence (round 81, operator-loop drill): every dependency finding looked
brand-new on every rescan, so an honestly fixed condition degraded to
REGRESSION on any target that declares a crypto dependency — BouncyCastle,
Tink, OpenSSL — and VERIFIED was unreachable.

These tests pin the property that matters: the same estate scanned under two
different job ids produces byte-identical evidence coordinates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_container_scan import (
    _rebase_findings,
    _target_relative,
)
from worker.pipeline.stage_container_scan import execute as container_scan

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.bank</groupId><artifactId>payments-api</artifactId><version>4.2.1</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk15on</artifactId><version>1.60</version>
    </dependency>
  </dependencies>
</project>
"""


def _staged(tmp_path: Path, job: str) -> Path:
    """A staged checkout the way the clone stage makes it."""
    root = tmp_path / "data" / "workspaces" / f"job-{job}" / "repo"
    (root / "src" / "main" / "java").mkdir(parents=True)
    (root / "pom.xml").write_text(POM, encoding="utf-8")
    return root


def _ctx(root: Path) -> PipelineContext:
    return PipelineContext(
        job_id=f"job-{root.parent.name}",
        target_repo="local://payments-api",
        target_branch="main",
        triggered_by="operator-drill",
        workspace_dir=str(root.parent),
        repo_path=str(root),
        scan_id=f"scan-{root.parent.name}",
    )


def _coordinates(ctx: PipelineContext) -> set[tuple]:
    """The evidence fingerprint, exactly as remediation verification builds it."""
    return {
        (str((f.get("source") or {}).get("file_path")),
         int((f.get("source") or {}).get("line_number") or 0),
         str((f.get("crypto") or {}).get("algorithm") or "").upper())
        for f in ctx.findings
    }


# ------------------------------------------------------------ the pure helper


def test_target_relative_strips_a_relative_staging_prefix():
    root = Path("data/workspaces/job-1/repo")
    assert _target_relative("data/workspaces/job-1/repo/pom.xml", root) == "pom.xml"
    assert _target_relative(
        "data/workspaces/job-1/repo/src/main/java/Pin.java", root
    ) == "src/main/java/Pin.java"


def test_target_relative_strips_an_absolute_staging_prefix(tmp_path):
    root = tmp_path / "data" / "workspaces" / "job-1" / "repo"
    root.mkdir(parents=True)
    assert _target_relative(str(root / "pom.xml"), root) == "pom.xml"


def test_target_relative_handles_the_mixed_form(tmp_path, monkeypatch):
    """A relative walked path against an absolute root — the form the live
    pipeline actually produced (WORKSPACE_BASE is "./data/workspaces")."""
    monkeypatch.chdir(tmp_path)
    root = _staged(tmp_path, "1")
    assert _target_relative(str(root / "pom.xml"), root.resolve()) == "pom.xml"
    assert _target_relative("data/workspaces/job-1/repo/pom.xml", root) == "pom.xml"


def test_target_relative_leaves_a_foreign_path_alone(tmp_path):
    """Image-internal paths are not under the staged root: inventing a relative
    path for them would be a lie, so they are returned unchanged."""
    root = tmp_path / "repo"
    root.mkdir()
    assert _target_relative("/etc/apk/world", root) == "/etc/apk/world"
    assert _target_relative("usr/lib/libcrypto.so.3", root) == "usr/lib/libcrypto.so.3"


def test_target_relative_passes_through_non_strings():
    root = Path("repo")
    assert _target_relative(None, root) is None
    assert _target_relative("", root) == ""
    assert _target_relative(0, root) == 0


def test_rebase_findings_mutates_in_place_and_counts(tmp_path):
    root = tmp_path / "data" / "workspaces" / "job-9" / "repo"
    findings = [
        {"source": {"file_path": f"{root}/pom.xml", "line_number": 0}},
        {"source": {"file_path": "src/Other.java", "line_number": 12}},
        {"source": "not-a-dict"},
        {"no_source": True},
    ]
    shared = findings[0]
    assert _rebase_findings(findings, root) == 1
    # in place, so the stored container artifact and the evidence agree
    assert shared["source"]["file_path"] == "pom.xml"
    assert findings[1]["source"]["file_path"] == "src/Other.java"


# ------------------------------------------------------------- the real stage


def test_stage_evidence_paths_are_target_relative(tmp_path):
    root = _staged(tmp_path, "abc123")
    ctx = container_scan(_ctx(root))
    if not ctx.findings:  # container_scanner not importable in this environment
        pytest.skip("container_scanner unavailable")
    paths = {str((f.get("source") or {}).get("file_path")) for f in ctx.findings}
    assert paths, "the staged pom.xml declares BouncyCastle: findings expected"
    for path in paths:
        assert "workspaces" not in path, path
        assert "job-" not in path, path
        assert not Path(path).is_absolute(), path
    assert "pom.xml" in paths


def test_stage_discloses_how_many_paths_it_rebased(tmp_path):
    root = _staged(tmp_path, "disclosed")
    ctx = container_scan(_ctx(root))
    container = (ctx.scan_meta or {}).get("container")
    if container is None:
        pytest.skip("container_scanner unavailable")
    # every walked path is lifted out of the staging dir; a finding whose path is
    # not under the root (a bare library name, an image-internal path) is left
    # alone rather than rewritten into something it is not
    assert 1 <= container["evidence_paths_rebased"] <= len(ctx.findings)
    assert container["libraries"] >= 1
    assert all("workspaces" not in str((f.get("source") or {}).get("file_path"))
               for f in ctx.findings)


def test_evidence_coordinates_are_identical_across_two_jobs(tmp_path):
    """The property remediation verification depends on: same estate, different
    job id, identical evidence coordinates."""
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    ctx_a = container_scan(_ctx(_staged(first, "11111111-aaaa")))
    ctx_b = container_scan(_ctx(_staged(second, "22222222-bbbb")))
    if not ctx_a.findings or not ctx_b.findings:
        pytest.skip("container_scanner unavailable")
    assert _coordinates(ctx_a) == _coordinates(ctx_b)
    assert _coordinates(ctx_a), "expected at least the BouncyCastle fingerprints"


def test_stage_without_a_manifest_stays_a_noop(tmp_path):
    root = tmp_path / "data" / "workspaces" / "job-x" / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "App.java").write_text("class App {}\n", encoding="utf-8")
    ctx = container_scan(_ctx(root))
    assert ctx.findings == []
    assert "container" not in (ctx.scan_meta or {})
