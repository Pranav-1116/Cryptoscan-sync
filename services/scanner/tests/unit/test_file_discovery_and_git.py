"""Scanner core tests — file discovery + git client (untested modules)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scanner.core.file_discovery import FileDiscovery
from scanner.git.git_client import GitClient, GitMetadata


def _tree(root: Path) -> dict[str, str]:
    files = {}
    for dirpath, _, filenames in os.walk(root):
        dirpath = Path(dirpath)
        for fn in filenames:
            rel = dirpath.relative_to(root) / fn
            files[str(rel)] = (dirpath / fn).read_text(encoding="utf-8", errors="replace")
    return files


class TestFileDiscovery:
    def _make_tree(self, tmp_path: Path) -> Path:
        (tmp_path / "src" / "main" / "java").mkdir(parents=True)
        (tmp_path / "src" / "test" / "java").mkdir(parents=True)
        (tmp_path / "build").mkdir()
        (tmp_path / ".git").mkdir()
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "src" / "main" / "java" / "App.java").write_text("class App {}", encoding="utf-8")
        (tmp_path / "src" / "test" / "java" / "AppTest.java").write_text("class AppTest {}", encoding="utf-8")
        (tmp_path / "build" / "Generated.java").write_text("class Generated {}", encoding="utf-8")
        (tmp_path / "notes.txt").write_text("not source", encoding="utf-8")
        return tmp_path

    def test_finds_only_source_extensions(self, tmp_path):
        root = self._make_tree(tmp_path)
        found = sorted(str(p.relative_to(root)) for p in FileDiscovery().discover(root))
        assert "src/main/java/App.java" in found
        assert "notes.txt" not in found
        assert "build/Generated.java" not in found  # build excluded by default

    def test_excludes_build_and_vcs_dirs(self, tmp_path):
        root = self._make_tree(tmp_path)
        found = [str(p.relative_to(root)) for p in FileDiscovery().discover(root)]
        assert not any("build" in p or ".git" in p or "node_modules" in p for p in found)

    def test_exclude_test_dirs(self, tmp_path):
        root = self._make_tree(tmp_path)
        with_tests = [str(p.relative_to(root)) for p in FileDiscovery(exclude_test_dirs=False).discover(root)]
        without_tests = [str(p.relative_to(root)) for p in FileDiscovery(exclude_test_dirs=True).discover(root)]
        assert any("/test/" in p for p in with_tests)
        assert not any("/test/" in p for p in without_tests)

    def test_raises_on_missing_root(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            list(FileDiscovery().discover(tmp_path / "nope"))

    def test_raises_on_file_root(self, tmp_path):
        target = tmp_path / "file.java"
        target.write_text("", encoding="utf-8")
        with pytest.raises(ValueError):
            list(FileDiscovery().discover(target))

    def test_oversized_file_skipped(self, tmp_path):
        (tmp_path / "Big.java").write_text("x" * 100, encoding="utf-8")
        found = list(FileDiscovery(max_file_size_mb=0.00001).discover(tmp_path))
        assert found == []

    def test_custom_extensions(self, tmp_path):
        (tmp_path / "App.go").write_text("package main", encoding="utf-8")
        (tmp_path / "App.java").write_text("class A {}", encoding="utf-8")
        found = list(FileDiscovery(extensions=(".go",)).discover(tmp_path))
        assert [p.name for p in found] == ["App.go"]

    def test_hidden_dirs_skipped(self, tmp_path):
        hidden = tmp_path / ".hidden"
        hidden.mkdir(parents=True)
        (hidden / "Secret.java").write_text("class S {}", encoding="utf-8")
        (tmp_path / "Visible.java").write_text("class V {}", encoding="utf-8")
        found = list(FileDiscovery().discover(tmp_path))
        assert [p.name for p in found] == ["Visible.java"]


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


@pytest.mark.skipif(not _git_available(), reason="git binary not available")
class TestGitClient:
    def _init_repo(self, tmp_path: Path) -> Path:
        subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.email",
                        "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.name",
                        "Test User"], check=True)
        (tmp_path / "file.txt").write_text("hello", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-q",
                        "-m", "initial commit"], check=True)
        return tmp_path

    def test_get_metadata(self, tmp_path):
        repo = self._init_repo(tmp_path / "repo")
        meta = GitClient().get_metadata(repo, "https://example.com/org/repo.git")
        assert isinstance(meta, GitMetadata)
        assert len(meta.commit_hash) == 40
        assert meta.branch == "main"
        assert meta.repository_url == "https://example.com/org/repo.git"
        assert meta.commit_message == "initial commit"
        assert "Test User" in meta.commit_author

    def test_extract_context_compat(self, tmp_path):
        repo = self._init_repo(tmp_path / "repo")
        ctx = GitClient().extract_context(repo, "https://example.com/org/repo.git")
        assert set(ctx) == {"commit_hash", "commit_author", "commit_timestamp",
                            "branch", "repository_url", "commit_message"}
        assert ctx["branch"] == "main"

    def test_clone_local_repo(self, tmp_path):
        source = self._init_repo(tmp_path / "source")
        dest = tmp_path / "clone"
        GitClient().clone(f"file://{source}", dest)
        assert (dest / "file.txt").exists()

    def test_clone_failure_raises_runtime_error(self, tmp_path):
        with pytest.raises(RuntimeError):
            GitClient().clone("https://127.0.0.1:1/nope.git", tmp_path / "x")
