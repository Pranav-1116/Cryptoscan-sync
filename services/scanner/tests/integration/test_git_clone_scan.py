"""Scan a locally initialized git repo and attach commit metadata."""

from __future__ import annotations

import subprocess
from pathlib import Path

from scanner.core.scanner import Scanner


def test_scan_local_git_repo_attaches_commit(temp_workspace):
    repo = Path(temp_workspace)
    (repo / "src").mkdir()
    (repo / "src" / "Pay.java").write_text(
        "package com.example;\n"
        "import javax.crypto.Cipher;\n"
        "public class Pay { void t() throws Exception { Cipher.getInstance(\"DES\"); } }\n"
    )
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add des"], cwd=repo, check=True, capture_output=True)
    result = Scanner().scan(repo)
    assert any(f.crypto.algorithm == "DES" for f in result.findings)
    finding = next(f for f in result.findings if f.crypto.algorithm == "DES")
    assert finding.git_context is not None
    assert finding.git_context.commit_hash
    assert finding.git_context.commit_hash != "unknown"
