"""A local scan target may legitimately contain the scan workspace.

Scanning a project directory that holds `data/workspaces/` -- the project
checkout itself being the obvious case -- used to fail at stage "init"
with "maximum recursion depth exceeded", before a single file was read.
shutil.copytree walks the source while writing into the destination, so
when the destination sits under the source it descends into the tree it
is still producing.

The RecursionError named neither the directory nor the cause, which made
it look like a parser bug rather than a copy that eats itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

from worker.workspace.repo_cloner import RepoCloner


def _seed(root: Path) -> None:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "crypto.py").write_text("import hashlib\n", encoding="utf-8")
    (root / "README.md").write_text("project\n", encoding="utf-8")


def test_copy_terminates_when_the_workspace_is_inside_the_target(tmp_path):
    source = tmp_path / "project"
    _seed(source)
    # The workspace lives inside the very tree being copied.
    dest = source / "data" / "workspaces" / "job-1" / "repo"

    # Previously raised RecursionError; the assertion is simply that it returns.
    commit = RepoCloner().clone(repo_url=f"local://{source}", branch="main",
                                target_path=str(dest))

    assert commit == "local"
    assert (dest / "src" / "crypto.py").read_text(encoding="utf-8") == "import hashlib\n"
    assert (dest / "README.md").exists()


def test_previous_scan_outputs_are_not_copied_into_the_new_scan(tmp_path):
    """Earlier runs' extracted repos are scanner artefacts, not target source.

    Copying them would re-scan every previous run's checkout and attribute
    those findings to this scan, inflating exactly the counts a bank reads.
    """
    source = tmp_path / "project"
    _seed(source)
    older = source / "data" / "workspaces" / "job-0" / "repo"
    older.mkdir(parents=True)
    (older / "vendored.py").write_text("from Crypto.Cipher import DES\n", encoding="utf-8")

    dest = source / "data" / "workspaces" / "job-1" / "repo"
    RepoCloner().clone(repo_url=f"local://{source}", branch="main", target_path=str(dest))

    assert (dest / "src" / "crypto.py").exists()          # real source copied
    assert not (dest / "data" / "workspaces").exists()    # prior runs skipped


def test_ordinary_target_outside_the_workspace_is_unaffected(tmp_path):
    """The guard must not change the normal case."""
    source = tmp_path / "project"
    _seed(source)
    (source / "node_modules").mkdir()
    (source / "node_modules" / "junk.js").write_text("x\n", encoding="utf-8")
    dest = tmp_path / "workspaces" / "job-1" / "repo"

    RepoCloner().clone(repo_url=f"local://{source}", branch="main", target_path=str(dest))

    assert (dest / "src" / "crypto.py").exists()
    assert (dest / "README.md").exists()
    assert not (dest / "node_modules").exists()  # still honoured


def test_pathologically_deep_tree_is_bounded_not_fatal(tmp_path):
    """A deep tree must cost coverage, not the whole scan.

    Self-nesting is not the only way to get one. This repository carried
    `_tmp/snbchk/ws/repo/ws/repo/...` about 250 levels deep -- 5,167 files
    committed by an earlier harness run hitting this same bug, since
    removed -- and a customer can hand us the same shape in an unpacked
    archive or a vendored dependency. Those trees live outside the
    workspace, so pruning the destination does not help; the copy itself
    has to be bounded.
    """
    source = tmp_path / "project"
    _seed(source)
    deep = source / "deep"
    for _ in range(RepoCloner.MAX_COPY_DEPTH + 40):
        deep = deep / "ws"
    deep.mkdir(parents=True)
    (deep / "buried.py").write_text("import ssl\n", encoding="utf-8")

    dest = tmp_path / "workspaces" / "job-1" / "repo"
    RepoCloner().clone(repo_url=f"local://{source}", branch="main", target_path=str(dest))

    # The scan completes and the real source is present...
    assert (dest / "src" / "crypto.py").exists()
    # ...and the tree is truncated rather than copied without limit.
    assert not deep.relative_to(source).parts[: RepoCloner.MAX_COPY_DEPTH + 2] == ()
    copied_depth = 0
    probe = dest / "deep"
    while probe.is_dir():
        copied_depth += 1
        probe = probe / "ws"
    assert copied_depth <= RepoCloner.MAX_COPY_DEPTH + 1


def test_recursion_limit_is_not_merely_raised(tmp_path):
    """Guard against a 'fix' that just buys headroom.

    A deeper recursion limit would make the old bug pass this suite while
    still failing on a real estate, so the copy runs under a deliberately
    shallow limit.
    """
    source = tmp_path / "project"
    _seed(source)
    dest = source / "data" / "workspaces" / "job-1" / "repo"

    original = sys.getrecursionlimit()
    sys.setrecursionlimit(200)
    try:
        RepoCloner().clone(repo_url=f"local://{source}", branch="main",
                           target_path=str(dest))
    finally:
        sys.setrecursionlimit(original)

    assert (dest / "src" / "crypto.py").exists()
