"""Clone or copy a scan target into the workspace."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


#: What a fetchable remote may look like. Deliberately excludes anything that
#: starts with "-", and any scheme git would hand to a transport we do not want a
#: bank scan to open (`ext::`, `fd::`).
_REMOTE_URL = re.compile(
    r"^(?:https?://|ssh://(?:[\w.\-]+@)?|git://)[^\s]+$"
)
#: Hex revision or a plain ref name — never an option.
_COMMIT = re.compile(r"^(?:[0-9a-fA-F]{7,64}|[A-Za-z0-9._/\-]{1,200})$")


def _is_within(child: Path, parent: Path) -> bool:
    """True when `child` is `parent` or sits beneath it."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


class RepoCloner:
    def clone(
        self,
        repo_url: str,
        branch: str,
        target_path: str,
        commit: str | None = None,
        depth: int = 1,
    ) -> str:
        dest = Path(target_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        local = self._as_local_path(repo_url)
        if local is not None:
            if dest.exists():
                shutil.rmtree(dest)
            self._copy_local_tree(local, dest)
            return commit or "local"

        # A remote URL is a positional to `git clone`; a positional beginning with
        # "-" is an option, and `--upload-pack=` turns a clone into arbitrary
        # command execution. `--` ends option parsing, and the URL grammar is
        # checked first so a non-URL never reaches the process at all.
        if not _REMOTE_URL.match(str(repo_url or "")):
            raise ValueError("repository URL is not an http(s), ssh or git URL")
        cmd = ["git", "clone", "--depth", str(depth)]
        if branch:
            cmd.extend(["--branch", branch, "--single-branch"])
        cmd.extend(["--", repo_url, str(dest)])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"git clone failed: {proc.stderr.strip()}")
        if commit:
            if not _COMMIT.match(str(commit or "")):
                raise ValueError("commit must be a hex revision or a ref name")
            checkout = subprocess.run(
                ["git", "-C", str(dest), "checkout", commit, "--"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if checkout.returncode != 0:
                raise RuntimeError(f"git checkout failed: {checkout.stderr.strip()}")
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return (head.stdout or commit or "unknown").strip()

    # A source tree deeper than this is not a codebase. Real repositories
    # sit well under 30 levels; past that it is build output, an unpacked
    # archive, or the fallout of a tool that nested its own workspace. The
    # cap bounds the copy instead of letting the process die on it.
    MAX_COPY_DEPTH = 64

    @classmethod
    def _copy_local_tree(cls, source: Path, dest: Path) -> None:
        """Copy a local scan target iteratively, bounded in depth.

        This was shutil.copytree, which recurses once per directory level
        and therefore dies on a deep tree with "maximum recursion depth
        exceeded" -- reported at pipeline stage "init", naming neither the
        directory nor the cause, so it reads like a parser fault.

        Two separate things produce such a tree, and both are handled here
        rather than in the caller:

        * The destination sitting inside the source. The walk then reaches
          the tree it is still writing and descends into it forever. The
          workspace root is pruned, not just this job's directory, because
          earlier runs' extracted repositories are scanner output rather
          than target source -- copying them would re-scan every previous
          run and bill those findings to this scan.
        * A tree that is simply pathological. This repository carried
          `_tmp/snbchk/ws/repo/ws/repo/...` some 250 levels deep -- 5,167
          files committed by an earlier harness run hitting exactly this
          bug, since removed. A customer can hand us the same shape in a
          vendored dependency or an unpacked archive, so depth is capped
          and the skip is logged rather than trusted not to happen.

        Directory symlinks are copied as links, never followed: a link to
        an ancestor is the third way to make this walk unbounded.
        """
        ignore = shutil.ignore_patterns(".git", "node_modules", "__pycache__")
        source = source.resolve()
        dest_resolved = dest.resolve()
        # <workspace>/<job-id>/repo -> <workspace>
        skip_roots = {dest_resolved, dest_resolved.parent.parent}
        too_deep: list[str] = []

        dest.mkdir(parents=True, exist_ok=True)
        stack: list[tuple[Path, Path, int]] = [(source, dest, 0)]
        while stack:
            src_dir, dst_dir, level = stack.pop()
            try:
                entries = list(src_dir.iterdir())
            except OSError as exc:
                logger.warning("clone_copy_unreadable_dir",
                               extra={"path": str(src_dir), "error": str(exc)})
                continue
            names = [e.name for e in entries]
            ignored = set(ignore(str(src_dir), names))
            for entry in entries:
                if entry.name in ignored:
                    continue
                target = dst_dir / entry.name
                if entry.is_symlink():
                    link = entry.readlink()
                    try:
                        target.symlink_to(link)
                    except OSError:
                        pass
                    continue
                if entry.is_dir():
                    if entry.resolve() in skip_roots:
                        continue
                    if level + 1 > cls.MAX_COPY_DEPTH:
                        too_deep.append(str(entry))
                        continue
                    target.mkdir(parents=True, exist_ok=True)
                    stack.append((entry, target, level + 1))
                else:
                    try:
                        shutil.copy2(entry, target)
                    except OSError as exc:
                        logger.warning("clone_copy_file_failed",
                                       extra={"path": str(entry), "error": str(exc)})

        if too_deep:
            # Loud, and it names paths: a silently truncated scan would
            # under-report an estate, which is the one failure this product
            # must never produce quietly.
            logger.warning(
                "clone_copy_depth_limit",
                extra={"limit": cls.MAX_COPY_DEPTH,
                       "skipped_count": len(too_deep),
                       "skipped_sample": too_deep[:5]},
            )

    @staticmethod
    def _copy_ignore(source: Path, dest: Path):
        """Ignore callable that stops a local copy recursing into its own output.

        Scanning a directory that contains the scan workspace -- the project
        checkout itself is the obvious case -- used to die with
        "maximum recursion depth exceeded" before a single file was read.
        copytree walks `source` while writing into `dest`; when `dest` sits
        under `source`, the walk reaches the tree it is still producing and
        descends into it forever. The job failed at stage "init" with a
        RecursionError, which named neither the directory nor the cause.

        The whole workspace root is skipped, not just this job's directory.
        Previous scan outputs are build artefacts of the scanner, not source
        belonging to the target, and copying them would mean re-scanning
        every earlier run's extracted repositories -- gigabytes of findings
        already recorded, re-attributed to this scan.
        """
        base = shutil.ignore_patterns(".git", "node_modules", "__pycache__")
        try:
            source_resolved = source.resolve()
            # <workspace>/<job-id>/repo -> <workspace>
            skip_roots = {dest.resolve(), dest.resolve().parent.parent}
        except OSError:  # pragma: no cover - unreadable path, fall back to names
            return base

        def _ignore(dir_path: str, names: list[str]) -> set[str]:
            ignored = set(base(dir_path, names))
            try:
                here = Path(dir_path).resolve()
            except OSError:
                return ignored
            if not _is_within(here, source_resolved):
                return ignored
            for name in names:
                child = here / name
                if child in skip_roots:
                    ignored.add(name)
            return ignored

        return _ignore

    def _as_local_path(self, repo_url: str) -> Path | None:
        raw = repo_url
        if raw.startswith("local://"):
            raw = raw[len("local://") :]
        elif raw.startswith("file://"):
            raw = raw[len("file://") :]
        path = Path(raw)
        if not path.is_absolute():
            from shared_config.env_loader import repo_root

            path = repo_root() / raw
        if path.exists() and path.is_dir():
            return path
        return None
