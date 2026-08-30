"""Change-watch probes for 24/7 live scanning.

Interval scanning answers *"is anything wrong right now?"*. Change watching
answers *"did anything change since the last look?"* — and when the answer is
yes, the monitor engine rescans that target immediately instead of waiting
for the next scheduled window. This is what turns the monitor from a nightly
poller into a real-time live scanner for repositories and container images.

Design rules:

- Probes are **cheap and side-effect free**: the git probe is a single
  ``git ls-remote`` round-trip (no clone); the container probe inspects the
  local docker daemon, or reports the registry path as *unsupported* rather
  than guessing.
- A probe never raises out of the engine: failure is reported as a
  ``ProbeResult`` with ``ok=False`` so the engine can record a
  ``WATCH_PROBE_FAILED`` event and keep the last known fingerprint — a
  temporary network blip must not cause a false "CHANGED" (and alert) later.
- The first observation is a **baseline** (verdict ``UNKNOWN``), never an
  alert. Only a *transition* from a previously observed fingerprint to a
  different one is a real change.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ results


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one change probe."""

    state: Optional[str]  # fingerprint of what we saw (None when probing failed)
    ok: bool  # False = probe could not run / could not observe
    error: Optional[str] = None
    supported: bool = True  # False = this target type has no probe at all


# ------------------------------------------------------------------ probes
# Probe protocol: ``probe(config: dict, *, timeout: float) -> ProbeResult``
# where ``config`` is the monitor target's config dict (repo URL, image ref…).

GIT_BRANCHES = ("main", "master", "HEAD")


def git_probe(config: dict, *, timeout: float = 10.0) -> ProbeResult:
    """Resolve the current HEAD of a git repository via ``git ls-remote``.

    Works for HTTPS/SSH URLs and local paths. No clone, no working tree —
    one round-trip to the remote. ``config`` keys: ``repo`` (required),
    ``branch`` (optional; tries ``main``/``master``/``HEAD``).
    """
    repo = str(config.get("repo") or config.get("url") or "").strip()
    if not repo:
        return ProbeResult(state=None, ok=False, error="config needs repo URL (e.g. {'repo': 'https://…'})")

    branch = str(config.get("branch") or "").strip()
    candidates = [branch] if branch else list(GIT_BRANCHES)
    for candidate in candidates:
        try:
            proc = subprocess.run(
                ["git", "ls-remote", repo, candidate],
                capture_output=True, text=True, timeout=timeout,
            )
        except FileNotFoundError:
            return ProbeResult(state=None, ok=False, error="git binary not found on PATH")
        except subprocess.TimeoutExpired:
            return ProbeResult(state=None, ok=False, error=f"git ls-remote timed out after {timeout}s")
        if proc.returncode != 0:
            logger.debug("git_ls_remote_failed", extra={"repo": repo, "branch": candidate})
            continue  # try the next branch name / HEAD
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        if not lines:
            continue
        head = lines[0].split("\t")[0].strip()
        if len(head) >= 7:
            return ProbeResult(state=head, ok=True)
        continue
    return ProbeResult(
        state=None, ok=False,
        error=f"could not resolve HEAD for {repo!r} on branch(es) {candidates}",
    )


def container_probe(config: dict, *, timeout: float = 10.0) -> ProbeResult:
    """Resolve the local image ID (digest-equivalent) for a container image.

    Uses the docker CLI when present. Registry digest resolution needs
    registry credentials/token flows per-registry, so when docker is absent
    we report the probe as *unsupported* — the target still gets scanned on
    its interval, it just cannot trigger change-based rescans.
    """
    reference = str(config.get("image") or config.get("reference") or "").strip()
    if not reference:
        return ProbeResult(state=None, ok=False, error="config needs image reference (e.g. {'image': 'registry/app:tag'})")

    if shutil.which("docker") is None:
        return ProbeResult(
            state=None, ok=False, supported=False,
            error="docker CLI not available — registry digest watch unsupported (scheduled scans continue)",
        )
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(state=None, ok=False, error=f"docker inspect timed out after {timeout}s")
    if proc.returncode != 0:
        return ProbeResult(state=None, ok=False, error=(proc.stderr or proc.stdout or "docker inspect failed").strip()[:300])
    image_id = proc.stdout.strip()
    if not image_id:
        return ProbeResult(state=None, ok=False, error="docker inspect returned an empty image id")
    return ProbeResult(state=image_id, ok=True)


WATCH_PROBES: dict[str, Callable[..., ProbeResult]] = {
    "REPO": git_probe,
    "CONTAINER": container_probe,
}

# Verdicts returned by ChangeDetector.detect
UNKNOWN = "UNKNOWN"  # first observation (baseline) or probe failure
UNCHANGED = "UNCHANGED"
CHANGED = "CHANGED"


class ChangeDetector:
    """Pure change logic: compare a previous fingerprint with a probe result."""

    @staticmethod
    def detect(previous: Any, result: ProbeResult) -> tuple[str, Optional[str]]:
        """Return ``(verdict, next_state_to_store)``.

        - probe failed        -> (UNKNOWN, keep previous) — never clobber a
          good fingerprint with a failure, or a later change would look like
          the *first* observation and never alert.
        - no previous state   -> (UNKNOWN, current) — baseline, never alert.
        - same fingerprint    -> (UNCHANGED, current)
        - different           -> (CHANGED, current)
        """
        if not result.ok or result.state is None:
            return UNKNOWN, previous
        if previous is None:
            return UNKNOWN, result.state
        if str(previous) == str(result.state):
            return UNCHANGED, result.state
        return CHANGED, result.state
