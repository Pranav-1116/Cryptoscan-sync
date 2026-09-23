"""Fleet intake: turn a drop of files into binary scans, once per distinct binary.

The spec's orchestrator queues arbitrary volumes of binaries. This platform has
no Kafka and no Flink — the queue is the existing scan-job queue (`enqueue_scan_job`
→ `ScanJob` → worker/API), and this module is the piece that *feeds* it: enumerate
a spool directory, work out what actually needs scanning, queue that, and remember
what was already done so a second pass is cheap.

Two properties matter more than throughput:

* **Every file that is not queued says why.** "Nothing was queued" and "everything
  was already scanned" look identical in a dashboard that only counts jobs — so
  every skip carries a reason and, where it exists, the artifact that covers it.
* **Identity is content, not path.** The same library shipped at eleven paths in a
  release drop is one scan, not eleven. A file whose *content* changed is a new
  scan even at the same path. That is what makes a fleet pass affordable at
  release-train frequency, and it is deterministic: same input tree, same plan.

The state lives next to the spool (``<spool>/.cryptoscan-intake.json``) so the
memory travels with the data it describes, survives restarts, and needs no
database, broker, or network — which is also what keeps this usable air-gapped.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

STATE_FILENAME = ".cryptoscan-intake.json"
STATE_VERSION = 1

DEFAULT_PATTERNS = (
    "*.so", "*.so.*", "*.a", "*.ko", "*.elf", "*.bin", "*.efi", "*.img", "*.fw",
    "*.hex", "*.rom", "*.deb", "*.rpm", "*.jar", "*.apk", "*.whl", "*.zip", "*.tar.gz",
)
#: entry points are commonly extension-less (``openssl``, ``nginx``, ``busybox``)
EXECUTABLE_FALLBACK = True

DEFAULT_MIN_SIZE = 64                      # bytes: below this there is nothing to find
DEFAULT_MAX_SIZE = 512 * 1024 * 1024       # 512 MiB per file, stated rather than implied
HASH_CHUNK = 1024 * 1024


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #

def load_state(path: str | Path) -> dict[str, Any]:
    """Read the intake memory. A missing or corrupt file is an empty memory, not a crash."""
    file = Path(path)
    if not file.is_file():
        return {"version": STATE_VERSION, "by_sha256": {}, "by_path": {}, "note": "no state file yet"}
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"version": STATE_VERSION, "by_sha256": {}, "by_path": {},
                "note": f"state file unreadable ({type(exc).__name__}), starting fresh"}
    return {
        "version": STATE_VERSION,
        "by_sha256": dict(raw.get("by_sha256") or {}),
        "by_path": dict(raw.get("by_path") or {}),
        "updated_at": raw.get("updated_at"),
        "note": raw.get("note"),
    }


def save_state(path: str | Path, state: dict[str, Any]) -> None:
    """Write the memory atomically — a half-written index would re-scan a fleet."""
    from datetime import datetime, timezone

    payload = {
        "version": STATE_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "by_sha256": state.get("by_sha256") or {},
        "by_path": state.get("by_path") or {},
    }
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_suffix(file.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, file)


def state_path_for(spool: str | Path, override: str | Path | None = None) -> Path:
    return Path(override) if override else Path(spool) / STATE_FILENAME


# --------------------------------------------------------------------------- #
# planning
# --------------------------------------------------------------------------- #

@dataclass
class Candidate:
    """One file the intake considered, and what it decided about it."""

    path: str
    size: int
    sha256: str | None = None
    action: str = "queue"          # queue | skip
    reason: str = ""
    artifact_id: str | None = None  # the artifact that already covers this content, when known
    prior_path: str | None = None
    job_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256,
                "action": self.action, "reason": self.reason,
                "artifact_id": self.artifact_id, "prior_path": self.prior_path,
                "job_id": self.job_id}


@dataclass
class IntakePlan:
    """What an intake pass would do — the whole answer, including the refusals."""

    spool: str
    queued: list[Candidate] = field(default_factory=list)
    skipped: list[Candidate] = field(default_factory=list)
    state_path: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def considered(self) -> int:
        return len(self.queued) + len(self.skipped)

    def as_dict(self) -> dict[str, Any]:
        return {"spool": self.spool, "state_path": self.state_path,
                "considered": self.considered, "queued": len(self.queued),
                "skipped": len(self.skipped),
                "files": [c.as_dict() for c in self.queued + self.skipped],
                "notes": self.notes}


def hash_file(path: str | Path, *, chunk: int = HASH_CHUNK) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in patterns)


def _is_candidate(path: Path, patterns: Iterable[str], executable_fallback: bool) -> bool:
    name = path.name
    if name.startswith("."):                       # the state file, editor droppings
        return False
    if _matches(name, patterns):
        return True
    # entry points are usually extension-less (``openssl``, ``nginx``, ``busybox``)
    return bool(executable_fallback and "." not in name and _walk_has_exec_bit(path))


def _walk_has_exec_bit(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & 0o111)
    except OSError:
        return False


def plan_intake(
    spool: str | Path,
    *,
    state: dict[str, Any] | None = None,
    state_file: str | Path | None = None,
    patterns: Iterable[str] = DEFAULT_PATTERNS,
    executable_fallback: bool = EXECUTABLE_FALLBACK,
    min_size: int = DEFAULT_MIN_SIZE,
    max_size: int = DEFAULT_MAX_SIZE,
    force: bool = False,
    limit: int | None = None,
    recursive: bool = True,
) -> IntakePlan:
    """Decide, file by file, what this pass would queue — and why not, for the rest.

    ``force`` re-queues content that is already known (a rescan), which is the
    only way to ask for it: without it, unchanged content is a skip with the
    artifact id that covers it.
    """
    root = Path(spool).expanduser()
    resolved_state = state_path_for(root, state_file)
    state = state or load_state(resolved_state)
    plan = IntakePlan(spool=str(root), state_path=str(resolved_state))
    by_sha = dict(state.get("by_sha256") or {})
    by_path = dict(state.get("by_path") or {})
    if state.get("note"):
        plan.notes.append(str(state["note"]))

    if not root.exists():
        plan.notes.append(f"spool directory does not exist: {root}")
        return plan
    if not root.is_dir():
        plan.notes.append(f"spool is not a directory: {root}")
        return plan

    seen_in_pass: dict[str, str] = {}
    candidates: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if name.startswith("."):
                continue  # the state file itself, and editor droppings
            candidates.append(Path(current) / name)
        if not recursive:
            dirnames[:] = []
    candidates.sort()

    queued = 0
    for path in candidates:
        try:
            stat = path.stat()
        except OSError as exc:
            plan.skipped.append(Candidate(str(path), 0, action="skip",
                                          reason=f"unreadable: {type(exc).__name__}"))
            continue
        if not _is_candidate(path, patterns, executable_fallback):
            plan.skipped.append(Candidate(str(path), stat.st_size, action="skip",
                                          reason="not a binary-looking name and not an extension-less "
                                                 "executable (patterns decide; see --patterns)"))
            continue
        if stat.st_size < min_size:
            plan.skipped.append(Candidate(str(path), stat.st_size, action="skip",
                                          reason=f"smaller than min-size ({min_size} bytes)"))
            continue
        if stat.st_size > max_size:
            plan.skipped.append(Candidate(str(path), stat.st_size, action="skip",
                                          reason=f"larger than max-size ({max_size} bytes)"))
            continue
        if limit is not None and queued >= limit:
            plan.skipped.append(Candidate(str(path), stat.st_size, action="skip",
                                          reason=f"over this pass's limit ({limit})"))
            continue

        try:
            digest = hash_file(path)
        except OSError as exc:
            plan.skipped.append(Candidate(str(path), stat.st_size, action="skip",
                                          reason=f"could not be read to hash it: {type(exc).__name__}"))
            continue

        # already-covered content is answered with the artifact that covers it, which is
        # more useful than "this pass found a duplicate"
        known = by_sha.get(digest)
        previous = by_path.get(str(path))
        if known and not force:
            same_path = bool(previous and previous.get("sha256") == digest)
            plan.skipped.append(Candidate(
                str(path), stat.st_size, sha256=digest, action="skip",
                reason=("unchanged since the last pass" if same_path
                        else "this content was already scanned under another path"),
                artifact_id=known.get("artifact_id"), prior_path=known.get("path")))
            continue

        # a pass never queues the same bytes twice, even under --force: two paths with
        # identical content are one scan, and force is about *when*, not about *what*
        if digest in seen_in_pass:
            plan.skipped.append(Candidate(str(path), stat.st_size, sha256=digest, action="skip",
                                          reason="the same content appears twice in this pass; "
                                                 "the first copy is being scanned",
                                          prior_path=seen_in_pass[digest]))
            continue

        candidate = Candidate(str(path), stat.st_size, sha256=digest, action="queue",
                              reason=("content changed since the last pass" if previous
                                      else "new content"))
        plan.queued.append(candidate)
        seen_in_pass[digest] = str(path)
        queued += 1

    return plan


def record_outcome(
    state: dict[str, Any],
    plan: IntakePlan,
    *,
    artifact_ids: dict[str, str] | None = None,
    job_ids: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fold a finished pass into the memory (queued files get their artifact ids)."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    artifact_ids = artifact_ids or {}
    job_ids = job_ids or {}
    by_sha = dict(state.get("by_sha256") or {})
    by_path = dict(state.get("by_path") or {})
    for candidate in plan.queued:
        artifact_id = artifact_ids.get(candidate.path) or candidate.artifact_id
        job_id = job_ids.get(candidate.path) or candidate.job_id
        if not artifact_id:
            continue  # nothing was queued for it: do not record a scan that did not happen
        by_sha[str(candidate.sha256)] = {"artifact_id": artifact_id, "job_id": job_id,
                                         "path": candidate.path, "scanned_at": now}
        by_path[candidate.path] = {"sha256": candidate.sha256, "artifact_id": artifact_id,
                                   "job_id": job_id, "size": candidate.size, "scanned_at": now}
    return {**state, "by_sha256": by_sha, "by_path": by_path, "updated_at": now}


# --------------------------------------------------------------------------- #
# queueing (HTTP, so the CLI needs no worker library on the box that drops files)
# --------------------------------------------------------------------------- #

def queue_target(
    target: str,
    *,
    api_base: str,
    token: str,
    fmt: str = "cyclonedx",
    recursive: bool = True,
    include_raw: bool = False,
    ingest_cbom: bool = False,
    system_name: str | None = None,
    batch_id: str | None = None,
    verify: bool = True,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Queue one binary scan through the API. Raises RuntimeError on refusal."""
    import urllib.error
    import urllib.request

    from devsecops.dynamic_scan import auth_header

    base = api_base.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise RuntimeError(f"api base must be an http(s) URL, got {api_base!r}")
    body: dict[str, Any] = {"target": target, "format": fmt, "recursive": recursive,
                            "include_raw": include_raw, "ingest_cbom": ingest_cbom}
    if system_name:
        body["system_name"] = system_name
    if batch_id:
        body["batch_id"] = batch_id
    request = urllib.request.Request(
        base + "/api/v1/devsecops/binary/jobs",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **auth_header(token)},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 — scheme checked
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"queueing {target} was refused ({exc.code}): {detail}") from exc
    except OSError as exc:
        raise RuntimeError(f"could not reach {base}: {getattr(exc, 'reason', None) or exc}") from exc


#: planning decides *what* to scan; queueing decides *how* those scans are recorded
PLAN_KEYS = {"patterns", "executable_fallback", "min_size", "max_size", "force", "limit", "recursive"}
QUEUE_KEYS = {"fmt", "include_raw", "ingest_cbom", "system_name"}


def run_pass(
    spool: str | Path,
    *,
    api_base: str | None = None,
    token: str | None = None,
    dry_run: bool = True,
    state_file: str | Path | None = None,
    batch_id: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One intake pass: plan it, queue it (unless dry run), remember what was queued."""
    import uuid

    options = options or {}
    plan_kwargs = {k: v for k, v in options.items() if k in PLAN_KEYS}
    queue_kwargs = {k: v for k, v in options.items() if k in QUEUE_KEYS}
    root = Path(spool).expanduser()
    state_file = state_path_for(root, state_file)
    state = load_state(state_file)
    plan = plan_intake(root, state=state, state_file=state_file, **plan_kwargs)
    plan.state_path = str(state_file)
    batch_id = batch_id or str(uuid.uuid4())
    result: dict[str, Any] = {**plan.as_dict(), "batch_id": batch_id, "dry_run": bool(dry_run),
                              "queued_jobs": 0}
    if dry_run or not plan.queued:
        return result
    if not (api_base and token):
        raise RuntimeError("queueing needs both an api base and a token "
                           "(or run with --dry-run to only plan)")
    artifact_ids: dict[str, str] = {}
    job_ids: dict[str, str] = {}
    failures: list[dict[str, str]] = []
    for candidate in plan.queued:
        try:
            answer = queue_target(candidate.path, api_base=api_base, token=token, batch_id=batch_id,
                                  recursive=plan_kwargs.get("recursive", True), **queue_kwargs)
        except RuntimeError as exc:
            candidate.action, candidate.reason = "skip", str(exc)
            failures.append({"path": candidate.path, "error": str(exc)})
            continue
        candidate.job_id = str(answer.get("job_id") or "") or None
        candidate.artifact_id = str(answer.get("artifact_id") or "") or None
        artifact_ids[candidate.path] = candidate.artifact_id or ""
        job_ids[candidate.path] = candidate.job_id or ""
    state = record_outcome(state, plan, artifact_ids=artifact_ids, job_ids=job_ids)
    state["batch_id"] = batch_id
    save_state(state_file, state)
    result.update({
        "queued_jobs": len(artifact_ids),
        "state_path": str(state_file),
        "failures": failures,
        "files": [c.as_dict() for c in plan.queued + plan.skipped],
        "queued": len([c for c in plan.queued if c.action == "queue"]),
        "skipped": len(plan.skipped) + len([c for c in plan.queued if c.action == "skip"]),
    })
    return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str] | None) -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m devsecops.intake",
        description="Feed a spool directory of binaries into the scan queue, once per distinct "
                    "binary. Dry run by default: nothing is queued until you ask.",
    )
    parser.add_argument("spool", help="directory to take binaries from")
    parser.add_argument("--patterns", default=",".join(DEFAULT_PATTERNS),
                        help="comma-separated glob patterns (default: the usual binary/archive names)")
    parser.add_argument("--executable-fallback", action="store_true", default=EXECUTABLE_FALLBACK,
                        help="also take extension-less files with the execute bit (default: on)")
    parser.add_argument("--no-executable-fallback", dest="executable_fallback", action="store_false")
    parser.add_argument("--min-size", type=int, default=DEFAULT_MIN_SIZE)
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    parser.add_argument("--limit", type=int, default=None, help="queue at most N files this pass")
    parser.add_argument("--force", action="store_true", help="re-queue content that was scanned before")
    parser.add_argument("--no-recursive", dest="recursive", action="store_false", default=True)
    parser.add_argument("--state", default=None, help=f"state file (default: <spool>/{STATE_FILENAME})")
    parser.add_argument("--batch-id", default=None, help="batch id to stamp on every queued job")
    parser.add_argument("--queue", action="store_true", help="actually queue (default: dry run)")
    parser.add_argument("--watch", action="store_true", help="keep passing over the spool")
    parser.add_argument("--interval", type=float, default=30.0, help="seconds between watch passes")
    parser.add_argument("--iterations", type=int, default=None,
                        help="stop after N passes (watch mode; useful in tests)")
    parser.add_argument("--api", default=None, help="API base URL (default: CRYPTOSCAN_API_BASE)")
    parser.add_argument("--token", default=None, help="API key or session token (default: CRYPTOSCAN_API_KEY)")
    parser.add_argument("--format", dest="fmt", default="cyclonedx", help="cyclonedx | spdx")
    parser.add_argument("--include-raw", action="store_true")
    parser.add_argument("--ingest-cbom", action="store_true")
    parser.add_argument("--system-name", default=None)
    parser.add_argument("--json", default=None, help="write the pass result(s) here ('-' for stdout)")
    parser.add_argument("--no-verify-tls", action="store_true")
    return parser.parse_args(argv)


def _credentials(args: Any) -> tuple[str | None, str | None]:
    from devsecops.dynamic_scan import api_credentials

    env_base, env_token = api_credentials()
    return args.api or env_base, args.token or env_token


def main(argv: list[str] | None = None) -> int:
    """Exit 0 = a pass completed (dry run or queued); 2 = a pass could not queue; 4 = bad input."""
    import json

    args = _parse_args(argv)
    spool = Path(args.spool).expanduser()
    if not spool.is_dir():
        print(f"not a directory: {spool}", file=sys.stderr)
        return 4

    api_base, token = _credentials(args)
    if args.queue and not (api_base and token):
        print("--queue needs --api/--token or CRYPTOSCAN_API_BASE/CRYPTOSCAN_API_KEY", file=sys.stderr)
        return 4

    # the spool is the queue's input: it must be a place this process may write the
    # state file into, and the API must be allowed to read the files it is told about
    plan_kwargs: dict[str, Any] = {
        "patterns": tuple(p.strip() for p in args.patterns.split(",") if p.strip()),
        "executable_fallback": args.executable_fallback,
        "min_size": args.min_size, "max_size": args.max_size,
        "force": args.force, "limit": args.limit, "recursive": args.recursive,
        "fmt": args.fmt, "include_raw": args.include_raw, "ingest_cbom": args.ingest_cbom,
        "system_name": args.system_name,
    }
    passes: list[dict[str, Any]] = []
    exit_code = 0
    iterations = args.iterations if args.iterations is not None else (0 if args.watch else 1)
    completed = 0
    while iterations == 0 or completed < iterations:
        completed += 1
        try:
            result = run_pass(spool, api_base=api_base, token=token, dry_run=not args.queue,
                              state_file=args.state, batch_id=args.batch_id, options=plan_kwargs)
        except RuntimeError as exc:
            print(f"intake failed: {exc}", file=sys.stderr)
            exit_code = 2
            break
        passes.append(result)
        if args.json != "-":
            _print_pass(result)
        if args.watch and (iterations == 0 or completed < iterations):
            time.sleep(max(0.0, args.interval))

    if args.json == "-":
        print(json.dumps(passes if args.watch else passes[0], indent=2))
    elif args.json:
        Path(args.json).write_text(json.dumps(passes if args.watch else passes[0], indent=2),
                                   encoding="utf-8")
    return exit_code


def _print_pass(result: dict[str, Any]) -> None:
    head = "dry run" if result["dry_run"] else f"queued {result['queued_jobs']}"
    print(f"{result['spool']}: {head} — {result['considered']} considered, "
          f"{result['queued']} to scan, {result['skipped']} skipped "
          f"(batch {result['batch_id']}, state {result['state_path']})")
    for row in result["files"]:
        if row["action"] == "queue":
            print(f"  queue  {row['path']}  [{row['reason']}]")
        elif "already scanned" in row["reason"] or "unchanged" in row["reason"] \
                or "appears twice" in row["reason"]:
            where = row.get("artifact_id") or "?"
            print(f"  skip   {row['path']}  [{row['reason']}; artifact {str(where)[:8]}]")
        else:
            print(f"  skip   {row['path']}  [{row['reason']}]")
    for note in result.get("notes") or []:
        print(f"  note: {note}")
    for failure in result.get("failures") or []:
        print(f"  FAILED {failure['path']}: {failure['error']}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover — CLI entry point
    raise SystemExit(main())
