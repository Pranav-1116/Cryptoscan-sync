# Static source-parser isolation

Implemented locally on 2026-10-17. **Real Docker execution and target-platform
security qualification are NOT yet evidenced.** Unit tests cover the command,
protocol, runtime guards and failure paths; they are not a container escape test.

## Policy and scope

Both source scan entry points (`PipelineRunner._scan` and `stage_scan.execute`)
call `worker.core.static_scan_isolation.scan_static`.

| Environment | Default | May select inline? |
| --- | --- | --- |
| development / test | `inline` | Yes; reported as `isolated: false` |
| production | `container` | No; explicitly selecting inline is rejected |

Settings are read through WorkerSettings, including its `.env` configuration.
Production worker startup requires an immutable `CRYPTOSCAN_SCANNER_IMAGE`
(`repository@sha256:` followed by 64 lowercase hexadecimal characters), a valid
budget, and container mode. Per-scan execution additionally requires a POSIX
worker, Docker CLI, reachable approved daemon and a **locally available** image.
The launcher uses `--pull=never`: it never builds, downloads, publishes, deploys
or silently falls back to in-process scanning. Missing prerequisites fail the job.
A tag such as `scanner:latest`, including a versioned tag, is insufficient.

This boundary covers the **entire Scanner source-parser invocation**, including
small/single-file scans, source discovery, constant indexing, configuration,
material and cascade analysis. It does **not** isolate admission, Git clone,
parent language discovery, optional container/image, network/TLS, cloud or OT
collectors, JSON-result validation, evidence loading, normalization or reporting.
Those stages remain in the credentialed worker and need separate qualification.
The authorized source itself can contain sensitive files; the boundary does not
make such source non-sensitive or resolve historical stored-snippet disposition.

## Requested container policy

- Fixed non-root UID/GID `10001:10001`, no capabilities, no-new-privileges.
- Separate default PID/mount namespace; `--network=none`. No worker environment,
  database/Redis descriptors, Docker socket, host configuration or credentials
  are mounted/passed into the parser. The host-side Docker CLI still runs with
  the dispatcher's ordinary environment and daemon access.
- Root filesystem and `/scan` source bind read-only; recursive bind submounts
  disabled. Source paths containing mount-option delimiters are refused.
- A checkout's `.git` directory is hidden beneath an empty unreadable read-only
  tmpfs, since clone configuration may contain authentication in the origin URL.
  Linked/file-form `.git` metadata is refused. The worker reattaches known
  target commit/branch/location after parsing; unavailable author/time/message
  metadata stays absent, not fabricated. No URL/branch/credential is sent in the
  parser request.
- A container-local metadata walk rejects sockets, devices and FIFOs before
  detectors and never follows source symlinks. Staging must be owned exclusively
  by the dispatcher and remain quiescent during parsing; this is not a defence
  against a privileged host actor racing changes into that shared storage.
- 1 GiB memory, memory+swap also 1 GiB, one CPU, 64 PIDs, 256 open descriptors,
  no core dumps; a 64 MiB `noexec,nosuid,nodev` scratch tmpfs. Supplemental scanner
  child rlimits apply too. These fixed limits are not an estate-scale guarantee.
- Whole-parser deadline `CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S` defaults to 600 seconds,
  finite range 1–3600. The adapter has an independent watchdog, not the per-file
  SIGALRM timer. Parent CLI exchange allows an additional five seconds, and
  failure cleanup has bounded daemon calls (10 seconds each).
- JSON request bounded at 64 KiB, stdout at 32 MiB, diagnostic stderr at 256 KiB.
  Nonblocking I/O bounds a blocked stdin as well as output; no pickle, arbitrary
  function, path, command or environment protocol. Invalid/incomplete/failed
  responses and mismatched scan IDs are refused. Error messages do not repeat
  source text or runtime stderr.
- Child checks require non-root identity, dropped effective capabilities,
  no-new-privileges, a runtime seccomp filter, read-only root/input, hidden Git
  metadata and only loopback network interfaces. These are child-observed
  checks, **not independently signed attestation** or proof of every syscall
  denied by the staged custom seccomp policy. The adapter does not replace an
  already-active Docker filter with the process-specific scanner filter.

A random read-only marker is temporarily created in the staged checkout. The
child verifies it at `/scan` before importing/running Scanner. This rejects the
common container-worker error where the daemon binds a different directory with
the same absolute path. The marker carries no application credential and is
removed on normal success/failure. The worker must own/write its staging root;
this helper is for admitted staged workspaces, not arbitrary immutable inputs.

On failure/cancellation the launcher kills the CLI process group and explicitly
removes the uniquely named daemon-side container. A successful empty exact-name
listing may confirm that `--rm` already removed it; a daemon connection error
cannot. Unconfirmed cleanup fails visibly and requires an operator check.
Abrupt worker/host death can bypass Python cleanup: the adapter watchdog and
`--rm` reduce that risk but daemon-loss/orphan recovery still needs qualification.

Execution policy/image/checks are attached to the result and persisted in scan
statistics as `static_scan_execution`. An `isolated: true` entry describes the
configured/child-observed parser boundary, **not** independently audited host
isolation, complete scan coverage or production approval. Parser-error counts
and other collector failures retain their existing independent meanings.

## Deployment prerequisites — deliberate fail-closed change

New environment variables (also listed in `.env*.example`):

```text
CRYPTOSCAN_STATIC_SCAN_MODE=container
CRYPTOSCAN_SCANNER_IMAGE=<operator-approved immutable repository@sha256:digest>
CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S=600
```

The placeholder is deliberately not a usable image. Provision and inspect the
approved digest before starting production source jobs. The scanner Dockerfile
contains `scanner.isolated`; its system site-packages `.pth` registration works
with `python -I -m scanner.isolated` without trusting checkout/PYTHONPATH imports.
Existing tag-only non-publishing CI builds do not establish a registry digest.

**The stock Compose stack is NOT a provisioned isolated scanner deployment.**
It passes the settings but deliberately does not add a Docker socket mount or
privileged container. The current worker image does not bundle a Docker CLI,
and the production worker uses a private tmpfs workspace which another Docker
daemon cannot see. An operator must provide an appropriately reviewed launcher
image/runtime and staging topology:

1. Use a Linux Docker daemon/CLI supporting `--mount bind-recursive=disabled`
   (Docker Engine 25+), cgroup memory/CPU/PID controls and seccomp.
2. Keep the approved scanner digest preloaded. Do not weaken to mutable tags or
   automatic pulls to work around missing provisioning.
3. Share only the admitted staging storage with the daemon at the **same
   canonical absolute path** as the worker. Override the stock private tmpfs
   workspace and `WORKSPACE_BASE_PATH`/authorized source roots accordingly.
   A different host checkout with a coincidentally equal path fails the marker
   check. Every admitted source directory/file must be readable by container
   UID 10001; do not broaden permissions on worker secrets to accomplish this.
4. Restrict/segregate daemon access. An unrestricted rootful Docker socket gives
   the dispatcher host-equivalent authority. Do not mount the ordinary host
   socket into the stock worker merely to get past the prerequisite, and never
   expose it inside the parser. Rootless/user-namespace setups require their own
   storage-permission and resource-control qualification.
5. Retain positive and negative runtime evidence for supported architectures,
   timeout/OOM/PID exhaustion, denied networking/writes/host access, credentials,
   source-path binding, cancellation, daemon outages/restarts and orphan cleanup.
   A unit mock and a child status report alone cannot close this gate.

## Tests and qualification command

With the repository's dependencies and full service/shared PYTHONPATH installed:

```bash
ENVIRONMENT=test python -m pytest -q -p no:xdist \
  services/scanner/tests/unit/test_isolated_adapter.py \
  services/worker/tests/unit/test_static_scan_isolation.py \
  services/worker/tests/unit/test_production_settings.py
```

Those tests include real harmless subprocesses for output/request caps, blocked
stdin, wall-clock watchdog/CLI deadlines, process-group termination and inherited
file-descriptor closure. Docker calls and runtime guard inputs are mocked in
unit tests. The focused scanner-safety CI lane runs these contracts too.

The separate **live** test invokes the real Docker-backed launcher and scans a
small MD5 fixture with child runtime checks. It is a smoke qualification, not a
complete hostile-repository or kernel-escape assessment. On a properly
provisioned host, set the genuine image environment variable, then run:

```bash
: "${CRYPTOSCAN_SCANNER_IMAGE:?set an approved preloaded immutable image reference}"
ENVIRONMENT=test python -m pytest -q -p no:xdist -m live \
  services/worker/tests/integration/test_static_parser_container_live.py \
  --junitxml=static-parser-live.xml
python scripts/check_junit.py static-parser-live.xml
```

Missing Docker/image causes a visible skip; the proof checker rejects skipped or
empty proof. This live test has **not run successfully in the current sandbox**
(Docker unavailable). No image was built/published and no runtime was deployed.

## Local implementation evidence

- Focused adapter/launcher/production-configuration suite: **79 passed** (77 new
  non-live cases and two existing production-setting cases).
- Seven-suite regression: **2,475 passed, 29 skipped, 6 live deselected**, 116.00s;
  worker, scanner, devsecops, database, container scanner, shared config and
  shared models. This is not the full 54-suite backend gate. Existing
  Pydantic/Alembic and blocked-network warnings remain visible.
- Fresh real three-scan SQLite chain: execution policy read from each persisted
  Scan row, **1 passed / 1 PostgreSQL skipped / 23 deselected**, 3.99s. No
  PostgreSQL parity credit for the skip.
- Explicit Docker qualification attempt: **1 skipped**, rejected by the JUnit
  proof checker. No real container execution credit.
- Repo-wide ruff, dependency consistency (`pip check`), workflow YAML/shell
  checks pass; Compose YAML parses, but actual Compose validation/build/runtime
  is unavailable. Frontend and GitHub execution were not rerun.

Local log/XML files: `/home/user/scanner-boundary-final.{log,xml}` and
`/home/user/static-policy-persistence.{log,xml}`. These are local engineering
artifacts, not signed external evidence or reproducible release provenance.
