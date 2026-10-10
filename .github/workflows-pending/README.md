# Pending workflows

Four workflow files live here: `docker-build.yml`, `db-migration.yml`,
`scanner-tests.yml` and `secret-scan.yml` (round 26, deep/22 P0#6 — the
repo had no secret scanning anywhere; `ci.yml` under `.github/workflows/`
still runs, but it has no gitleaks step). Commit
`5a32105e` ("Revert workflow file fills so the branch can be pushed")
emptied them because pushing anything under `.github/workflows/` needs a
token with the `workflow` scope, and the automation credential does not
have it — the push fails with HTTP 403. Only `ci.yml` survives with
content.

Their content lives here instead, so the branch stays pushable and the
workflows stay reviewable. GitHub ignores this directory.

## Installing them

Needs a token with the `workflow` scope (classic PAT: tick `workflow`;
fine-grained: Actions → Read and write).

```bash
# -f: the three files under .github/workflows/ exist as tracked 0-byte
# placeholders, and plain `git mv` refuses with "destination exists".
git mv -f .github/workflows-pending/docker-build.yml   .github/workflows/docker-build.yml
git mv -f .github/workflows-pending/db-migration.yml   .github/workflows/db-migration.yml
git mv -f .github/workflows-pending/scanner-tests.yml  .github/workflows/scanner-tests.yml
git mv -f .github/workflows-pending/secret-scan.yml     .github/workflows/secret-scan.yml
git rm .github/workflows-pending/README.md
git commit -m "Enable the build, schema and scanner workflows"
git push
```

## What changed from the versions in history

Restored from `39e0a3e2`, which is the last commit where they had content.

**`docker-build.yml` — rewritten, not restored.** The historical version
ran `docker build -t cryptoscan-api:ci` and stopped: no registry login,
no push, no digest. It could not feed `scripts/pin_release_images.py`,
which is what closes the `production image immutable digests` gate — and
a locally built image has a different digest from the registry manifest
anyway, so building alone can never produce that value. It now pushes to
GHCR and prints all three digests as bare 64-hex, the form
`pin_release_images.py` accepts (`DIGEST = ^[0-9a-f]{64}$`). `neo4j` is
resolved rather than built, because the digest that matters is the one
that will actually be pulled.

**`db-migration.yml` — restored with one fix.** The original used
`sqlite:///:memory:`, which selects `StaticPool` and rejects the
`pool_size` / `max_overflow` / `pool_timeout` arguments the engine
passes. It died with `Invalid argument(s) ... sent to create_engine()`
before reaching the schema. Both forms were run against this repository:
`:memory:` fails, a file-backed URL prints `ok`.

**`scanner-tests.yml` — rewritten (2026-10-08, round 9).** The verbatim
restore ran `services/scanner` only and installed a minimal dependency set.
This version runs all five scanner-heavy services (`scanner`,
`network_scanner`, `cloud_scanner`, `container_scanner`, `universal_vendor`)
as a matrix on the full `requirements.txt` + PYTHONPATH bootstrap, offline
env pinned, with path filtering and concurrency cancellation. It exists
here for the same credential reason as everything else in this directory.

**`ci.yml` — copy with one addition (2026-10-08, round 9).** The tracked
`.github/workflows/ci.yml` typechecks and builds the frontend but does not
run its tests. This copy adds `npx vitest run` to the frontend job (the
"no fabricated data" smoke contract and the per-page suites belong in the
gate). When a workflow-scope token installs the pending files, apply this
copy over `.github/workflows/ci.yml` too.

## What this does not unlock on its own

Branch protection is a separate credential (Administration scope), and
the exact `gh api` call is in `docs/PRODUCTION-ROADMAP.md` §3. The
`required_status_checks.contexts` there is `["ci"]`, which matches the
one workflow that still has content (`ci.yml`, `name: ci`), so that part
is consistent today.
