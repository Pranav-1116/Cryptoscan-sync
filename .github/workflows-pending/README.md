# Pending workflows

Three files under `.github/workflows/` are **0 bytes** on `main`:
`docker-build.yml`, `db-migration.yml` and `scanner-tests.yml`. Commit
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

**`scanner-tests.yml` — restored verbatim.**

## What this does not unlock on its own

Branch protection is a separate credential (Administration scope), and
the exact `gh api` call is in `docs/PRODUCTION-ROADMAP.md` §3. The
`required_status_checks.contexts` there is `["ci"]`, which matches the
one workflow that still has content (`ci.yml`, `name: ci`), so that part
is consistent today.
