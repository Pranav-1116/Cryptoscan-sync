# Historical workflow proposals — not the active CI source

As of the 2026-10-17 release-automation work, the executable definitions are in
`.github/workflows/`:

- `ci.yml`: automatic discovery of every service/shared suite, frontend
  typecheck + Vitest + build, lint, production config guard, PostgreSQL parity,
  and a fail-closed aggregate check named `ci`.
- `scanner-tests.yml`: focused timeout/seccomp/hostile-archive regressions.
- `db-migration.yml`: real Alembic chain/schema tests on SQLite and PostgreSQL;
  required migration proof fails if the tests are skipped.
- `docker-build.yml`: all six checked-in Dockerfiles plus Compose validation,
  with read-only permissions and **no publishing or deployment**.

These are local implementation changes, not evidence that GitHub accepted or
executed them. Workflow installation, check results and branch-protection
configuration still need verification through the repository's GitHub connection.
Previous attempts were permission-blocked; no new successful installation is
claimed here.

## Why these files remain

The YAML files beside this README are retained proposals/history, not templates
that should be copied over the active workflows. In particular:

- The proposed release-image workflow publishes to GHCR. The active image
  workflow intentionally only builds. Registry publication, immutable registry
  digests, signing/provenance and deployment remain separate release work that
  must be explicitly reviewed and authorized.
- `secret-scan.yml` is still a proposal here, not an enabled secret-scanning
  workflow. Do not describe secret scanning as installed based on its presence.
- The older database proposal initializes models; that alone is not a migration
  test. The active database workflow applies the Alembic chain instead.

See `docs/dev/release-automation.md` for the current contract, local validation
commands, required checks and the remaining evidence boundary. The other older
copies under `docs/dev/github-workflows/` are historical too.
