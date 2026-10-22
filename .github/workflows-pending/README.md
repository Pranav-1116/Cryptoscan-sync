# Historical workflow proposals — not the active CI source

As of the 2026-10-22 CI/CD implementation, the configured definitions are in
`.github/workflows/`:

- `ci.yml`: PR/main/requested integration-branch/manual entrypoint, disjoint discovery of every service/shared suite,
  frontend typecheck/Vitest/build/toolchain, lint, production config guard,
  and the fail-closed `ci-required` aggregate. It calls all three lanes below.
- `scanner-tests.yml`: reusable/manual offline scanner matrix, six suites in five
  scanner families with JUnit and no path-filtered PR bypass.
- `db-migration.yml`: reusable/manual PostgreSQL 15 **shipping** and 16 compatibility
  parity, plus no-skip live Alembic migration proof against disposable databases.
- `docker-build.yml`: reusable/manual six standard image builds, with nginx's own
  context, read-only permissions, and **no publishing or deployment**. The separate
  worker-runtime image requires operator-reviewed base digests and is not built here.

These definitions in a checkout are not evidence that GitHub executed them.
Workflow-file push permissions, successful PR/main check results, and required
branch-protection/ruleset contexts must be verified in GitHub. None of these
jobs publishes release images. The separate manual `release-preflight.yml`
only renders an unsigned, explicitly unqualified handoff from supplied digests;
there is no automatic registry publication or site deployment.

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
  test. The reusable database lane applies Alembic against PostgreSQL instead.
- The worker-runtime Dockerfile is not included in the six-image build: it needs
  two reviewed `image@sha256:` inputs and a separate operator runtime review.

See `docs/dev/release-automation.md` for the current contract, local validation
commands, required checks and the remaining evidence boundary. The other older
copies under `docs/dev/github-workflows/` are historical too.
