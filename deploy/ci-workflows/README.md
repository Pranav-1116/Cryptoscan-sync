# Historical staged workflow copies

**Reviewed 2026-10-22 at `698beb38`.** Configured GitHub Actions definitions
already live in [`.github/workflows/`](../../.github/workflows/).
The YAML files beside this README are retained older copies, **not activation
templates**. Do not copy them over the active workflows.

The active entrypoint discovers backend/shared suites and calls reusable scanner,
PostgreSQL 15/16 migration/parity and six-image **build-only** lanes. It also
runs frontend typecheck, Vitest, coverage instrumentation smoke, build/toolchain,
lint and production-config checks. The final aggregate is **`ci-required`**.
Scanner/migration/image workflows are reusable/manual, not the old scheduled or
path-filtered standalone proposals.

The separate manual release preflight creates explicitly unsigned/unqualified
artifacts. No current workflow publishes images or deploys a site. Actions source
files do not prove successful runs or enforced GitHub branch/environment rules.

See the [current CI contract](../../docs/dev/release-automation.md),
[complete product-build plan](../../docs/CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md)
and [current implementation status](../../docs/CURRENT-IMPLEMENTATION-STATUS.md).
Historical/proposed YAML is preserved unchanged for provenance; registry publishing,
signing and secret-scanning proposals must be reviewed before any activation.
