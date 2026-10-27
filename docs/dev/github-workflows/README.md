# Historical GitHub workflow copies

These YAML files are older documentation/staging copies, **not** the configured
Actions source. Do not copy them over [`.github/workflows/`](../../../.github/workflows/).

As reviewed 2026-10-22 at `698beb38`, active CI discovers backend/shared and
scanner suites, tests PostgreSQL 15/16 migration/parity, runs frontend tests/build,
and performs six non-publishing image builds. Its final aggregate is
**`ci-required`**. The manual release preflight is unsigned and is not site
packaging, registry publication or deployment.

Read the [current CI contract](../release-automation.md),
[product-build plan](../../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) and
[current implementation status](../../CURRENT-IMPLEMENTATION-STATUS.md).
The retained historical YAML is not fresh evidence of passing workflow runs.
