# Frontend toolchain hardening — R87

Dated local qualification: **2026-10-18**. This is a development-toolchain
change, not deployment approval or browser/security certification.

> Publication boundary: at the user's request, active `.github/workflows/`
> changes are excluded from this push because the GitHub connection lacks
> Workflows permission. The proposed CI gates and workflow-contract test results
> below describe the locally qualified configuration, not the published active
> workflows. Workflow-contract tests requiring those changes will need the CI
> updates restored; this CI-excluded snapshot is not claimed to pass that lane.
> The excluded workflow diff is retained locally at
> `/home/user/cryproscan-r87-ci-workflows.patch`.

## Coordinated upgrade, unchanged application dependencies

| Tool | R86 resolved version | R87 exact pin |
|---|---|---|
| Vite | 5.4.21 | 8.3.4 |
| Vitest | 2.1.9 | 5.0.5 |
| V8 coverage provider | 2.1.9 | 5.0.5 |
| React Vite plugin | 4.7.0 | 6.1.2 |

Vitest and its coverage provider must match. The supported engine declaration
is Node `^22.12.0 || ^24.0.0 || >=26.0.0`, npm `>=10`; qualification ran on
**Node 22.22.3 / npm 10.9.8**, not every declared Node version. `.npmrc` enables
`engine-strict` and exact saving. A clean normal dependency resolution was used,
not `npm audit fix --force` or `--legacy-peer-deps`.

The clean resolution initially floated three motion packages; their original
lock records were restored and validated with `npm ci`. All **15 production
package records** match the pre-upgrade lock, including versions, resolutions
and integrity metadata. No production package was added or removed; application
runtime dependency ranges remain unchanged. The development graph necessarily
changes with the coordinated upgrade.

## Compatibility changes

- Vite 8 uses Rolldown. Replace the rejected Rollup object `manualChunks` with
  `build.rolldownOptions.output.codeSplitting.groups`, preserving the React,
  motion and icon vendor groups and automatic lazy-page splitting. Priorities
  put the React group first; package-boundary matchers cover Unix and Windows.
- Explicitly retain Vite 5's production compilation targets: `es2020`, `edge88`,
  `firefox78`, `chrome87`, `safari14`. Vite 8 otherwise raises the default browser
  baseline. Compiler targets are not browser runtime evidence or feature
  polyfills; no positive legacy-browser certification is claimed.
- The stricter Lightning CSS production parser exposed malformed trailing
  stylesheet fragments and duplicated pipeline media rules. Remove the corrupt
  duplicate tail, retain the earlier valid rules, and keep strict parsing and
  minification enabled rather than suppressing the failure.
- Keep development loopback defaults, named Host-header validation and the
  same-origin `/api` proxy. An empty advisory report is not permission to expose
  a development server publicly or use it as production hosting.

## Repeatable installs and advisory gates

Run from `frontend/` with a supported engine:

```sh
npm ci --no-audit --no-fund
npm audit --include=dev --audit-level=low
npm run test:toolchain
npm run typecheck
npm test
npm run test:coverage -- src/lib/api.test.ts
npm run test:coverage
npm run build
```

`npm audit --omit=dev` is a useful separate runtime-only view, **not** a
substitute for the all-dependency gate. CI explicitly includes development
packages and fails on low-or-higher advisories; registry outages also fail the
command rather than being treated as a clean audit. CI runs the existing full
UI suite and a focused V8 provider smoke; the latter is not a coverage threshold
or a second set of new tests. The optional full coverage command above is last
so its reports replace the focused smoke output under `frontend/coverage/`.

The frontend Docker build now requires `package.json`, `package-lock.json` and
`.npmrc`, then runs `npm ci`; it cannot silently install without the lock. This
freezes the npm graph, not the floating Node base image or every build input.
Docker/native-musl/image runtime qualification remains separate.

The five standalone Node contracts run outside the jsdom-only Vitest setup:
engine/pin/install policy; loopback/proxy defaults; browser targets and vendor
matchers; whole-stylesheet strict parsing; and real local HTTP host/file checks.
The HTTP test binds an ephemeral socket, serves an approved Host, rejects an
untrusted Host, and denies a uniquely named synthetic `.env` probe. It uses
`node:http` to send Host verbatim, cleans up its server/file, and contacts no
backend or external receiver. Tests do not certify a production ingress.

## Observed local evidence

- Fresh frozen install, TypeScript check and production bundle: **passed**;
  final target-preserving build **1.14s**, three vendor groups and lazy routes
  emitted. Compiled output is not proof of rendered browser behavior.
- Existing Vitest suite: **344 tests / 36 files passed**, 69.49s. Full V8
  coverage also ran all **344 / 36** successfully in the final repeat (**84.78s**);
  API provider smoke **19 / 1**.
- Five standalone toolchain/HTTP contracts: **5 passed**.
- DevSecOps suite including the new CI advisory/coverage contract: **572 passed**,
  8.69s. Ruff (`services scripts shared`) and `pip check`: **passed**. This slice
  did not rerun the entire backend/all discovered suites; R86's broader result
  remains separately dated evidence.
- Fresh all-dependency npm audit: **0 advisories**, all severities zero;
  production-only audit: **0**. This supersedes R86's **8 development-toolchain
  advisories** for this lock and registry observation, not the historical run.

V8 coverage is measured, not a completeness claim: the final complete run
reported **49.8% statements / 38.51% branches / 36.53% functions / 54.32% lines**.
There is no new percentage threshold; the focused smoke naturally measures much
less. Existing React `act` warnings remain in the test output. Neither passing
tests nor a zero npm audit covers unknown vulnerabilities, Node/npm binaries,
OS/nginx images, all browser versions, or production security.

Local evidence logs: `/home/user/toolchain-final.log`,
`/home/user/toolchain-{contracts,typecheck,build}-qualified.log`,
`/home/user/toolchain-coverage-final.log`,
`/home/user/toolchain-coverage-smoke-qualified.log`,
`/home/user/toolchain-ci-contracts-qualified.{log,xml}`,
`/home/user/toolchain-runtime-graph-qualified.log` and
`/home/user/toolchain-{audit,runtime-audit}-final.json`. Interrupted/install-racing
attempts are not qualification; successful fresh runs supersede them.

No observed GitHub workflow run, Docker build, image publication, deployment,
notification send, scheduler enablement, customer migration or source-branch
reconciliation is claimed. Work remains on the fixed session branch. Bank FAIL,
NO_FIELD_DATA and independent infrastructure/provider/readiness gaps are
unchanged.
