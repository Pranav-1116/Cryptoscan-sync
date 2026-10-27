# Replay the host-first evidence slice

Use the repository root and reviewed Python3.11 environment installed from
`requirements.lock.txt`. The PostgreSQL witness additionally needs the optional
`pgserver` validation dependency. No new production dependency/service or CI
workflow is required. Only authorized disposable local fixtures are used.

```bash
# Approved Python interpreter on PATH; output is outside the checkout.
PYTEST_XDIST_WORKER=host_release \
  bash docs/readiness-evidence/host-collection-2026-10-24/run-tests.sh \
  --junitxml=/external/host-release.xml

python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --junitxml /external/host-postgres.xml

npm test --prefix frontend
npm run typecheck --prefix frontend
npm run build --prefix frontend
```

The first selection includes all CBOM, evidence, inventory and shared-model tests,
plus selected API tenant/RBAC/CBOM/assurance/limiter and database evidence/audit
contracts. It is not the entire repository, all workflows or a bank deployment.
The native Windows case deliberately skips on Linux. The seven Windows path
contract cases are portable string tests, not Windows execution qualification.

The PostgreSQL harness creates owned temporary storage under the current user's
home, starts an unprivileged local PostgreSQL through `pgserver`, uses existing
fixtures that create/drop a fresh synthetic database per case, and cleans its
own server/storage in `finally`. It accepts no customer database URL and does
not provision or contact any customer system. Model-table creation in these
cases is not a new migration-chain/schema-parity qualification.

The fixture data covers certificate metadata, declared TLS settings,
package/library presence and negative receipts, not a complete bank estate.
See the [acceptance ledger](../../bank-environment/60-host-first-product-acceptance.md)
for the remaining Linux/Windows/container/HSM/TLS/KMS/supplier tests.

`manifest.json` records final source/artifact hashes. JUnit files and transcripts
record the exact selected runs. Timings are descriptive test-run durations only:
not scan throughput, p95/p99, memory/capacity or paired performance qualification.
