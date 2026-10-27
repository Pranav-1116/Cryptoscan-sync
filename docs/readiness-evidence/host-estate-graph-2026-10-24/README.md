# Host-to-estate association execution artifacts

Run from the repository root at the publication containing this directory.
The parent baseline is `455cb5e7d1fc18d3753472586de0fc77e0eeaf2b`.
[Report](../host-estate-graph-2026-10-24.md) ·
[Operator/API guide](../../bank-environment/61-host-to-six-bom-associations.md).

The scripts require the repository's locked validation dependencies. The optional
`pgserver` witness dependency is for validation, not a new product dependency.
Use an ordinary user; no customer URL, network collection or privileged runtime.
The PostgreSQL runner asserts an explicitly owned disposable local database,
creates per-case synthetic databases and cleans up its own server/data directory.
Do not aim the test fixture at a customer database.

```sh
# Use the approved Python/venv on PATH. One native Windows test skips on Linux.
PYTEST_XDIST_WORKER=host_graph_final \
  bash docs/readiness-evidence/host-estate-graph-2026-10-24/run-tests.sh \
  --junitxml=/home/user/host-graph-final.xml

# Explicitly acknowledged disposable PostgreSQL; baseline host + graph contracts.
python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-associations --junitxml /home/user/host-graph-pg-final.xml

cd frontend
npm test -- --maxWorkers=2
npm run typecheck
npm run build
```

`manifest.json` commits selected changed product/test/replay sources, important
existing host/SBOM/SSH/database fixtures and the lockfiles; it does not purport to
hash every repository file. The baseline commit plus publication patch identifies
the remaining tree. Artifacts include raw pytest/JUnit results, ANSI-stripped
frontend transcript, Ruff/pip/whitespace checks and observed owned-resource
cleanup. Report counts overlap existing tests; do not add them into a distinct
bank-control score. Elapsed test times are not performance qualification.

Frontend tests are jsdom with stubbed fetch, not a native browser running against
a deployed bank. Source graph tests use real sessions/HTTP/SQL, retained original
synthetic SBOM bytes and controlled SSH producer observations; acquisition is
stubbed, not a successful real SSH/TLS/HSM/KMS service deployment. All graph edges
remain metadata association/containment, never verified operational use.

Hashes are local reproducibility commitments, not independent signatures, WORM
attestation or host identity. Earlier `host-collection-2026-10-24` artifacts remain
historical evidence for their original source and are not silently upgraded to
this increment. Preliminary runs were repeated after the final labeling/proposer
fix; only the final current-source backend runs are published here.
