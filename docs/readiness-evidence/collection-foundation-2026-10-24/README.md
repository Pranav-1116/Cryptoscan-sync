# Phase 1 + Linux increment replay

Parent baseline: `54012209732c30d6f07e24bb8bd7d2ca0cdbef92`.
Use this publication's tree and locked validation dependencies, ordinary OS user,
no customer database/credentials/network targets. Optional `pgserver` is a local
validation dependency, not a new product service/dependency.

```sh
PYTEST_XDIST_WORKER=collection_foundation \
  bash docs/readiness-evidence/collection-foundation-2026-10-24/run-tests.sh \
  --junitxml=/home/user/collection-foundation.xml
python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-associations --include-foundation \
  --junitxml /home/user/collection-foundation-pg.xml
cd frontend
npm test -- --maxWorkers=2
npm run typecheck
npm run build
```

The PostgreSQL runner owns per-case synthetic databases and deletes its own local
server/data directory. Do not redirect its fixture URL to a customer database.
The initial 18 Phase 1 checks passed before OS-release work; final artifacts cover
the combined current source. Transcripts/JUnit overlap existing host/graph tests;
counts are not independent bank-control scores. Frontend is jsdom/stubbed fetch,
not a deployed native-browser test. One Windows-native case skips on Linux.

Manifest hashes identify selected changed implementation/test/schema/lock/replay
sources and the artifacts, not every repository file or an independent signature.
The baseline plus publication patch identifies the remaining tree. Earlier reports
remain historical source commitments, not silently relabeled as these new gates.
