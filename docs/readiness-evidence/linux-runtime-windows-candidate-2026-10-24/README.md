# Linux runtime / Windows candidate evidence bundle

The parent report explains scope, final counts, the fixed initial failure and
unqualified interfaces. Earlier foundation bundles remain historical, not evidence
for these source bytes. `manifest.json` commits selected source and artifact
SHA-256 values, not signed releases, authentic hosts or bank acceptance.

Replay from repository root, approved locked Python dependencies installed, with
no bank resources or workflow changes:

```bash
PYTEST_XDIST_WORKER=runtime_replay bash docs/readiness-evidence/linux-runtime-windows-candidate-2026-10-24/run-tests.sh --junitxml=/path/outside/repo/regression.xml
python scripts/validate_host_evidence.py --acknowledge-local-synthetic --include-associations --include-foundation --junitxml /path/outside/repo/postgres.xml
python docs/readiness-evidence/linux-runtime-windows-candidate-2026-10-24/check-hardware-fixtures.py
(cd frontend && npm test -- --maxWorkers=2 && npm run typecheck && npm run build)
```

The PostgreSQL runner requires the approved disposable local backend dependency,
starts only its owned synthetic backend and cleans it in `finally`. SQLite is not
a substitute for that gate. Replay as an actual ordinary Linux user; do not patch
privilege checks to manufacture native successes. `native-profile.json` records
actual interface statuses/counts without exporting raw process/library/socket
contents. Windows skips here are expected **unqualified** surfaces, not passes.

`initial-*.xml` retain the first broad runs' failure counts. The report describes
the missing shared receipt-reason vocabulary discovered by those gates and the
fix; `regression.*`/`postgres.*` are the subsequent complete reruns. Counts overlap
and are not coverage percentages or performance measurements.

Archived initial-failure XML diagnostic lines have trailing whitespace normalized
for repository whitespace checks; failure messages/counts are unchanged.
