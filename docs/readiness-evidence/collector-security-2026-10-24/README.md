# Collector security increment evidence

See parent report and guide 65 for exact scope and remaining native/production
gates. Hashes identify selected source/artifact bytes, not authenticity or review.
The Ed25519 test keys were disposable and generated in memory; no private keys
are included. Linux isolation tests use actual Landlock/seccomp, not fake PASS.

Replay from repository root with approved dependencies/Python on PATH:

```bash
PYTEST_XDIST_WORKER=security_replay bash docs/readiness-evidence/collector-security-2026-10-24/run-tests.sh --junitxml=/path/outside/repo/regression.xml
python scripts/validate_host_evidence.py --acknowledge-local-synthetic --include-associations --include-foundation --junitxml /path/outside/repo/postgres.xml
python docs/readiness-evidence/collector-security-2026-10-24/run-native-witness.py
(cd frontend && npm test -- --maxWorkers=2 && npm run typecheck && npm run build)
```

Run ordinary-user Linux x86_64 isolation witnesses on a kernel with Landlock.
Do not patch a privilege check or mock unavailable native APIs to manufacture a
qualification. Native Windows tests skipping here remain unqualified. The actual
fixture CLI requires a real reviewed target/expectation plan; missing interfaces
return a failing report, never a successful empty qualification.

The standalone native witness intentionally expects the reviewed Debian 12 sandbox
OS declaration and intentionally expects unavailable systemd/DMI/TPM interfaces
to fail qualification here. It is not a portable all-host PASS generator.
