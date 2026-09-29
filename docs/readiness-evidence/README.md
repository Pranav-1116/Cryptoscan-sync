# Readiness evidence directory

This directory is the default output location for the current bank-readiness
gate. Artifacts must be retained with their commands, UTC timestamps, commit,
environment, provider/database logs and operator/customer attestation where
applicable.

```bash
python scripts/bank_readiness.py --run-engineering \
  --out docs/readiness-evidence/bank-readiness.json
```

The JSON and Markdown reports are generated outputs. A generated report with a
`FAIL` or `SKIP` category is an honest incomplete result; do not edit its
verdict by hand. Use the root `PRODUCTION-READINESS.md` for interpretation.
External artifacts remain outside the repository when they contain sensitive
customer/provider information; pass their controlled paths to the gate.

## P0/P1 closure envelope

The documented enterprise-bank gaps have an explicit closure contract in
`config/readiness-closure-policy.json`. The gate requires one current,
release-bound, reviewed artifact for every required kind across P0-1 through
P1-5; it rejects missing files, hash mismatches, stale evidence, nested
`FAIL`/`SKIP` results, missing limitations, and same-person operation/review.
It does not turn a repository file into customer, provider, auditor, legal, or
regulatory evidence.

Use a controlled manifest supplied by the deployment/evidence owner:

```bash
python scripts/readiness_closure_gate.py \
  --manifest /secure/evidence/closure-manifest.json \
  --expected-commit "$(git rev-parse HEAD)" \
  --out /secure/evidence/closure-report.json \
  --strict
```

`closure-manifest.example.json` is a shape example only. Its placeholders must
never be copied into an approval package. For a release approval, also pass
`--require-readiness-closure --readiness-closure-manifest ...` to
`scripts/release_check.py`; pre-release checks leave this external requirement
opt-in so local development does not fabricate approval evidence.
