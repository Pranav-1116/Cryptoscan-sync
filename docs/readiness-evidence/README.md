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
