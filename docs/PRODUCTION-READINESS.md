# Historical production-readiness notes

The current production decision no longer lives in this historical document.
Use the root [`../PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) and run
`scripts/bank_readiness.py`, which emits the timestamped unified
`docs/readiness-evidence/bank-readiness.{json,md}` report.

The older percentage tables and local/synthetic evidence below are retained for
traceability only. They must not be used as a production approval, customer
certification, DR/HSM qualification or bank attestation. In particular:

- `docs/accuracy/BANK-READINESS.md` is detector and synthetic-estate evidence;
- `docs/accuracy/DUBAI-BANKS-E2E.md` did not access a Dubai bank;
- safe SKIP results from integration, HSM, DR or load harnesses are not PASS;
- repository controls do not establish SOC 2, ISO 27001, FIPS, residency, SLA
  or customer procurement acceptance.

When historical run details are needed, inspect the file history or the
adjacent scoped runbooks. New evidence belongs under `docs/readiness-evidence/`
and is collected by the root gate.
