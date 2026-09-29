# Bank readiness evidence report

Captured: `2026-09-29T08:43:41.209952+00:00`
Commit: `2ba52ffddab6f4ad5a487d0b134f0f92a3cb3963`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=e93f51e0d618dc44e82955066f29e2896df824fb06e71a36615a407ebb99de6f |
| postgresql_dr | SKIP | artifact=docs/readiness-evidence/postgres-dr-drill-2026-09-29.json; sha256=f58955b1aa1b7c0ab303d917b68b575df9bf1bfd0e8ba19e6f4996df9cc44317 |
| hsm | SKIP | no external artifact supplied; this is not evidence |
| integrations | SKIP | no external artifact supplied; this is not evidence |
| compliance | PASS | artifact=docs/readiness-evidence/control-register.json; sha256=48cfa85b062fe2ebd252a8e662b49e39cf6e81676fd2b5b67d366dbe5feab717 |
| load_soak | SKIP | no external artifact supplied; this is not evidence |
| documentation | FAIL | missing=0 broken_links=89 |
| external_attestations | SKIP | no external artifact supplied; this is not evidence |

## Boundary

PASS means only that the supplied artifact contained no FAIL/SKIP statuses. Missing customer/provider evidence is never inferred from source code, mocks, documentation or local SoftHSM.

## Evidence handling

Attach provider logs, database logs, test commands, signed attestations and retention metadata next to this report. A digest is integrity evidence, not proof of origin or customer execution.
