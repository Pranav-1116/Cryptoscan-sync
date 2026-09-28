# Bank readiness evidence report

Captured: `2026-09-28T04:00:50.702437+00:00`
Commit: `2e8e352d633fe7fde478899ad246a91a5c3a0b33`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=4b9ed98452221eb311f1dbf837653d4cab7da847b0e30ce7cb4241458dfe52db |
| postgresql_dr | SKIP | no external artifact supplied; this is not evidence |
| hsm | SKIP | no external artifact supplied; this is not evidence |
| integrations | SKIP | no external artifact supplied; this is not evidence |
| compliance | SKIP | no external artifact supplied; this is not evidence |
| load_soak | SKIP | no external artifact supplied; this is not evidence |
| documentation | PASS | checked 225 Markdown files and required readiness documents |
| external_attestations | SKIP | no external artifact supplied; this is not evidence |

## Boundary

PASS means only that the supplied artifact contained no FAIL/SKIP statuses. Missing customer/provider evidence is never inferred from source code, mocks, documentation or local SoftHSM.

## Evidence handling

Attach provider logs, database logs, test commands, signed attestations and retention metadata next to this report. A digest is integrity evidence, not proof of origin or customer execution.
