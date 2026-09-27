# Bank readiness evidence report

Captured: `2026-09-27T17:45:00.815360+00:00`
Commit: `236cdab311b6dcc7e0044ffb4733c4875d10ab48`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=e695d8c48cffdb8c293f446f0e126dd680ac6afa405b835692fc38f77633a680 |
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
