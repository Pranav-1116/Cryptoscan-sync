# Bank readiness evidence report

Captured: `2026-09-28T04:07:10.414647+00:00`
Commit: `fff5637b44b8dd64130dad4aef4112dee3ff640e`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=eb197e3316a235b3263a33936b304428d953b0605b7855c1603f8697f22483bf |
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
