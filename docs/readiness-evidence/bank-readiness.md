# Bank readiness evidence report

Captured: `2026-09-28T08:37:17.970678+00:00`
Commit: `5c173429eae535f6e19971144c151356b2db59d3`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=02e8bdbd9d394c51e226532b697f23ed6b0058f1120df54064efdad2a2687885 |
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
