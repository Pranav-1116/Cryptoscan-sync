# Bank readiness evidence report

Captured: `2026-09-28T08:38:33.710123+00:00`
Commit: `869229502d8893d63c2a0bb2ad8409b0685029c8`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=cb12c4f06f53fb0cc045c77c61b1ee9a1df92b90e72a9403b681ac607ee4515f |
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
