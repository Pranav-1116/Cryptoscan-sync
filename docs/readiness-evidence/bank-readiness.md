# Bank readiness evidence report

Captured: `2026-09-29T09:17:42.090755+00:00`
Commit: `7cd93ad25cfd31a3932069019d346b229aaa39a4`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=8a449ce46da1e76072efada5296efba4029338e9b5a8f197fc16d044b5aec29a |
| postgresql_dr | SKIP | artifact=docs/readiness-evidence/postgres-dr-drill-2026-09-29.json; sha256=f58955b1aa1b7c0ab303d917b68b575df9bf1bfd0e8ba19e6f4996df9cc44317 |
| hsm | SKIP | no external artifact supplied; this is not evidence |
| integrations | SKIP | no external artifact supplied; this is not evidence |
| compliance | PASS | artifact=docs/readiness-evidence/control-register.json; sha256=5b0dee3f183cdb74dff67d2e0628811aa01c8d0f1b86eaf64c644bcaf3f7783f |
| load_soak | SKIP | no external artifact supplied; this is not evidence |
| documentation | PASS | checked 229 Markdown files and required readiness documents |
| operational_policy | PASS | structural findings=0; status=draft |
| readiness_closure | SKIP | no P0/P1 closure manifest supplied; external evidence is not inferred |
| external_attestations | SKIP | no external artifact supplied; this is not evidence |

## Boundary

PASS means only that the supplied artifact contained no FAIL/SKIP statuses. Missing customer/provider evidence is never inferred from source code, mocks, documentation or local SoftHSM.

## Evidence handling

Attach provider logs, database logs, test commands, signed attestations and retention metadata next to this report. A digest is integrity evidence, not proof of origin or customer execution.
