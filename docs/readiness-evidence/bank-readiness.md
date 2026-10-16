# Bank readiness evidence report

Captured: `2026-10-16T09:19:38.872280+00:00`
Commit: `e03f6f149b60af855ee87d47510ad0cf1728f64c`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=/home/user/CryproScan/docs/readiness-evidence/engineering-gate.json; sha256=d6af5a7922f32c914902694785a5d57348c54def4d8ac39c3a45a0f3e44efae9 |
| postgresql_dr | PASS | artifact=docs/readiness-evidence/postgres-dr-drill-2026-10-04.json; sha256=bbc19aae30c70c393692a94a937f151469a1caa4b23eb7ad581624496180d32e |
| hsm | SKIP | no external artifact supplied; this is not evidence |
| integrations | PASS | artifact=docs/readiness-evidence/burn-in-2026-10-04.json; sha256=6209c28768630338bd453650603ef873bab5c2e26bf5f4896cc6221a13c17004 |
| compliance | PASS | artifact=docs/readiness-evidence/compliance-burn-2026-10-04.md; sha256=000ba1c84c2d8fec7f155e4804d769ac8d70ea8aa420d14adb98efba6271de32 |
| load_soak | PASS | artifact=docs/readiness-evidence/load-test-2026-10-04.json; sha256=0c10b82c66e8994a606d866f8a9928b3b56bb3637b55bce68d0c4a03a59bee2a |
| documentation | PASS | checked 391 Markdown files and required readiness documents |
| operational_policy | PASS | structural findings=0; status=draft |
| readiness_closure | SKIP | no P0/P1 closure manifest supplied; external evidence is not inferred |
| external_attestations | SKIP | no external artifact supplied; this is not evidence |

## Boundary

PASS means only that the supplied artifact contained no FAIL/SKIP statuses. Missing customer/provider evidence is never inferred from source code, mocks, documentation or local SoftHSM.

## Evidence handling

Attach provider logs, database logs, test commands, signed attestations and retention metadata next to this report. A digest is integrity evidence, not proof of origin or customer execution.
