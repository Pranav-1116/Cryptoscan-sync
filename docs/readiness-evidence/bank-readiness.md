# Bank readiness evidence report

Captured: `2026-09-29T09:16:33.581252+00:00`
Commit: `df33bb7f4ec893e4f38be1612d6ec55cfcc1be18`
Verdict: **FAIL**
Recommendation: **do not approve production; remediation and/or evidence collection required**

| Category | Status | Detail |
|---|---|---|
| engineering | FAIL | artifact=docs/readiness-evidence/engineering-gate.json; sha256=a29905a83d5475378e5e974b842a36ba783a314be33a363f0b54f1431a8ea5a8 |
| postgresql_dr | SKIP | artifact=docs/readiness-evidence/postgres-dr-drill-2026-09-29.json; sha256=f58955b1aa1b7c0ab303d917b68b575df9bf1bfd0e8ba19e6f4996df9cc44317 |
| hsm | SKIP | no external artifact supplied; this is not evidence |
| integrations | SKIP | no external artifact supplied; this is not evidence |
| compliance | PASS | artifact=docs/readiness-evidence/control-register.json; sha256=48cfa85b062fe2ebd252a8e662b49e39cf6e81676fd2b5b67d366dbe5feab717 |
| load_soak | SKIP | no external artifact supplied; this is not evidence |
| documentation | PASS | checked 229 Markdown files and required readiness documents |
| operational_policy | PASS | structural findings=0; status=draft |
| readiness_closure | SKIP | no P0/P1 closure manifest supplied; external evidence is not inferred |
| external_attestations | SKIP | no external artifact supplied; this is not evidence |

## Boundary

PASS means only that the supplied artifact contained no FAIL/SKIP statuses. Missing customer/provider evidence is never inferred from source code, mocks, documentation or local SoftHSM.

## Evidence handling

Attach provider logs, database logs, test commands, signed attestations and retention metadata next to this report. A digest is integrity evidence, not proof of origin or customer execution.
