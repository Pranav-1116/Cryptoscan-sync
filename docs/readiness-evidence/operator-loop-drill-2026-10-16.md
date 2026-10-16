# Operator-loop drill — 2026-10-16T18:50:04+00:00

Verdict: **PASS** (121 passed / 0 failed of 121 checks, 2 pass(es))

- API: `http://127.0.0.1:8010` (inline pipeline, no Redis)
- Estate: `/tmp/cryptoscan-sources/operator-loop` — 3 authorized systems
- Repository: `c6db4571` on `arena/bb4b80dd-cryproscan`
- Command: `scripts/operator_loop_drill.py --passes 2 --out docs/readiness-evidence/operator-loop-drill-2026-10-16.json`

## Checks

| Status | Check | Detail |
|---|---|---|
| PASS | `system.register.payments-api` | POST /systems -> 200; id=39b77484-de4f-4d47-9509-8a52ddd988a3; owners m.iyer@bank.example / s.duarte@bank.example |
| PASS | `system.register.mainframe-icsf` | POST /systems -> 200; id=2f3a436e-3eec-4413-ae33-3c8f94339aa3; owners r.okonkwo@bank.example / s.duarte@bank.example |
| PASS | `system.register.claims-ibmi` | POST /systems -> 200; id=5807c364-4247-4a94-9030-20ad87a1b647; owners a.lindqvist@bank.example / s.duarte@bank.example |
| PASS | `scan.accept.p1.payments` | POST /systems/39b77484/scan -> 200; job=2c192714-fa74-4bc1-8b38-d30dae9b51b6 |
| PASS | `scan.completed.p1.payments` | job 2c192714 -> COMPLETED; scan_id=c361ed3b-5e26-4c86-a483-ae1fd3ea53b8 |
| PASS | `scan.accept.p1.mainframe` | POST /systems/2f3a436e/scan -> 200; job=f5a136b7-f5f4-4c05-8a04-d4d96314c696 |
| PASS | `scan.completed.p1.mainframe` | job f5a136b7 -> COMPLETED; scan_id=0cf75a30-f71c-4dbc-b88f-831021581d9e |
| PASS | `scan.accept.p1.ibmi` | POST /systems/5807c364/scan -> 200; job=cf8f2913-9ab5-412d-90cb-957926f55740 |
| PASS | `scan.completed.p1.ibmi` | job cf8f2913 -> COMPLETED; scan_id=cfc0771a-729a-4256-906d-e351925f391f |
| PASS | `evidence.verify.p1.payments` | GET /scans/c361ed3b/verify -> 200; PASS |
| PASS | `evidence.mainframe.p1` | mainframe scan produced 7 evidence record(s) — the Natural/ICSF parsers participate in the loop |
| PASS | `evidence.verify.p1.mainframe` | GET /scans/0cf75a30/verify -> 200; PASS |
| PASS | `evidence.ibmi.p1` | ibmi scan produced 11 evidence record(s) — the RPG IV/ILE C/GSKit parsers participate in the loop |
| PASS | `evidence.verify.p1.ibmi` | GET /scans/cfc0771a/verify -> 200; PASS |
| PASS | `findings.p1` | payments-api scan produced 20 finding(s): ['3DES', 'AES', 'MD5', 'RC4', 'RSA', 'SHA-1', 'SHA2', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'] |
| PASS | `evidence.paths_target_relative.p1` | all 20 evidence record(s) name their file in the TARGET's coordinates (0 carried a worker staging path) — evidence identity has to survive a rescan or verification invents regressions |
| PASS | `target.finding.p1` | driving condition: 3DES at src/main/java/com/bank/payments/PinBlockService.java:16 (evidence 7519d868, 2 record(s) at that site) |
| PASS | `baseline.approve.p1` | POST /baselines/approve -> 200; baseline=f5534e15-4b8d-4eed-a6fd-adc5c7e8c0f4; approved_by=admin |
| PASS | `task.create.p1.verified` | POST /remediation/tasks -> 200; task=28471aa2-9761-4f8e-af0f-210410aa52ed; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p1.verified` | POST /tasks/28471aa2/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p1.fix` | POST /systems/39b77484/scan -> 200; job=6ff3327a-681d-4e7e-8cff-e40433b9838e |
| PASS | `scan.completed.p1.fix` | job 6ff3327a -> COMPLETED; scan_id=cef79e8f-2212-4557-a329-1326780def2c |
| PASS | `verification.verified.p1.verified` | complete -> 200; result=VERIFIED (expected VERIFIED); task=VERIFIED; None |
| PASS | `condition.gone.p1` | PinBlockService.java holds 0 weak-cipher record(s) after the fix (the 3DES cipher string in tls.conf is a different condition and is not what this task names) |
| PASS | `scan.accept.p1.reintroduced` | POST /systems/39b77484/scan -> 200; job=944d6e1d-2d93-44a7-a0b2-0487fcfab2b2 |
| PASS | `scan.completed.p1.reintroduced` | job 944d6e1d -> COMPLETED; scan_id=3772cb82-9d4a-4509-b634-17cf22b55550 |
| PASS | `reintroduction.detected.p1` | the reintroduced 3DES PIN block is observed again at the same site (1 record(s)) — a verified fix is not a permanent state |
| PASS | `verification.reintroduced.p1` | re-verify -> 200; result=FAILED (expected one of ['FAILED', 'PARTIAL', 'REGRESSION']); task=FAILED |
| PASS | `scan.accept.p1.untouched` | POST /systems/39b77484/scan -> 200; job=be22bbf7-2087-4a85-82ea-1afa692863ab |
| PASS | `scan.completed.p1.untouched` | job be22bbf7 -> COMPLETED; scan_id=d7d831e6-67d6-4943-8dd7-413167c5a201 |
| PASS | `task.create.p1.failed` | POST /remediation/tasks -> 200; task=368b96d3-3991-467f-b022-2fb73468fd40; rule=replace-md5; status=PROPOSED |
| PASS | `task.accept.p1.failed` | POST /tasks/368b96d3/accept -> 200; status=ACCEPTED |
| PASS | `verification.failed.p1.failed` | complete -> 200; result=FAILED (expected FAILED); task=FAILED; None |
| PASS | `scan.accept.p1.partial` | POST /systems/39b77484/scan -> 200; job=8572ecd4-ac17-4240-8d47-9917e6192897 |
| PASS | `scan.completed.p1.partial` | job 8572ecd4 -> COMPLETED; scan_id=9a5a0897-35e3-48a5-ad84-e47bf33d21d8 |
| PASS | `task.create.p1.partial` | POST /remediation/tasks -> 200; task=00b4d06b-90f7-4caa-a135-3ef0ce4c7052; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p1.partial` | POST /tasks/00b4d06b/accept -> 200; status=ACCEPTED |
| PASS | `verification.partial.p1.partial` | complete -> 200; result=PARTIAL (expected PARTIAL); task=PARTIAL; None |
| PASS | `partial.state.p1` | after the partial change the named site holds 0 weak-cipher and 1 MD5 record(s) — the state PARTIAL describes |
| PASS | `scan.accept.p1.regression-base` | POST /systems/39b77484/scan -> 200; job=7fa2f46d-65b0-4730-a7ac-cfde83cb1fc4 |
| PASS | `scan.completed.p1.regression-base` | job 7fa2f46d -> COMPLETED; scan_id=fd049c39-6f48-4503-bf06-6b1efec69794 |
| PASS | `task.create.p1.regression` | POST /remediation/tasks -> 200; task=a01a8bae-d8bc-4b17-8ebb-fe7b6b13e3e7; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p1.regression` | POST /tasks/a01a8bae/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p1.regression` | POST /systems/39b77484/scan -> 200; job=ac42afac-53f9-4b2d-8d1c-eabb25244599 |
| PASS | `scan.completed.p1.regression` | job ac42afac -> COMPLETED; scan_id=f68ff0be-a033-4935-92b4-8e05d2a9c1b3 |
| PASS | `regression.observed.p1` | the change set fixed PinBlockService.java and dropped 1 new weak-cipher record(s) into LegacySigner.java |
| PASS | `verification.regression.p1.regression` | complete -> 200; result=REGRESSION (expected REGRESSION); task=REGRESSION; None |
| PASS | `scan.accept.p1.inconclusive-base` | POST /systems/39b77484/scan -> 200; job=0053a305-c33b-4143-b3cb-766b55aa1c25 |
| PASS | `scan.completed.p1.inconclusive-base` | job 0053a305 -> COMPLETED; scan_id=7d0c5fec-5bc6-402a-844e-501b6051cb70 |
| PASS | `task.create.p1.inconclusive` | POST /remediation/tasks -> 200; task=b834d286-7269-4cc5-b983-f34e308dd4f0; rule=manual-review; status=PROPOSED |
| PASS | `task.accept.p1.inconclusive` | POST /tasks/b834d286/accept -> 200; status=ACCEPTED |
| PASS | `identity.stable.p1` | the same estate scanned under two job ids produced identical evidence coordinates (20 vs 20; 0 differing) — a rescan can therefore be compared to its predecessor at all |
| PASS | `scan.accept.p1.inconclusive-empty` | POST /systems/39b77484/scan -> 200; job=e12f5b01-2ac8-4421-847b-ab63e93dc2c2 |
| PASS | `scan.completed.p1.inconclusive-empty` | job e12f5b01 -> COMPLETED; scan_id=b88592ba-15af-4bbb-9ce0-5ac7a4085d32 |
| PASS | `rescan.empty.p1` | the emptied target produced 0 evidence record(s) — this is the rescan that must NOT read as 'fixed' |
| PASS | `verification.inconclusive.p1.inconclusive` | complete -> 200; result=INCONCLUSIVE (expected INCONCLUSIVE); task=COMPLETED; None |
| PASS | `audit.trail.p1` | GET /events/recent -> 200; 224 journal event(s) read (latest_id=224, replay_gap=False); 5/5 task(s) opened this pass carry their proposal event; lifecycle recorded=['task_accepted', 'task_completed', 'task_created', 'task_verified'] |
| PASS | `drift.list.p1` | GET /drift -> 200; 39 event(s) |
| PASS | `report.pin.p1` | POST /scans/f68ff0be/report-snapshot {template_id=fips-140-3} -> 200; snapshot=e12156aa; payload_hash=2df501709c6691ba; created=True |
| PASS | `report.serve.p1` | GET /report-snapshots/e12156aa -> 200; integrity=OK (the recomputed SHA-256 over the stored payload equals the pinned hash=True); template=fips-140-3; pinned scan=f68ff0be (the scan named in the request=True) |
| PASS | `coverage.p1` | GET /scans/f68ff0be/coverage -> {"scan_id": "f68ff0be-a033-4935-92b4-8e05d2a9c1b3", "scanner_id": "static-multi-scanner-v1.0", "status": "COMPLETED", "files_scanned": 6, "files_with_crypto": 6} |
| PASS | `durable.cbom_pin.p1` | the scan's CBOM pin is durable: 1 pipeline-generated snapshot(s) of 1 (round 80: this was 0 on SQLite) |
| PASS | `scan.accept.p2.payments` | POST /systems/39b77484/scan -> 200; job=b739fa4d-61aa-4131-8ab0-31ceaab3f968 |
| PASS | `scan.completed.p2.payments` | job b739fa4d -> COMPLETED; scan_id=715372db-bfd4-40a2-a4f9-18d4071a79aa |
| PASS | `scan.accept.p2.mainframe` | POST /systems/2f3a436e/scan -> 200; job=a433bb16-2c8e-4201-9915-cfbab4564973 |
| PASS | `scan.completed.p2.mainframe` | job a433bb16 -> COMPLETED; scan_id=c0f38752-c49a-480b-886b-c5d5b84de9cb |
| PASS | `scan.accept.p2.ibmi` | POST /systems/5807c364/scan -> 200; job=73c6c7ce-3a20-4431-bf51-af55842e3d84 |
| PASS | `scan.completed.p2.ibmi` | job 73c6c7ce -> COMPLETED; scan_id=91f8d99c-c94b-4d6f-bd23-a5ce8e794968 |
| PASS | `evidence.verify.p2.payments` | GET /scans/715372db/verify -> 200; PASS |
| PASS | `evidence.mainframe.p2` | mainframe scan produced 7 evidence record(s) — the Natural/ICSF parsers participate in the loop |
| PASS | `evidence.verify.p2.mainframe` | GET /scans/c0f38752/verify -> 200; PASS |
| PASS | `evidence.ibmi.p2` | ibmi scan produced 11 evidence record(s) — the RPG IV/ILE C/GSKit parsers participate in the loop |
| PASS | `evidence.verify.p2.ibmi` | GET /scans/91f8d99c/verify -> 200; PASS |
| PASS | `findings.p2` | payments-api scan produced 20 finding(s): ['3DES', 'AES', 'MD5', 'RC4', 'RSA', 'SHA-1', 'SHA2', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'] |
| PASS | `evidence.paths_target_relative.p2` | all 20 evidence record(s) name their file in the TARGET's coordinates (0 carried a worker staging path) — evidence identity has to survive a rescan or verification invents regressions |
| PASS | `target.finding.p2` | driving condition: 3DES at src/main/java/com/bank/payments/PinBlockService.java:16 (evidence abaef960, 2 record(s) at that site) |
| PASS | `baseline.exists.p2` | GET /baselines -> 200; 1 row(s), 1 ACTIVE, 1 approved against an EARLIER scan — the baseline survived the pass that created it (local:///tmp/cryptoscan-sources/operator-loop/payments-api -> c361ed3b, approved_by=admin) |
| PASS | `task.create.p2.verified` | POST /remediation/tasks -> 200; task=31b2e66b-4dae-4c6a-8e13-4a45b180c088; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p2.verified` | POST /tasks/31b2e66b/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p2.fix` | POST /systems/39b77484/scan -> 200; job=7818f578-7a5c-4ee9-b5e8-a51febe3df79 |
| PASS | `scan.completed.p2.fix` | job 7818f578 -> COMPLETED; scan_id=196f85c7-4083-4d95-885d-779c22471677 |
| PASS | `verification.verified.p2.verified` | complete -> 200; result=VERIFIED (expected VERIFIED); task=VERIFIED; None |
| PASS | `condition.gone.p2` | PinBlockService.java holds 0 weak-cipher record(s) after the fix (the 3DES cipher string in tls.conf is a different condition and is not what this task names) |
| PASS | `scan.accept.p2.reintroduced` | POST /systems/39b77484/scan -> 200; job=2a886cdb-6b08-412a-aeec-42119ce22a13 |
| PASS | `scan.completed.p2.reintroduced` | job 2a886cdb -> COMPLETED; scan_id=a4801b03-dc23-45f3-9dfc-95aab79777ab |
| PASS | `reintroduction.detected.p2` | the reintroduced 3DES PIN block is observed again at the same site (1 record(s)) — a verified fix is not a permanent state |
| PASS | `verification.reintroduced.p2` | re-verify -> 200; result=FAILED (expected one of ['FAILED', 'PARTIAL', 'REGRESSION']); task=FAILED |
| PASS | `scan.accept.p2.untouched` | POST /systems/39b77484/scan -> 200; job=54cfdc49-850a-4c8a-92a4-fc99b404108d |
| PASS | `scan.completed.p2.untouched` | job 54cfdc49 -> COMPLETED; scan_id=a3340431-fe7f-4b8b-8969-871ea72b8734 |
| PASS | `task.create.p2.failed` | POST /remediation/tasks -> 200; task=60abb9a0-b0a1-4693-89e9-7fde69f4bbaf; rule=replace-md5; status=PROPOSED |
| PASS | `task.accept.p2.failed` | POST /tasks/60abb9a0/accept -> 200; status=ACCEPTED |
| PASS | `verification.failed.p2.failed` | complete -> 200; result=FAILED (expected FAILED); task=FAILED; None |
| PASS | `scan.accept.p2.partial` | POST /systems/39b77484/scan -> 200; job=03eeae60-8cd7-41c4-8033-cac3dd222a49 |
| PASS | `scan.completed.p2.partial` | job 03eeae60 -> COMPLETED; scan_id=6dadebe0-1c12-4070-a7b3-21aecc560861 |
| PASS | `task.create.p2.partial` | POST /remediation/tasks -> 200; task=a33f929d-1ca4-4193-a674-b9f3ba61e0f3; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p2.partial` | POST /tasks/a33f929d/accept -> 200; status=ACCEPTED |
| PASS | `verification.partial.p2.partial` | complete -> 200; result=PARTIAL (expected PARTIAL); task=PARTIAL; None |
| PASS | `partial.state.p2` | after the partial change the named site holds 0 weak-cipher and 1 MD5 record(s) — the state PARTIAL describes |
| PASS | `scan.accept.p2.regression-base` | POST /systems/39b77484/scan -> 200; job=81890d52-2ca1-4aae-952d-8a17f20133c0 |
| PASS | `scan.completed.p2.regression-base` | job 81890d52 -> COMPLETED; scan_id=bd68604f-8d56-458f-a85d-5b2351407ebd |
| PASS | `task.create.p2.regression` | POST /remediation/tasks -> 200; task=32dd8063-a4bc-4470-afad-85bd16abd53c; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p2.regression` | POST /tasks/32dd8063/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p2.regression` | POST /systems/39b77484/scan -> 200; job=b53f107f-4659-4a85-ba10-e737aaf8a5d2 |
| PASS | `scan.completed.p2.regression` | job b53f107f -> COMPLETED; scan_id=56877237-0529-4664-9ce0-39d215a56e8c |
| PASS | `regression.observed.p2` | the change set fixed PinBlockService.java and dropped 1 new weak-cipher record(s) into LegacySigner.java |
| PASS | `verification.regression.p2.regression` | complete -> 200; result=REGRESSION (expected REGRESSION); task=REGRESSION; None |
| PASS | `scan.accept.p2.inconclusive-base` | POST /systems/39b77484/scan -> 200; job=9b7a48e0-712b-40d3-86cf-690d5fc8cd77 |
| PASS | `scan.completed.p2.inconclusive-base` | job 9b7a48e0 -> COMPLETED; scan_id=6ed0f912-493a-40f9-9120-a1ab4a7606da |
| PASS | `task.create.p2.inconclusive` | POST /remediation/tasks -> 200; task=2cfc8425-3593-4ac4-b72b-5bbc3bfcdf55; rule=manual-review; status=PROPOSED |
| PASS | `task.accept.p2.inconclusive` | POST /tasks/2cfc8425/accept -> 200; status=ACCEPTED |
| PASS | `identity.stable.p2` | the same estate scanned under two job ids produced identical evidence coordinates (20 vs 20; 0 differing) — a rescan can therefore be compared to its predecessor at all |
| PASS | `scan.accept.p2.inconclusive-empty` | POST /systems/39b77484/scan -> 200; job=beaabfe4-8bae-4f02-8098-155471d27a57 |
| PASS | `scan.completed.p2.inconclusive-empty` | job beaabfe4 -> COMPLETED; scan_id=f379db89-98f4-4b05-a465-fe455a8b42b0 |
| PASS | `rescan.empty.p2` | the emptied target produced 0 evidence record(s) — this is the rescan that must NOT read as 'fixed' |
| PASS | `verification.inconclusive.p2.inconclusive` | complete -> 200; result=INCONCLUSIVE (expected INCONCLUSIVE); task=COMPLETED; None |
| PASS | `audit.trail.p2` | GET /events/recent -> 200; 442 journal event(s) read (latest_id=442, replay_gap=False); 5/5 task(s) opened this pass carry their proposal event; lifecycle recorded=['task_accepted', 'task_completed', 'task_created', 'task_verified'] |
| PASS | `drift.list.p2` | GET /drift -> 200; 78 event(s) |
| PASS | `report.pin.p2` | POST /scans/56877237/report-snapshot {template_id=fips-140-3} -> 200; snapshot=493812dd; payload_hash=acca209604dcd918; created=True |
| PASS | `report.serve.p2` | GET /report-snapshots/493812dd -> 200; integrity=OK (the recomputed SHA-256 over the stored payload equals the pinned hash=True); template=fips-140-3; pinned scan=56877237 (the scan named in the request=True) |
| PASS | `coverage.p2` | GET /scans/56877237/coverage -> {"scan_id": "56877237-0529-4664-9ce0-39d215a56e8c", "scanner_id": "static-multi-scanner-v1.0", "status": "COMPLETED", "files_scanned": 6, "files_with_crypto": 6} |
| PASS | `durable.cbom_pin.p2` | the scan's CBOM pin is durable: 1 pipeline-generated snapshot(s) of 1 (round 80: this was 0 on SQLite) |

## Notes

- the ticket-as-fix trap: the operator marks the task COMPLETED, the platform refuses the credit because the condition is still in the rescan evidence
- GET /monitor/events -> 200 with 0 row(s): platform-scope journal rows (target_id NULL — every remediation.task_* event) are unreachable through that endpoint; the readable paths are /events/recent and the SSE stream. Open defect, recorded in PRODUCT-VISION-AND-GAPS.md.
- the ticket-as-fix trap: the operator marks the task COMPLETED, the platform refuses the credit because the condition is still in the rescan evidence
- GET /monitor/events -> 200 with 0 row(s): platform-scope journal rows (target_id NULL — every remediation.task_* event) are unreachable through that endpoint; the readable paths are /events/recent and the SSE stream. Open defect, recorded in PRODUCT-VISION-AND-GAPS.md.

## What this does not prove

- The estate is synthetic: built from this repository's own parser corpora (corpus_wave13_mainframe_defs.py, test_rpg_parser.py) plus hand-written Java/Python/TLS/Maven sources. It is corpus evidence, NOT customer validation - the same distinction the engineering gate applies to the COBOL/PL-I/RPG customer-sample checks.
- Runs against a single-node development deployment on SQLite with the pipeline executed inline in the API process. It does not exercise the Redis queue, a worker fleet, PostgreSQL, or Neo4j.
- Authorization is exercised as the bootstrap admin (auditor-gated routes accept an admin session outside production). A denied-actor traversal belongs to the frontend P1 row, not this drill.
- Notification dispatch is not asserted: no SMTP transport is wired, so email routing stays count-only.
