# Operator-loop drill — 2026-10-16T19:40:19+00:00

Verdict: **PASS** (123 passed / 0 failed of 123 checks, 2 pass(es))

- API: `http://127.0.0.1:8010` (inline pipeline, no Redis)
- Estate: `/tmp/cryptoscan-sources/operator-loop` — 3 authorized systems
- Repository: `40a27e1f` on `arena/bb4b80dd-cryproscan`
- Command: `scripts/operator_loop_drill.py --passes 2 --out docs/readiness-evidence/operator-loop-drill-2026-10-16.json`

## Checks

| Status | Check | Detail |
|---|---|---|
| PASS | `system.register.payments-api` | POST /systems -> 200; id=995321d0-701e-4fa7-b0db-827172890b79; owners m.iyer@bank.example / s.duarte@bank.example |
| PASS | `system.register.mainframe-icsf` | POST /systems -> 200; id=171bb5f8-d01e-4901-9efb-cb77bf8a693a; owners r.okonkwo@bank.example / s.duarte@bank.example |
| PASS | `system.register.claims-ibmi` | POST /systems -> 200; id=3e7321f6-1ae5-4a7e-8efe-4c6335b5b86f; owners a.lindqvist@bank.example / s.duarte@bank.example |
| PASS | `scan.accept.p1.payments` | POST /systems/995321d0/scan -> 200; job=35eabb08-e640-4cbf-ba58-bce8b2fa47ef |
| PASS | `scan.completed.p1.payments` | job 35eabb08 -> COMPLETED; scan_id=b745c04a-5a84-493c-a53e-f5f25b5fea58 |
| PASS | `scan.accept.p1.mainframe` | POST /systems/171bb5f8/scan -> 200; job=8128c904-6fe5-4baf-9023-0de836b46891 |
| PASS | `scan.completed.p1.mainframe` | job 8128c904 -> COMPLETED; scan_id=be0505f2-10c0-430d-8af4-308fcae832e1 |
| PASS | `scan.accept.p1.ibmi` | POST /systems/3e7321f6/scan -> 200; job=1772b2fb-eb83-4759-b931-cbad7eb0238e |
| PASS | `scan.completed.p1.ibmi` | job 1772b2fb -> COMPLETED; scan_id=251df758-96cc-45d4-aee1-4d12a6ab130a |
| PASS | `evidence.verify.p1.payments` | GET /scans/b745c04a/verify -> 200; PASS |
| PASS | `evidence.mainframe.p1` | mainframe scan produced 7 evidence record(s) — the Natural/ICSF parsers participate in the loop |
| PASS | `evidence.verify.p1.mainframe` | GET /scans/be0505f2/verify -> 200; PASS |
| PASS | `evidence.ibmi.p1` | ibmi scan produced 11 evidence record(s) — the RPG IV/ILE C/GSKit parsers participate in the loop |
| PASS | `evidence.verify.p1.ibmi` | GET /scans/251df758/verify -> 200; PASS |
| PASS | `findings.p1` | payments-api scan produced 20 finding(s): ['3DES', 'AES', 'MD5', 'RC4', 'RSA', 'SHA-1', 'SHA2', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'] |
| PASS | `evidence.paths_target_relative.p1` | all 20 evidence record(s) name their file in the TARGET's coordinates (0 carried a worker staging path) — evidence identity has to survive a rescan or verification invents regressions |
| PASS | `target.finding.p1` | driving condition: 3DES at src/main/java/com/bank/payments/PinBlockService.java:16 (evidence 0fec59ac, 2 record(s) at that site) |
| PASS | `baseline.approve.p1` | POST /baselines/approve -> 200; baseline=9a2aadb3-e892-41af-a66e-f84c88f8b4aa; approved_by=admin |
| PASS | `task.create.p1.verified` | POST /remediation/tasks -> 200; task=ae974299-1f7d-4d7e-a121-ea24800d0b4a; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p1.verified` | POST /tasks/ae974299/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p1.fix` | POST /systems/995321d0/scan -> 200; job=90deed8c-629a-4210-bdde-8b5a9f38ccb5 |
| PASS | `scan.completed.p1.fix` | job 90deed8c -> COMPLETED; scan_id=e3d5084c-8922-40fb-bef4-8428957466df |
| PASS | `verification.verified.p1.verified` | complete -> 200; result=VERIFIED (expected VERIFIED); task=VERIFIED; None |
| PASS | `condition.gone.p1` | PinBlockService.java holds 0 weak-cipher record(s) after the fix (the 3DES cipher string in tls.conf is a different condition and is not what this task names) |
| PASS | `scan.accept.p1.reintroduced` | POST /systems/995321d0/scan -> 200; job=0f831604-a236-4fef-859b-f2ee49eb4fbd |
| PASS | `scan.completed.p1.reintroduced` | job 0f831604 -> COMPLETED; scan_id=7b850aba-e714-4d37-a03e-edd0b5d00b54 |
| PASS | `reintroduction.detected.p1` | the reintroduced 3DES PIN block is observed again at the same site (1 record(s)) — a verified fix is not a permanent state |
| PASS | `verification.reintroduced.p1` | re-verify -> 200; result=FAILED (expected one of ['FAILED', 'PARTIAL', 'REGRESSION']); task=FAILED |
| PASS | `scan.accept.p1.untouched` | POST /systems/995321d0/scan -> 200; job=7d3c3a48-fed6-421b-8e66-6e309dd06d58 |
| PASS | `scan.completed.p1.untouched` | job 7d3c3a48 -> COMPLETED; scan_id=84bb4c94-25e1-45ef-83ef-4afabb5577a3 |
| PASS | `task.create.p1.failed` | POST /remediation/tasks -> 200; task=ec258e85-a729-414b-a02a-84c4dd52c4f3; rule=replace-md5; status=PROPOSED |
| PASS | `task.accept.p1.failed` | POST /tasks/ec258e85/accept -> 200; status=ACCEPTED |
| PASS | `verification.failed.p1.failed` | complete -> 200; result=FAILED (expected FAILED); task=FAILED; None |
| PASS | `scan.accept.p1.partial` | POST /systems/995321d0/scan -> 200; job=fcda3c70-8f73-4cb0-88cc-412c9d293def |
| PASS | `scan.completed.p1.partial` | job fcda3c70 -> COMPLETED; scan_id=514a46c3-e314-4af0-8e8b-0cf1acd26fa6 |
| PASS | `task.create.p1.partial` | POST /remediation/tasks -> 200; task=b6096091-98a2-40ab-a067-071e1b45e328; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p1.partial` | POST /tasks/b6096091/accept -> 200; status=ACCEPTED |
| PASS | `verification.partial.p1.partial` | complete -> 200; result=PARTIAL (expected PARTIAL); task=PARTIAL; None |
| PASS | `partial.state.p1` | after the partial change the named site holds 0 weak-cipher and 1 MD5 record(s) — the state PARTIAL describes |
| PASS | `scan.accept.p1.regression-base` | POST /systems/995321d0/scan -> 200; job=671dca55-b871-4cb1-a98f-1fa9634472cf |
| PASS | `scan.completed.p1.regression-base` | job 671dca55 -> COMPLETED; scan_id=e7819e08-a558-4e9e-892d-61d35a32b610 |
| PASS | `task.create.p1.regression` | POST /remediation/tasks -> 200; task=04ea8108-83aa-4d77-907f-935aeab8907c; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p1.regression` | POST /tasks/04ea8108/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p1.regression` | POST /systems/995321d0/scan -> 200; job=c7544505-e268-4ff3-b352-f43d053b5582 |
| PASS | `scan.completed.p1.regression` | job c7544505 -> COMPLETED; scan_id=f784dd0b-1427-46c6-bae7-8d07ee9c7f62 |
| PASS | `regression.observed.p1` | the change set fixed PinBlockService.java and dropped 1 new weak-cipher record(s) into LegacySigner.java |
| PASS | `verification.regression.p1.regression` | complete -> 200; result=REGRESSION (expected REGRESSION); task=REGRESSION; None |
| PASS | `scan.accept.p1.inconclusive-base` | POST /systems/995321d0/scan -> 200; job=147169a9-bd32-4851-b19e-6b24dc0c312e |
| PASS | `scan.completed.p1.inconclusive-base` | job 147169a9 -> COMPLETED; scan_id=ec0970db-80dc-4127-8fc9-d8e56c5a3341 |
| PASS | `task.create.p1.inconclusive` | POST /remediation/tasks -> 200; task=3e19369a-5f5f-44c9-b35a-28b6af161e2b; rule=manual-review; status=PROPOSED |
| PASS | `task.accept.p1.inconclusive` | POST /tasks/3e19369a/accept -> 200; status=ACCEPTED |
| PASS | `identity.stable.p1` | the same estate scanned under two job ids produced identical evidence coordinates (20 vs 20; 0 differing) — a rescan can therefore be compared to its predecessor at all |
| PASS | `scan.accept.p1.inconclusive-empty` | POST /systems/995321d0/scan -> 200; job=8040d0df-a446-45f5-ac8c-223baeea8643 |
| PASS | `scan.completed.p1.inconclusive-empty` | job 8040d0df -> COMPLETED; scan_id=ed1ab7a7-ce1e-4986-bd23-7588885ac954 |
| PASS | `rescan.empty.p1` | the emptied target produced 0 evidence record(s) — this is the rescan that must NOT read as 'fixed' |
| PASS | `verification.inconclusive.p1.inconclusive` | complete -> 200; result=INCONCLUSIVE (expected INCONCLUSIVE); task=COMPLETED; None |
| PASS | `audit.trail.p1` | GET /events/recent -> 200; 225 journal event(s) read (latest_id=225, replay_gap=False); 5/5 task(s) opened this pass carry their proposal event; lifecycle recorded=['task_accepted', 'task_completed', 'task_created', 'task_verified'] |
| PASS | `audit.trail.operator_endpoint.p1` | GET /monitor/events -> 200; 32 journal row(s) readable by this caller (32 platform-scope); 5/5 task(s) opened this pass carry their proposal event here too — the operator surface and the durable journal agree |
| PASS | `drift.list.p1` | GET /drift -> 200; 39 event(s) |
| PASS | `report.pin.p1` | POST /scans/f784dd0b/report-snapshot {template_id=fips-140-3} -> 200; snapshot=f011c03f; payload_hash=d2e319208b32cf93; created=True |
| PASS | `report.serve.p1` | GET /report-snapshots/f011c03f -> 200; integrity=OK (the recomputed SHA-256 over the stored payload equals the pinned hash=True); template=fips-140-3; pinned scan=f784dd0b (the scan named in the request=True) |
| PASS | `coverage.p1` | GET /scans/f784dd0b/coverage -> {"scan_id": "f784dd0b-1427-46c6-bae7-8d07ee9c7f62", "scanner_id": "static-multi-scanner-v1.0", "status": "COMPLETED", "files_scanned": 6, "files_with_crypto": 6} |
| PASS | `durable.cbom_pin.p1` | the scan's CBOM pin is durable: 1 pipeline-generated snapshot(s) of 1 (round 80: this was 0 on SQLite) |
| PASS | `scan.accept.p2.payments` | POST /systems/995321d0/scan -> 200; job=8ebb8f84-6bbe-4ce8-9953-abb84f5b849a |
| PASS | `scan.completed.p2.payments` | job 8ebb8f84 -> COMPLETED; scan_id=284d2cce-3161-4b31-a61d-121215d6d70c |
| PASS | `scan.accept.p2.mainframe` | POST /systems/171bb5f8/scan -> 200; job=19585d5f-ec52-44d8-a8bc-eba1bf4b2a15 |
| PASS | `scan.completed.p2.mainframe` | job 19585d5f -> COMPLETED; scan_id=736fed7a-caa3-4a02-8943-601c05cf919b |
| PASS | `scan.accept.p2.ibmi` | POST /systems/3e7321f6/scan -> 200; job=6ce74ac7-a26f-4bfb-bd12-f0958715b4d1 |
| PASS | `scan.completed.p2.ibmi` | job 6ce74ac7 -> COMPLETED; scan_id=3c200121-9f8e-46e4-bb69-1a50f96c9e19 |
| PASS | `evidence.verify.p2.payments` | GET /scans/284d2cce/verify -> 200; PASS |
| PASS | `evidence.mainframe.p2` | mainframe scan produced 7 evidence record(s) — the Natural/ICSF parsers participate in the loop |
| PASS | `evidence.verify.p2.mainframe` | GET /scans/736fed7a/verify -> 200; PASS |
| PASS | `evidence.ibmi.p2` | ibmi scan produced 11 evidence record(s) — the RPG IV/ILE C/GSKit parsers participate in the loop |
| PASS | `evidence.verify.p2.ibmi` | GET /scans/3c200121/verify -> 200; PASS |
| PASS | `findings.p2` | payments-api scan produced 20 finding(s): ['3DES', 'AES', 'MD5', 'RC4', 'RSA', 'SHA-1', 'SHA2', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'] |
| PASS | `evidence.paths_target_relative.p2` | all 20 evidence record(s) name their file in the TARGET's coordinates (0 carried a worker staging path) — evidence identity has to survive a rescan or verification invents regressions |
| PASS | `target.finding.p2` | driving condition: 3DES at src/main/java/com/bank/payments/PinBlockService.java:16 (evidence 68b001e7, 2 record(s) at that site) |
| PASS | `baseline.exists.p2` | GET /baselines -> 200; 1 row(s), 1 ACTIVE, 1 approved against an EARLIER scan — the baseline survived the pass that created it (local:///tmp/cryptoscan-sources/operator-loop/payments-api -> b745c04a, approved_by=admin) |
| PASS | `task.create.p2.verified` | POST /remediation/tasks -> 200; task=4e7f0540-9ddb-4d44-bfa9-1f6ad4d83f6d; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p2.verified` | POST /tasks/4e7f0540/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p2.fix` | POST /systems/995321d0/scan -> 200; job=ed6ca193-4b37-491f-b526-066fc88e113f |
| PASS | `scan.completed.p2.fix` | job ed6ca193 -> COMPLETED; scan_id=e28e5008-20f3-4c15-8866-b0827be4187d |
| PASS | `verification.verified.p2.verified` | complete -> 200; result=VERIFIED (expected VERIFIED); task=VERIFIED; None |
| PASS | `condition.gone.p2` | PinBlockService.java holds 0 weak-cipher record(s) after the fix (the 3DES cipher string in tls.conf is a different condition and is not what this task names) |
| PASS | `scan.accept.p2.reintroduced` | POST /systems/995321d0/scan -> 200; job=803ec56e-55a9-423a-ba75-46f3a184193d |
| PASS | `scan.completed.p2.reintroduced` | job 803ec56e -> COMPLETED; scan_id=f7963a6e-771e-4bbb-b17e-dabf9927d162 |
| PASS | `reintroduction.detected.p2` | the reintroduced 3DES PIN block is observed again at the same site (1 record(s)) — a verified fix is not a permanent state |
| PASS | `verification.reintroduced.p2` | re-verify -> 200; result=FAILED (expected one of ['FAILED', 'PARTIAL', 'REGRESSION']); task=FAILED |
| PASS | `scan.accept.p2.untouched` | POST /systems/995321d0/scan -> 200; job=df52f88b-db28-42e8-92d2-e0c6a43b692c |
| PASS | `scan.completed.p2.untouched` | job df52f88b -> COMPLETED; scan_id=3ac47411-2217-40b3-93e8-7d9ed1025c0f |
| PASS | `task.create.p2.failed` | POST /remediation/tasks -> 200; task=5ad7bf29-aa5a-4124-8d79-c83d8ef6805e; rule=replace-md5; status=PROPOSED |
| PASS | `task.accept.p2.failed` | POST /tasks/5ad7bf29/accept -> 200; status=ACCEPTED |
| PASS | `verification.failed.p2.failed` | complete -> 200; result=FAILED (expected FAILED); task=FAILED; None |
| PASS | `scan.accept.p2.partial` | POST /systems/995321d0/scan -> 200; job=17e5a877-2c2d-4858-a095-42382b9d9acc |
| PASS | `scan.completed.p2.partial` | job 17e5a877 -> COMPLETED; scan_id=a215e332-ed24-4bdf-81e9-056330327980 |
| PASS | `task.create.p2.partial` | POST /remediation/tasks -> 200; task=9150d0d3-1e8c-4117-a918-05cf12a3cbcb; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p2.partial` | POST /tasks/9150d0d3/accept -> 200; status=ACCEPTED |
| PASS | `verification.partial.p2.partial` | complete -> 200; result=PARTIAL (expected PARTIAL); task=PARTIAL; None |
| PASS | `partial.state.p2` | after the partial change the named site holds 0 weak-cipher and 1 MD5 record(s) — the state PARTIAL describes |
| PASS | `scan.accept.p2.regression-base` | POST /systems/995321d0/scan -> 200; job=591667f5-840a-4ccc-8ea9-4f0a0f0f7c16 |
| PASS | `scan.completed.p2.regression-base` | job 591667f5 -> COMPLETED; scan_id=e8064fca-ef71-47f4-89b4-01dcf19ec880 |
| PASS | `task.create.p2.regression` | POST /remediation/tasks -> 200; task=f7b18215-2fc9-4f61-892d-50363b664fcc; rule=replace-3des; status=PROPOSED |
| PASS | `task.accept.p2.regression` | POST /tasks/f7b18215/accept -> 200; status=ACCEPTED |
| PASS | `scan.accept.p2.regression` | POST /systems/995321d0/scan -> 200; job=e84badc2-3261-4772-8cb5-057191502e63 |
| PASS | `scan.completed.p2.regression` | job e84badc2 -> COMPLETED; scan_id=bddaef86-8e69-4d05-879e-0f22d71f467c |
| PASS | `regression.observed.p2` | the change set fixed PinBlockService.java and dropped 1 new weak-cipher record(s) into LegacySigner.java |
| PASS | `verification.regression.p2.regression` | complete -> 200; result=REGRESSION (expected REGRESSION); task=REGRESSION; None |
| PASS | `scan.accept.p2.inconclusive-base` | POST /systems/995321d0/scan -> 200; job=f8831e6c-c94c-4284-a416-da25349b28c4 |
| PASS | `scan.completed.p2.inconclusive-base` | job f8831e6c -> COMPLETED; scan_id=294af771-69da-405d-a04a-77ae78b76827 |
| PASS | `task.create.p2.inconclusive` | POST /remediation/tasks -> 200; task=6c7a276b-4804-4b40-bfbb-0697fef85e17; rule=manual-review; status=PROPOSED |
| PASS | `task.accept.p2.inconclusive` | POST /tasks/6c7a276b/accept -> 200; status=ACCEPTED |
| PASS | `identity.stable.p2` | the same estate scanned under two job ids produced identical evidence coordinates (20 vs 20; 0 differing) — a rescan can therefore be compared to its predecessor at all |
| PASS | `scan.accept.p2.inconclusive-empty` | POST /systems/995321d0/scan -> 200; job=0fbab999-d542-4024-ad52-481e802e2a6a |
| PASS | `scan.completed.p2.inconclusive-empty` | job 0fbab999 -> COMPLETED; scan_id=b316b3ff-104e-4113-9032-d3dd22e48921 |
| PASS | `rescan.empty.p2` | the emptied target produced 0 evidence record(s) — this is the rescan that must NOT read as 'fixed' |
| PASS | `verification.inconclusive.p2.inconclusive` | complete -> 200; result=INCONCLUSIVE (expected INCONCLUSIVE); task=COMPLETED; None |
| PASS | `audit.trail.p2` | GET /events/recent -> 200; 443 journal event(s) read (latest_id=443, replay_gap=False); 5/5 task(s) opened this pass carry their proposal event; lifecycle recorded=['task_accepted', 'task_completed', 'task_created', 'task_verified'] |
| PASS | `audit.trail.operator_endpoint.p2` | GET /monitor/events -> 200; 64 journal row(s) readable by this caller (64 platform-scope); 5/5 task(s) opened this pass carry their proposal event here too — the operator surface and the durable journal agree |
| PASS | `drift.list.p2` | GET /drift -> 200; 78 event(s) |
| PASS | `report.pin.p2` | POST /scans/bddaef86/report-snapshot {template_id=fips-140-3} -> 200; snapshot=01a5dc3b; payload_hash=865b1cd5f7f9f501; created=True |
| PASS | `report.serve.p2` | GET /report-snapshots/01a5dc3b -> 200; integrity=OK (the recomputed SHA-256 over the stored payload equals the pinned hash=True); template=fips-140-3; pinned scan=bddaef86 (the scan named in the request=True) |
| PASS | `coverage.p2` | GET /scans/bddaef86/coverage -> {"scan_id": "bddaef86-8e69-4d05-879e-0f22d71f467c", "scanner_id": "static-multi-scanner-v1.0", "status": "COMPLETED", "files_scanned": 6, "files_with_crypto": 6} |
| PASS | `durable.cbom_pin.p2` | the scan's CBOM pin is durable: 1 pipeline-generated snapshot(s) of 1 (round 80: this was 0 on SQLite) |

## Notes

- the ticket-as-fix trap: the operator marks the task COMPLETED, the platform refuses the credit because the condition is still in the rescan evidence
- the ticket-as-fix trap: the operator marks the task COMPLETED, the platform refuses the credit because the condition is still in the rescan evidence

## What this does not prove

- The estate is synthetic: built from this repository's own parser corpora (corpus_wave13_mainframe_defs.py, test_rpg_parser.py) plus hand-written Java/Python/TLS/Maven sources. It is corpus evidence, NOT customer validation - the same distinction the engineering gate applies to the COBOL/PL-I/RPG customer-sample checks.
- Runs against a single-node development deployment on SQLite with the pipeline executed inline in the API process. It does not exercise the Redis queue, a worker fleet, PostgreSQL, or Neo4j.
- Authorization is exercised as the bootstrap admin (auditor-gated routes accept an admin session outside production). A denied-actor traversal belongs to the frontend P1 row, not this drill.
- Notification dispatch is not asserted: no SMTP transport is wired, so email routing stays count-only.
