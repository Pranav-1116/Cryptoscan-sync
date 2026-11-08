# Backup and disaster-recovery documentation — 2026-10-23

**Status:** documentation/source review only; no live disaster-recovery test.
**Source baseline:** `08b48df0d3667123b5aa90b791014a0cc6e5907d`.
**Branch:** `arena/bb4b80dd-cryproscan`; publication uses `[skip ci]`.

## Deliverables and scope

[Plan entry point](../disaster-recovery/README.md): eight detailed chapters, a pack index,
a diagram index, eight SVGs and eight editable DOT sources, diagram catalog and
documentation-only renderer. Existing documentation navigation and helper/HA
scope corrections point readers to the complete plan.

Coverage includes 26 inventory groups; six BOMs; PostgreSQL/WAL/cohort planning;
eight Redis roles; source/raw artifact custody; runtime isolation; identity and
key recovery; revocation/withdrawal rollback; UNKNOWN/external effects; backup
formats/custody/retention; isolated restore; cutover; failback and acceptance.

No application, schema, dependency lockfile, workflow, deploy profile, running
service, key, backup destination or customer environment was changed. The new
renderer builds documentation assets only; it is not a DR controller.

## Documentation checks

| Check | Final result |
|---|---|
| Repository Markdown files / local links checked | 506 files / 1,997 local links; no missing targets or unresolved Markdown anchors. |
| External links | 57 counted, not fetched; no remote availability assertion. |
| Changed Markdown and fenced shell syntax | 16 files; 5 shell blocks checked with `bash -n`, not executed. |
| Retained source fingerprints | 75 SHA-256 values match: 47 from earlier quality records plus 28 plan inputs below. |
| DOT compile and SVG XML/accessibility | 8 sources render; 92 nodes / 118 edges; every SVG has title/description, no script/external image/DTD. |
| Independent documented renderer reproduction | All 8 SVGs reproduced byte-for-byte with the documented pinned renderer. |
| Renderer syntax and refusal checks | JavaScript syntax passes; existing output, output under sources and missing arguments refused (3 expected failures, no protected asset changes). |
| JSON planning templates | Both parse; explicitly labeled planning records, not implemented helper schemas. |
| Whitespace | `git diff --check` plus new-file checks pass after removing Markdown hard-break trailing spaces found during authoring. |

Tooling: Node 22.22.3, Python 3.11.2, `@viz-js/viz` 3.31.0 and
`@resvg/resvg-js` 2.6.2. Tool packages/raster previews stayed outside Git.
These are documentation checks, not execution of the five shell blocks or a
production SQL/Redis recovery test.

Four diagram previews were visually sampled: architecture, recovery, execution
reconciliation and drill/acceptance. Full SVGs remain zoomable and have accessible
captions. The first authoring render failed on an unquoted reserved DOT identifier;
node IDs/endpoints were quoted and all final sources rendered successfully.

## What was not executed or qualified

- No live backup, restore, replica promotion, failover, destructive fault injection,
  key-recovery ceremony, real provider PITR or bank-site/cyber-recovery drill.
- No production RPO/RTO, zero-loss result, capacity/throughput or 24/7 support claim.
- No customer acceptance, new application test campaign or GitHub Actions verdict.
- Example cadences/retention in the plan are unapproved proposals, not deployed defaults.
- Prior readiness/SQLite/mock reports remain historical evidence with their original scope.

Actual adoption requires completed site inventory, independent custody/fencing,
approved recovery objectives, witnessed scenario measurements and separate review.

## Source fingerprints reviewed for the plan

These bind referenced unchanged source inputs, not customer runtime configuration
or evidence that their complete production recovery behavior was exercised. Each
block is `repository-relative path` followed by its SHA-256.

```text
deploy/ha/docker-compose.replication.yml
485c0f2a768a797b4da602de0ed9aa0c39c7f76d9d074e063a34685a4eab2eec
```

```text
deploy/ha/promote-replica.sh
75367963706df86f355cf07433eafc0790d2626f5a69bcd49eef5e5c52605fbd
```

```text
deploy/operator-profile/site.example.yaml
e2bfca86afda67932586376f882bda31f3f1a5936ea0b8e6e33cc11f670a967d
```

```text
deploy/systemd/cryptoscan-backup.service
cff2d1f2280abe7fcfa766bf1df1f6f2d9c6dae4b0ff1a5627d6e06e60fc5fac
```

```text
deploy/systemd/cryptoscan-backup.timer
7b72a834fcc8595daedb4736e2a35564520dd9075d6acf61f835f5713a3583c0
```

```text
scripts/backup_crypto.py
7403b42cdccd22f1ca7aba80bc2e13886a5250b01e13e0e67bb4bdb063ef4d37
```

```text
scripts/backup_drill.py
d6918a37c83588837fcea74f79b7a2ec0d822a6e9213b25d4f6b3fcab8223135
```

```text
scripts/backup_evidence.py
f998de06621f9059d5919e17b305bc6494233aa504a7577c4e84216084342064
```

```text
scripts/db_backup.sh
4cf66f4dd5a67d9f3ded69d1f6709207744b635b2b59b3c94e2bbdd9c1040a52
```

```text
scripts/db_restore.sh
8266be48c9fa3feb106d664b6dc9c477f652995460d5cf75ae9b7bc13832a3cb
```

```text
scripts/redis_recovery_evidence.py
473f4aac3c6308a88ffd2f10c04963bd26f75a849e5ab32896ccffb389292130
```

```text
scripts/restore_evidence.py
45c81e6aa70d06ad1a7db9884f5df190ed37c74a3eb1976adfd44b206cc9d23a
```

```text
scripts/verify_evidence.py
3cac155270ba5c34401da44fab404651c14d1587b20535d395d35c0bf1369026
```

```text
scripts/verify_evidence_chain.py
35fb3ad0befbe6888316f1be299d12d9ca525ff3d335c5ede39f6796545bf79f
```

```text
services/api/api/assurance/launch.py
76489fe0057aeff71af371d8ca79877aa38fcb62836a717a5980808926ea3ebc
```

```text
services/api/api/assurance/operator.py
dd5f52646260d68a7904958eb702efc1eb19519956490653bc90bcf1796be6ed
```

```text
services/api/api/assurance/relationships.py
b857c02dba9ba18e1d5ed2c2131c7baa576a13c9f3806af124baad6f5682dbd6
```

```text
services/api/api/assurance/remediation.py
30af87917db45f683e917f70bde88cdea9ec0ec3e18ea30235a11a8ccbed16e1
```

```text
services/api/api/routers/cbom.py
59dbf29bf690fda33b38b46c7c27dc3106ed4c5cc00223d2992ac3dacd74a404
```

```text
services/api/api/routers/stream.py
f153404df6d054dcd57ee373f11697c347351920413dcfbc146619e705f796a3
```

```text
services/cbom/cbom/config/settings.py
b6440b59bfa47fd7e65af609820e2a5dd5e54f0408f392288c11a550778080c2
```

```text
services/database/db/models/assurance.py
360bd3ab97c37a26f38956bd21077451583b7ecccea828a100c1207e47bc98b0
```

```text
services/database/db/models/evidence_record.py
d869d906e52765e8eca32b73de12473070b08ec275c5602e6003984e302af405
```

```text
services/database/db/models/execution_control.py
5a4eb3b135e4379e9de6b5222294fef1a0a50c68d8b10d81790f9697fa4d483e
```

```text
services/database/db/models/remediation_task.py
8230ee5b74c673211eba1169c0e7ab330b143b30a4a91ab6389177a3c0d0dd20
```

```text
services/database/db/models/software_supply_chain.py
e6f5d94826b136c653d08f7e90c938675c2fecf5a584c7b1d26a66f3e60c734e
```

```text
services/devsecops/devsecops/artifact_store.py
da91df04c101dc842521ad9ac1c4084f30029a79f69c5e0a5cf0ab1d03d02ee0
```

```text
shared/shared_models/shared_models/assurance.py
5d22ce291d339d9456ebc31e4f0e18f183ad28aa485bf13ad1b4709c1092448e
```
