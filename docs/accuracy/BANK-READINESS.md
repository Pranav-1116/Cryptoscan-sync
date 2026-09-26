# Bank-estate readiness — what is validated, what is not

_Companion to `EXTERNAL-VALIDATION.md` (rounds 11–12) and `REPORT.md` (594/594 on the ground-truth corpus). Written 2026-09-24._

The question behind "real-time testing on banks" is not the generic-language corpus (that is at F1 1.000 across nine waves, seven of them measured blind or first-pass before tuning). It is whether the detector sees the **kinds of cryptography a bank actually has**. This page keeps that list honest.

## Coverage by bank code class

| Code class | Detector | Validated on | Status |
|---|---|---|---|
| Payments Java (PIN blocks, CVV, EMV ARQC/ARPC, DUKPT, TR-31, retail MAC, KCV, SM adapters) | `java_rules.py` payments/HSM pack | jPOS end-to-end: 14 → 75 files with findings, every out-of-package hit hand-reviewed | ✅ measured |
| HSM / PKCS#11 (SunPKCS11, IAIK, Luna, nCipher, Utimaco, CloudHSM, IBMJCECCA, Thales payShield adapters, LMK) | same | wave 8 blind corpus (first pass 25/31 → 31/31); jPOS `JCESecurityModule` | ✅ corpus, ⚠️ no public payShield client to scan |
| Core-banking Java/Spring (TLS, JWT, password encoders, JDBC, keystores) | existing parsers | Apache Fineract 7533 files, 105 findings, 0 noise change after the payments pack | ✅ measured |
| Database-resident crypto: Oracle PL/SQL, T-SQL, pgcrypto, MySQL, DB2 | `sql_parser.py` (new) | sql-server-samples (2359 files, 1 FP class found+fixed), utPLSQL, Oracle sample schemas | ✅ measured |
| Mainframe COBOL/ICSF (CSNB*/CSND*/CSFP*, rule arrays, RACF, JCL) | `cobol_parser.py` (new) | wave 9 corpus (positives) + 257 real COBOL/JCL files with **zero** ICSF usage (negatives) | ⚠️ positives corpus-only — no public ICSF code exists |
| Config / infra (TLS min versions, cipher lists, keystores, k8s/Terraform/web.config/XML) | `config_rules.py`, `xml_parser.py` | rounds 5–10 | ✅ measured |
| Shell provisioning (openssl/keytool/gpg/certbot, `curl -k`) | `shell_parser.py` | round 9 | ✅ measured |
| Middleware: IBM MQ (MQSC/ini/JMS), WebSphere/Liberty, WebLogic, IBM JSSE2/JCE, `java.security`, Mule, Camel, CXF/Rampart/WSO2, jasypt, QuickFIX/J, SWIFT LAU | `config_rules.py`, `xml_parser.py`, `java_rules.py` middleware packs | wave 10 corpus (34 files) | ⚠️ corpus-only — production descriptors are never public |
| Thales payShield host commands (A0/A6/CA/EI/KQ/…) in Java HSM clients | `java_rules.py` (file-context gated: only files that mention Thales/payShield/HSM) | wave 10 corpus + 2-letter-token negatives | ⚠️ corpus-only |
| PL/I calling ICSF | `pli_parser.py` (shares the COBOL verb table) | wave 10 corpus ×4 | ⚠️ corpus-only |
| Vendored JAR/WAR/EAR/`.class` (no source) | `jar_string_scanner.py` — constant-pool strings + class references, nested archives | synthetic class files in unit tests | ✅ deterministic, ⚠️ names only (no data-flow) |
| Triage at 10–50M LOC | `metadata.code_origin` = source / test / generated / vendored / archive on every finding | quorum 797 source vs 944 test; OBP-API 121/57/4 | ✅ measured |
| IBM i: RPG IV / CL / SQLRPGLE / ILE C — Qc3 APIs (ALGD codes), GSKit, QSSLPCL/QSSLCSL, master keys | `rpg_parser.py` (+ C hook) | wave 11 corpus (18 files) + ILEastic/OSSILE/noxDB/QshOni (673 real files) | ✅ measured (GSKit, Qc3 hash), ⚠️ Qc3 encrypt corpus-only |
| Software AG Natural (Adabas) — ICSF calls + rule-array INIT literals | `natural_parser.py` | wave 13 (7 files) + 213 real Natural sources (0 FP) | ✅ measured |
| CICS RDO/CSD (`SSL()`, `SCHEME(HTTPS)`, `CIPHERS(hex)`), SIT, IMS Connect HWSCFG, AT-TLS policy | `mainframe_defs_parser.py` | wave 13 (10 files) | ✅ measured (corpus); ⚠️ no public real CSD extracts available |
| Vendored .NET assemblies / native DLLs (no source) | `detectors/dotnet/assembly_scanner.py` — CLI metadata heaps + PE import table | 103 real binaries (pythonnet facades, OpenSSL/libpq) | ✅ deterministic, ⚠️ names only |
| Payments / HSM vocabulary in C#, Python, Go, C, TS (payShield commands, DUKPT, TR-31, KCV, python-pkcs11) | `java_rules.PAYMENTS_RULES` via `_payments_pass` | wave 14 blind (0.994 → 722/722); jPOS +15 TP, Fineract/zowe-cli unchanged | ✅ measured |
| Cross-file constants classes (`Algorithms.CIPHER` in another file) | `core/constant_index.py` | jjwt 5 hops + keycloak 3 hops, all verified; nifi/cas 0 wrong hops over 8 k constants (round 22) | ✅ exercised on real repos |
| Informix 4GL / Genero, PowerBuilder, Progress OpenEdge ABL, NonStop TAL/TACL (Atalla + SSLLIB), SAS, payShield console `.hsm` scripts, HLASM comments | `parsers/legacy_4gl_parser.py`, `cobol_parser._strip_hlasm_comments` | wave 15 blind (0.988 → 748/748); Progress ADE 4766 files: 53 findings, all confirmed | ✅ deterministic; ⚠️ vocabularies built from vendor docs + one real ABL repo, no real PowerBuilder/4GL/TAL bank code seen yet |
| Mobile packages without source — Android `.apk/.aab/.dex` (DEX type + string tables through the JAR constant-pool analysis; `lib/*.so` symbols), iOS `.ipa` (Mach-O symbols: CommonCrypto, Security.framework, Secure Enclave, CryptoKit mangled names; `Info.plist` ATS keys) | `detectors/mobile/mobile_binary_scanner.py` | 25 real APKs from Apktool's test corpus parsed without error (SHA-256 / SSL / BC-provider strings found where the DEX references Cipher/Mac/Signature); synthetic DEX + Mach-O unit tests | ✅ parses real DEX; ⚠️ no real bank app or real IPA seen (release-asset egress blocked in the sandbox) |
| Runtime evidence — ICSF SMF-82, RACDCERT, payShield audit, JSSE debug, `openssl s_client`, nginx/Apache/HAProxy `$ssl_cipher`, sshd, AT-TLS `EZD12xxI` | `parsers/runtime_log_parser.py` (`source.type = RUNTIME_LOG`, aggregated with occurrence counts), `scripts/ingest_runtime_logs.py` reconciles runtime vs source | 9 fixture logs, 8 sources, plain app log silent | ✅ built; ⚠️ no bank log drop yet — see `docs/runtime/RUNTIME-EVIDENCE.md` |
| Bank triage loop — review workbook (findings with source line + candidate-miss list from crypto *signals* in zero-finding files + unowned extensions) and scoring back to precision/recall + corpus skeletons | `scripts/bank_triage.py workbook / score` | first run on jPOS: 1 581 findings, 23 candidate rows, 1 real miss found and fixed (`keytool` argv in Java) | ✅ |
| Dependency & cascade — blast radius per crypto provider, migration waves, crypto libraries + versions from manifests, shared key material, key sizes below floor | `analysis/cascade.py` (third hop of every scan) — [CASCADE-ANALYSIS.md](CASCADE-ANALYSIS.md) | jPOS 1 208 files / 2 961 edges / 75 providers, Fineract 7 567 files / 31 028 edges | ✅ import-level; ⚠️ not call-level, dynamic loading not followed |
| Key & certificate inventory — ICSF CKDS/PKDS, TR-31 key blocks, Luna/nShield/Utimaco/PKCS#11, AWS/Azure/GCP KMS, Vault, keytool, RACDCERT, cert CSV; reconciled against code (consumers / orphans / keys outside the estate) | `parsers/key_inventory_parser.py`, `scripts/ingest_key_inventory.py` — [KEY-INVENTORY.md](KEY-INVENTORY.md) | 14 fixture exports, 12 systems, 45 keys; flags weak/expired/stale/inactive/exportable/no-rotation | ✅ built; ⚠️ no bank export parsed yet |
| Business-system roll-up — `cryptoscan-systems.yml` maps paths to CMDB ids; cascade reports per-system providers, algorithms, weak params, cross-system dependencies and earliest migration wave | `analysis/cascade.py` (`systems` section) | unit-tested on a 4-system estate | ✅ |
| Post-quantum adoption (the target side of the migration): ML-KEM / ML-DSA / SLH-DSA / hybrid groups in JDK 24, .NET 10, Go 1.24, OpenSSL 3.5, liboqs (C/Python/Go), BouncyCastle PQC, `@noble/post-quantum`, OpenSSH 9.9, nginx; pre-standard Kyber/Dilithium/SPHINCS+ names | `parsers/pqc_names.py` shared by every language parser + config rules | wave 17 blind (0.992 → 797/797); oqs-provider 62 files (0 → 208 PQC findings), circl 617 files, liboqs-python | ✅ measured; normaliser → CBOM contract guarantees `quantum_vulnerable=false` + correct designation for them |
| Not covered yet | direct enumeration of HSM partitions over the network (we ingest the vendor's own listing instead — deliberate: no HSM credentials in the tool); live database encryption state (TDE/column encryption) — code + config + KMS keys only; HLASM ICSF *macros* other than CALL/LINK verbs; obfuscated (R8/ProGuard string-encrypted) DEX; iOS apps whose crypto lives entirely behind Swift generics with no mangled CryptoKit names; live network observation (a sensor product, not a log parser) | — | ❌ |

## Throughput

### Real repositories, single core (sandbox CPU)

Measured with `/tmp/throughput.py`-style loop over Fineract + jPOS + sql-server-samples + CardDemo:

```
files=11306  lines=1,858,721  findings=1842  seconds=100.2
files/s=112.8   kLOC/s=18.5   => 1M LOC ≈ 0.9 min single-core
.java 16.5 kLOC/s · .js 12.0 · .cs 26.1 · .sql 35.2 · .xml 153 · .cbl 85
```

### Multi-million-LOC monorepo, multi-process (`scripts/scale_evidence.py`)

Synthetic polyglot monorepo (Java 40 % / JS 14 % / C# 12 % / Python 12 % / COBOL 8 % / Go / SQL / YAML,
~2.5 % of files carry crypto), scanned end-to-end through `Scanner.scan` (discovery → parsers →
cross-file constant index → config/material scanners) with `CRYPTOSCAN_SCAN_PROCESSES` = 1 and 2 on
the 2-core sandbox:

```
synthetic monorepo: 36877 files, 3,000,032 LOC
procs=1: 76.2s  39.4 kLOC/s  484 files/s  findings=1836  peak RSS 96 MB  -> 10M LOC ≈ 4.2 min
procs=2: 41.8s  71.7 kLOC/s  882 files/s  findings=1836  peak RSS 96 MB  -> 10M LOC ≈ 2.3 min
```

Finding counts are identical across process counts (the script exits non-zero otherwise), the
speed-up is 1.82× on 2 cores (the remainder is the serial constant-index build and result
assembly), and memory is flat because findings stream back per chunk. Synthetic code is
lighter than real code per line, so plan with the real-repo 18.5 kLOC/s/core figure: a 10M-LOC
bank estate is ~9 CPU-minutes of parsing — **under 5 minutes wall-clock on a 4-core worker**,
and the per-repo git clone will dominate. The 7-day / 10M-LOC *soak* on a real estate is still
to be run at the pilot; what is established here is that the pipeline is CPU-bound and
parallelises linearly per file with no memory growth.

Sizing rule: `CRYPTOSCAN_SCAN_PROCESSES × worker max_workers ≤ cores` (one job × N processes,
or N jobs × 1 process — the second is better when many small repos queue up).

## What a first bank engagement should do (in order)

1. Run `scripts/scan_third_party.py <repo> v` on the **payments switch** and the **ICSF-calling COBOL modules** first — these are the two areas where the positive side is least externally validated.
2. Triage output per package: every file with findings gets a 30-second read; every file *without* findings that imports `org.jpos.security`, `javax.crypto`, `iaik.pkcs`, or calls `CSN*` gets flagged as a candidate miss.
3. Feed both lists back as a wave-10 corpus (bank-anonymised) before tuning anything — first-pass numbers are recorded, then fixed.
4. Only then trust the inventory for CBOM / PQC-migration planning.

## Scope defaults that affect the numbers

* Test directories are **scanned** by the CLI and the worker; their findings carry `metadata.code_origin = "test"`. Set `CRYPTOSCAN_EXCLUDE_TESTS=1` (worker) or `--exclude-tests` (CLI) to drop them. Before round 16 the worker and any config-loaded CLI run silently skipped `test/` and `tests/` — a 25 % file-count gap on a Maven multi-module bank repo.
* `SCANNER_EXCLUDE_DIRS` adds to the built-in exclusions (`.git`, `node_modules`, `vendor`, build outputs …); it never replaces them.
* Archives (`.jar/.war/.ear/.dll/.exe`) are scanned once through discovery and tagged `code_origin = "archive"`.



## Whole-product check on a Saudi bank-shaped estate (2026-09-26)

[SNB-VALIDATION.md](SNB-VALIDATION.md): a representative SNB-profile fixture (36 files across mada switch, SARIE,
SADAD, ZATCA, Nafath, core ledger Oracle + z/OS, mobile, SAMA-CSF infra — synthetic, not the bank's systems) scanned
blind at **0.981 F1** (764/785 exact), 1.000 after fixes, then run through the full pipeline with a
`cryptoscan-systems.yml`, policy, evidence chain and an HSM/KMS key-export drop. The pipeline run exposed and fixed
three defects the scanner benchmark could not see — a policy name-matching bug that PASSed TLS 1.0, `.inf` templates
skipped by pipeline discovery, and mainframe/HSM key labels missing from reconciliation.

## Bank readiness — the number (2026-09-25)

| Layer | Readiness | Basis |
|---|---|---|
| **Discovery accuracy on bank code classes** | **~95 %** | 15 blind waves (748 files, every first pass since wave 9 ≥ 0.988, corpus 100 % after fixes); real repos: jPOS, Fineract, OBP-API, quorum, baker, legend-engine, keycloak, jjwt, nifi, cas, Progress ADE, 257 COBOL/JCL, 673 IBM i, 213 Natural, 103 .NET binaries, 25 APKs. Now also: legacy 4GL/TAL/SAS/payShield-console parsers, mobile packages, runtime-log evidence, cross-file hop verified on real repos (8/8 correct), a triage loop that turns a bank's review into a number, and **dependency & cascade analysis** (who depends on each piece of crypto, migration waves, library versions, shared keys, weak key sizes) so the inventory is an estate view, not a list of hits. Deductions: ICSF/CICS/PL/I/Natural/4GL/TAL positives are corpus-only (no public bank code exists for them); runtime evidence is log-based, not a network sensor; no bank has yet fed its own first-pass numbers back. |
| **Scan pipeline (clone → scan → evidence → CBOM → policy → alert)** | ~92 % | PostgreSQL + Redis end-to-end, at-least-once queue + reaper, soak evidence; per-file process pool measured on a 3M-LOC synthetic monorepo (71.7 kLOC/s on 2 cores, deterministic, flat RSS → 10M LOC ≈ 2.3 min); API capacity measured honestly (~180 authenticated rps per worker) and three defects fixed in the process. Still not run for 7 days on a real estate; the `kill -9` of a worker against a *real* Redis and the HA compose fail-over need a host with Redis/Docker (neither exists in this sandbox — runbooks: `docs/runbooks/job-queue.md`). |
| **Bank operating requirements** (air-gap install, RBAC/SSO, audit chain, backup/PITR, HA, SBOM of the product itself) | ~75 % | unchanged: air-gap + backup + PITR drills documented and run once; HA compose exists but not drilled; SSO/SAML beta; ITSM/SIEM connectors and the product's own SOC 2 / pen-test are company actions, not sandbox work. |
| **Overall for a first bank pilot** | **~87 %** | Ready for a *pilot on the payments switch, the mobile channel packages and the ICSF COBOL modules with the triage loop* — not yet for an unattended, audit-grade inventory across the whole estate. |
