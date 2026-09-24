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
| Vendored .NET assemblies / native DLLs (no source) | `detectors/dotnet/assembly_scanner.py` — CLI metadata heaps + PE import table | 103 real binaries (pythonnet facades, OpenSSL/libpq) | ✅ deterministic, ⚠️ names only |
| Not covered yet | Natural/Adabas, CICS/IMS resource definitions, 4GLs, payShield console/`.hsm` scripts | — | ❌ |

## Throughput (single core, sandbox CPU)

Measured with `/tmp/throughput.py`-style loop over Fineract + jPOS + sql-server-samples + CardDemo:

```
files=11306  lines=1,858,721  findings=1842  seconds=100.2
files/s=112.8   kLOC/s=18.5   => 1M LOC ≈ 0.9 min single-core
.java 16.5 kLOC/s · .js 12.0 · .cs 26.1 · .sql 35.2 · .xml 153 · .cbl 85
```

A 10M-LOC bank monorepo is therefore ~9 CPU-minutes; the worker pool parallelises per file, so wall-clock is bounded by the number of workers, not the parser.

## What a first bank engagement should do (in order)

1. Run `scripts/scan_third_party.py <repo> v` on the **payments switch** and the **ICSF-calling COBOL modules** first — these are the two areas where the positive side is least externally validated.
2. Triage output per package: every file with findings gets a 30-second read; every file *without* findings that imports `org.jpos.security`, `javax.crypto`, `iaik.pkcs`, or calls `CSN*` gets flagged as a candidate miss.
3. Feed both lists back as a wave-10 corpus (bank-anonymised) before tuning anything — first-pass numbers are recorded, then fixed.
4. Only then trust the inventory for CBOM / PQC-migration planning.

## Scope defaults that affect the numbers

* Test directories are **scanned** by the CLI and the worker; their findings carry `metadata.code_origin = "test"`. Set `CRYPTOSCAN_EXCLUDE_TESTS=1` (worker) or `--exclude-tests` (CLI) to drop them. Before round 16 the worker and any config-loaded CLI run silently skipped `test/` and `tests/` — a 25 % file-count gap on a Maven multi-module bank repo.
* `SCANNER_EXCLUDE_DIRS` adds to the built-in exclusions (`.git`, `node_modules`, `vendor`, build outputs …); it never replaces them.
* Archives (`.jar/.war/.ear/.dll/.exe`) are scanned once through discovery and tagged `code_origin = "archive"`.

