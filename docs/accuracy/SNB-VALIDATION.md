# Saudi bank estate — end-to-end validation (SNB profile)

**What this is.** A representative, synthetic estate shaped like a large Saudi bank (Saudi National Bank profile: mada
switch, SARIE, SADAD, ZATCA e-invoicing, Nafath/Absher identity, core ledger on Oracle + z/OS, mobile, SAMA CSF
hardening), scanned **blind** through the discovery engine and then through the **whole pipeline** (git checkout →
scan → normalise → policy → evidence chain → cascade / systems roll-up → key-inventory reconciliation).

**What this is not.** It is not SNB's code, configuration or key material. No SNB system was accessed. The fixture was
written from public standards and vendor documentation (mada / SAMA CSF / ZATCA Fatoora SDK / SARIE LAU / payShield
and ICSF manuals / Nafath OIDC / Yakeen & SIMAH integration guides). The numbers below say how the product behaves
on code *of that shape*; they are not a statement about SNB.

## The fixture (`services/scanner/tests/accuracy/corpus_wave16_saudi_bank.py`, 36 files, 5 negatives)

| System (cryptoscan-systems.yml) | Files | What it exercises |
|---|---|---|
| MADA-SWITCH (critical) | `MadaPinTranslator.java`, `Tr34RemoteKeyLoader.java`, `PayShieldKeyBlockExporter.java`, `EmvArqcVerifier.java`, `payshield-lmk-migration.hsm`, `SARIEKEY.jcl` | jPOS-style PIN translation, TR-34 remote key load, TR-31 key blocks, EMV ARQC, payShield console scripts, KGUP |
| SARIE-HUB (critical) | `SarieLauSigner.java`, `sarie-alliance-gateway.xml`, `SarieMqBridge.cs` | SWIFT LAU HMAC-SHA256, Alliance Gateway TLS suites, MQ AMS |
| SADAD-GATEWAY (high) | `SadadBillerClient.cs`, `sadad_reconcile.py` | JWS RS256 / SHA-256 payment references |
| ZATCA-EINVOICE (high) | `ZatcaInvoiceSigner.cs`, `ZatcaCsrBuilder.cs`, `zatca-qr.ts` | ECDSA secp256k1, XAdES SHA-256, CSR, QR TLV hash |
| DIGITAL-IDENTITY (high) | `NafathTokenValidator.cs`, `openBankingJws.js`, `otpService.ts`, `yakeen_client.py` | PS256/ES256 JWT, JWKS, CSPRNG OTP, mTLS |
| CORE-LEDGER (critical) | `pkg_customer_pii.pks`, `tde_setup.sql`, `CBSTMTAR.cbl`, `legacy_pwd_hash.sql`, `iban_tokenizer.go`, `HijriDateConverter.java` (negative) | DBMS_CRYPTO, TDE, ICSF CSNBENC/CSNBSYE, MD5 password hash (deliberately weak), AES-GCM tokenisation |
| SNB-MOBILE (high) | `SecureStore.kt`, `PinnedClient.kt`, `DeviceBinding.swift` | Android Keystore AES-GCM, certificate pinning SHA-256, Secure Enclave P-256 |
| INFRA-HARDENING (medium) | `sama-csf-tls.conf`, `krb5.conf`, `legacy-branch-gpo.inf`, `mq-ams-policy.yaml`, `was-ssl.properties`, `simah_report_cipher.py` | SAMA-CSF TLS 1.2/1.3 only, Kerberos etypes (RC4 still enabled), SCHANNEL GPO with RC4 + TLS 1.0, MQ AMS, WebSphere SSL |
| negatives | Arabic-language README / i18n JSON / SQL seed / Hijri converter / reporting schedule | must stay silent |

## Discovery accuracy (scanner only, `scripts/accuracy_benchmark.py`)

| pass | precision | recall | F1 | exact files |
|---|---|---|---|---|
| blind first pass (no scanner change) | 0.9953 | 0.9671 | **0.981** | 764/785 |
| after label review + Java AST fixes | 0.9992 | 0.9784 | 0.9887 | — |
| after wave-16 fixes | 1.000 | 1.000 | 1.000 | 784/784 |

The blind pass was already above the 95 % bar. What the misses taught, all fixed and regression-tested:

* **CSPRNG through named imports** — `import { randomInt } from "crypto"` then a bare `randomInt()` was invisible (`javascript_parser.py`).
* **KGUP control statements** — `ADD LABEL(…) ALGORITHM(AES)` / `TYPE(EXPORTER)` in JCL (`cobol_parser.py`), and bare `'AES'`/`'DES'` COBOL literals are now only reported when the program has an ICSF shape (CSNB*/rule arrays/CKDS).
* **payShield console scripts** with comment lines and scripted commands (`legacy_4gl_parser._payshield_console`); two regex bugs where `\s` spanned newlines and shifted line numbers.
* **C# named curves** narrowed to `secp256k1` (ZATCA) — `nistP256` with ECDH is not ECDSA.
* **`encryption: NONE`** (MQ AMS) no longer counts as a family; `UNKNOWN`/`NULL`/`NONE` are all ignored by the scorer.
* One label corrected against the detector: `legacy-branch-gpo.inf` also enables AES in `SupportedEncryptionTypes`, so its ground truth is `{RC4, TLS, AES}`.

## Whole-pipeline run (`services/worker/tests/unit/test_pipeline_snb_estate.py`)

The same files are laid out as a repository with a `cryptoscan-systems.yml` (criticality, owner, `depends_on`) and run
through `PipelineRunner` against a real (SQLite) database. Asserted:

1. **Accuracy survives the pipeline** — evidence rows scored against the same labels: precision and recall ≥ 0.97, ≥ 95 % of files exact, the five Arabic negatives produce no row. (Rows are scored on the scanner's algorithm name kept in `finding_data`; the `algorithm` column holds the normalised family, e.g. `SHA2`.)
2. **Systems** — eight systems in `statistics.cascade.systems` with files/providers/algorithms; persisted `System` rows carry the declared criticality and owner; `SystemDependency` edges include both import-derived and **declared** `depends_on` (`MADA-SWITCH → CORE-LEDGER`); assets attached under each system's paths.
3. **Policy** — `legacy-branch-gpo.inf` RC4 and TLS 1.0 → FAIL, `legacy_pwd_hash.sql` MD5 → FAIL, `sama-csf-tls.conf` (TLS 1.2/1.3, AES-GCM, X25519) → no failure; every record carries content + chain hashes.
4. **Key inventory** — a drop of payShield / Luna / CKDS / keytool exports (`CRYPTOSCAN_KEY_INVENTORY=1`) yields ≥ 15 KEY_INVENTORY records; reconciliation lists `MADA.ZPK.ACQ.001` and `sarie-client.p12` as consumed by the code, `MADA.PVK.2024A` / `SARIE.OUT.AES256.DATA` as referenced by code but absent from every export, and ≥ 1 orphan.

### Three product defects the end-to-end run found (none visible to the scanner-only benchmark)

| defect | effect before | fix |
|---|---|---|
| `.inf` / `.reg` not in pipeline file discovery | the GPO security template was scanned by the CLI but skipped by the pipeline — RC4 + TLS 1.0 branch policy never reached the database | `core/file_discovery.py`, `registry/scanner_registry.py` |
| policy rule lists compared to the normaliser's *display* name | `normalized_crypto.algorithm = "TLS 1.0"` vs rule list `"TLS1.0"` → **BASELINE-005 / CBUAE-003 / PCIDSS-005 PASSed every TLS 1.0 / 1.1 / SSLv3 endpoint** | `policy/conditions/base_condition.py` — spelling-insensitive match across display name, standard name, evidence column and scanner name (`TLS 1.0` = `TLS1.0` = `TLSv1`, `Triple DES` = `DESede` = `3DES`); regression tests in `test_algorithm_in_list.py` |
| mainframe / HSM key labels not extracted as key references | COBOL `KEY-LABEL PIC X(64) VALUE 'MADA.ZPK.ACQ.001'`, KGUP `LABEL(…)` and payShield `A6 01 000 U MADA.ZMK…` never reached reconciliation, so every ICSF/payShield key looked like an orphan | `analysis/cascade.key_references` |

Follow-up (same day): a **cross-service contract test**, `services/worker/tests/unit/test_policy_normalizer_contract.py`,
now takes every algorithm named in every policy rule (leaf and COMPLEX conditions, 44 rules), pushes it through the
real normaliser exactly as `stage_normalize` does, and asserts the rule still fires. First run: **15 more
rule/algorithm pairs failed** — the COMPLEX condition used by CBUAE-001/003, PCIDSS-001/005, NIST131A, DIFC/PDPL
compared `evidence["algorithm"].upper()` directly, so those controls had the same blind spot. Fixed in
`complex_condition.py`; the contract test (90 cases) is the guard.

The second one is the reason to run the estate through the whole product and not just the scanner: the finding was
correct, the normalisation was correct, the rule was correct, and the verdict was still wrong.

## Suites after this round

scanner 251 passed / 12 skipped · worker 159 · policy 88 · evidence 43 · API (reconciliation / cascade / portfolio / compliance) 25 · benchmark 784/784, P/R/F1 1.000.

## Through the API (`services/api/tests/integration/test_snb_estate_api.py`)

The same estate is pushed into one SQLite database by `PipelineRunner`, then read back through `create_app()` with a
**real signed read-only session** (the only override is the DB session). Checked against the rows in the database:

* unauthenticated `GET /api/v1/scans/{id}` is refused; the analyst session sees `status = COMPLETED` and the cascade summary;
* `GET /scans/{id}/findings` (paged) returns exactly as many findings as evidence rows, each with the same `file_path`
  and `algorithm`; every labelled positive file is visible, the Arabic negatives are absent; RC4 in the GPO template
  and MD5 in the password hash read as failures through the API;
* `GET /scans/{id}/cascade?section=systems` returns the eight declared systems with TDES on `MADA-SWITCH`, the
  declared `MADA-SWITCH → CORE-LEDGER` dependency, and `?system=SNB-MOBILE` filters;
* `GET /scans/{inventory}/key-reconciliation` returns the same summary the worker stored, `MADA.ZPK.ACQ.001` among the
  consumers, ≥ 1 orphan and ≥ 1 code-only key;
* `GET /systems` lists the declared systems; `GET /cbom/portfolio` produces a non-empty CycloneDX CBOM after the scan;
* every field the console panels read (`CodeCascadePanel`, `KeyReconciliationPanel`) is present with the expected shape.

This hop found **no new defect** — the API/console layer already served what the pipeline had written. The browser
layer itself is exercised by the frontend unit suite (109 tests) against these same response shapes.
