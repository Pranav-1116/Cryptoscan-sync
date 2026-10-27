# GCC (Qatar + Bahrain) bank estate — end-to-end validation

**What this is.** A representative, synthetic estate of a Gulf bank with a Doha entity (QCB-supervised) and a Manama
entity (CBB-licensed): Himyan card switch, Fawran instant payments, QMP wallet, NAS identity, Qatar KYC vault (QID),
QCB regulatory reporting; BENEFIT switch / Fawri+ / BenefitPay, Bahrain Open Banking Framework, BENEFIT eKYC (CPR);
shared edge infrastructure (Palo Alto, F5, Cisco ASA). Scanned **blind**, then run through the **whole pipeline** with a
`cryptoscan-systems.yml` that gives every system its own `compliance_scopes` — and this time two regulators and two
personal-data laws sit in one repository.

**What this is not.** Not any bank's code or configuration; written from public standards and vendor manuals (QCB
Technology Risk Circular, Qatar Law 13/2016, CBB Rulebook OM-5, Bahrain Law 30/2018, Bahrain OBF, BENEFIT / Fawran
integration material, Apache Santuario, PAN-OS / TMOS / ASA CLI references).

## The fixture (`services/scanner/tests/accuracy/corpus_wave19_gcc_bank.py`, 22 files, 4 negatives)

| System | Scopes | Files | Deliberately weak? |
|---|---|---|---|
| QA-HIMYAN-SWITCH (critical) | QCB, PAYMENT, CARD | `HimyanPinBlockTranslator.java`, `CBHIMPIN.cbl` | TDES PIN translation |
| QA-FAWRAN-IPP (critical) | QCB, PAYMENT | `FawranIso20022Signer.java` (Santuario RSA-SHA256), schedule (negative) | — |
| QA-QMP-WALLET (high) | QCB, CUSTOMER-FACING | `QmpWalletTokenService.cs`, `QmpDeviceBinding.swift`, `i18n.ar-QA.json` (negative) | — |
| QA-NAS-IDENTITY (high) | QCB, CUSTOMER-FACING | `NasOidcValidator.cs` | — |
| QA-KYC-VAULT (critical) | PDPPL, PERSONAL_DATA | `pkg_qid_vault.pks`, `qid_validate.py` (negative) | — |
| QA-REG-REPORTING (medium) | QCB | `qcb_fx_report_signer.py`, `README.ar.md` (negative) | — |
| BH-BENEFIT-SWITCH (critical) | CBB, PAYMENT | `fawri_plus_hmac.go`, `benefitpay_qr_signer.go`, `BenefitPaySdk.kt`, `benefit-sftp-sshd_config` | — |
| BH-OPEN-BANKING (high) | CBB, OPEN-BANKING, CUSTOMER-FACING | `openBankingBh.ts` | — |
| BH-EKYC (high) | BH-PDPL, PERSONAL_DATA | `benefit_ekyc_client.py`, `legacy_cpr_hash.sql` | SHA-1 over CPR numbers |
| GCC-EDGE-INFRA (medium) | QCB, CBB, REMOTE-ACCESS | `paloalto-ssl-decrypt.set`, `f5-clientssl.tmsh`, `cisco-asa-ssl.cfg` | PAN-OS min-version tls1-0 / tls1-1 |

## Discovery accuracy (scanner only)

| pass | precision | recall | F1 | exact files |
|---|---|---|---|---|
| blind first pass (no scanner change) | 1.000 | 0.986 | **0.993** | 836/842 (6 GCC files short) |
| after wave-19 fixes | 1.000 | 1.000 | 1.000 | 842/842 |

Zero false positives blind. The misses:

* **Apache Santuario constants** — `XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256`, `Constants.ALGO_ID_DIGEST_SHA256`, `sig.addKeyInfo(cert)`: the Java signer for ISO 20022 / SAML named its algorithms only through library constants (`java_rules.py`, full `ALGO_ID_*` table).
* **`requests.post(…, cert=(crt, key))`** — an mTLS client certificate presented from Python was invisible (`python_parser._client_cert`).
* **jose `calculateJwkThumbprint(jwk, 'sha256')`** (`javascript_rules.py`).
* **Three network-appliance CLI dialects** — PAN-OS `set … min-version tls1-1`, `enc-algo-rc4 no` / `auth-algo-sha1 yes` (only `yes` counts), F5 tmsh `ciphers ECDHE+AES-GCM:…` (`+` groups), `options { no-tlsv1 no-tlsv1.1 }` (a floor), `cert-key-chain`, Cisco ASA `ssl server-version tlsv1.2`, `ssl cipher tlsv1.2 custom "…"`, `ssl dh-group group14` / `ecdh-group group19` (with group → bits), `ssl trust-point`. `.set` and `.tmsh` were not routed to any parser at all — both the CLI and the pipeline's file discovery now know them (`config_rules.py`, `language_scanners.CONFIG_EXT`, `core/file_discovery.py`).

One label corrected in the detector's favour: a PAN-OS `ssl-tls-service-profile … certificate portal-2024` line binds an X.509 certificate.

## Whole-pipeline run (`services/worker/tests/unit/test_pipeline_gcc_estate.py`, SQLite **and** PostgreSQL)

Asserted through `PipelineRunner` against a real database (both backends, see `scripts/postgres_parity.sh`):

1. **Accuracy survives the pipeline** — P/R ≥ 0.97 on the evidence rows, ≥ 95 % files exact, the four Arabic negatives silent.
2. **Per-file scopes** equal the owning declared system's scopes for every row.
3. **Jurisdiction follows the regulator tag, never the generic data tag** — the UAE gated pack (CBUAE-002..005, PDPL, DIFC, ADGM) never evaluates anywhere in this estate; Qatar systems never see CBB / Bahrain-PDPL rules and vice versa; `QA-KYC-VAULT [PDPPL, PERSONAL_DATA]` is judged under PDPPL-001/002 only; `BH-EKYC` fails **BHPDPL-001** for SHA-1 over CPR; the Himyan switch fails **QCB-001** for TDES; the shared edge fails **QCB-002 and CBB-002** for the PAN-OS TLS 1.0/1.1 floors while the hardened ASA passes both; the OBF service (PS256, SHA-256) fails nothing.
4. **Declared systems persisted** with scopes, criticality and `depends_on` edges; cascade shows all ten systems.

### The product defect this run found — and the fix

Before this run the scope test in every jurisdiction rule was a flat **any-of** list that mixed the regulator's tag with
jurisdiction-neutral data classes: CBUAE-002 was `[CBUAE, PAYMENT, CARD, SWIFT]`, CBUAE-003 `[CBUAE, CUSTOMER-FACING,
REMOTE-ACCESS]`, PDPL/DIFC/ADGM `[…, PERSONAL_DATA]`. Consequence: **a Qatari card switch tagged `PAYMENT` was evaluated
under CBUAE-002, and a Bahraini eKYC store tagged `PERSONAL_DATA` under UAE PDPL, DIFC and ADGM** — the first assertion of
this test failed exactly there (`('QA-HIMYAN-SWITCH', {'CBUAE-002'})`). The UAE-only estate could not show it because
every system there carried a UAE tag anyway.

Fix (`policy/core/scope_resolver.py`): rules now separate the two —

```yaml
required_scopes: [CBUAE]                      # any-of: the regulator / jurisdiction
required_scope_groups:                        # each group any-of, all groups required
  - [PAYMENT, CARD, SWIFT]                    # the data class the control is about
```

CBUAE-002/003, QCB-002 and CBB-002 use groups; the personal-data laws list their jurisdiction tags only (`PDPL`,
`DIFC`, `ADGM`, `PDPPL`, `BH-PDPL` and the statute aliases). `PERSONAL_DATA`, `PAYMENT`, `CARD`, `CUSTOMER-FACING`,
`REMOTE-ACCESS`, `OPEN-BANKING` on their own select no law. Pinned by `policy/tests/unit/test_gcc_rules.py`
(`test_personal_data_rules_follow_the_jurisdiction_not_the_generic_tag`), the updated UAE unit tests, and both estate
runs. CBUAE-001 remains unscoped by design (see UAE-VALIDATION.md).

## New policy packs

`rule_definitions/qatar/` QCB-001 (legacy algorithms), QCB-002 (TLS 1.2 floor for customer / remote channels), QCB-003
(2048-bit RSA/DSA), PDPPL-001/002 (Law 13/2016 technical precautions); `rule_definitions/bahrain/` CBB-001..003 (OM-5),
BHPDPL-001/002 (Law 30/2018 Art. 8). Grounding is public regulation text; a bank's compliance function should confirm
the mapping before relying on the verdicts — the rules are scoped, enabled, and carry references and remediation.

## Honest limits

Representative fixture; blind 0.993 is the measurement, 1.000 the regression guard. Scope correctness depends entirely
on the tags a bank declares in `cryptoscan-systems.yml`; nothing infers jurisdiction from code.
