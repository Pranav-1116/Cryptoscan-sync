# UAE bank estate — end-to-end validation (CBUAE / PDPL / DIFC profile)

**What this is.** A representative, synthetic estate shaped like a UAE retail bank — UAESWITCH / Jaywan card switch,
Aani instant payments (pacs.008), Open Finance (Nebras FAPI), UAE PASS identity (SAML + mobile), Emirates ID
validation gateway, Temenos T24 core with an Oracle KYC schema and an ICSF COBOL module, WPS / FTA regulatory
filing, branch infrastructure (FortiOS SSL-VPN, RD Gateway, CBUAE TLS baseline, MQ) — scanned **blind** through the
discovery engine and then through the **whole pipeline** with a `cryptoscan-systems.yml` that assigns each business
system its **compliance scopes** (`CBUAE`, `PAYMENT`, `CARD`, `CUSTOMER-FACING`, `REMOTE-ACCESS`, `PDPL`, `DIFC`,
`PERSONAL_DATA`).

**What this is not.** It is not any UAE bank's code, configuration or key material; no bank system was accessed. The
fixture was written from public standards and vendor documentation (UAESWITCH / Jaywan scheme material, Aani /
IPP ISO 20022 usage, Open Finance FAPI 1.0 Advanced, UAE PASS SAML/OIDC integration guides, ICSF and payShield
manuals, FortiOS CLI reference, Microsoft SCHANNEL registry documentation, PDPL 45/2021, DIFC DP Law 5/2020, ADGM
DPR 2021). The numbers say how the product behaves on code *of that shape*.

## The fixture (`services/scanner/tests/accuracy/corpus_wave18_uae_bank.py`, 24 files, 4 negatives)

| System (cryptoscan-systems.yml) | Scopes | Files | What it exercises |
|---|---|---|---|
| UAESWITCH-CARD (critical) | CBUAE, PAYMENT, CARD | `UaeSwitchPinTranslator.java`, `JaywanTokenizer.kt` | jPOS-style TDES PIN translation (ZPK/PVK), Android Keystore AES-GCM token vault |
| AANI-IPP (critical) | CBUAE, PAYMENT | `AaniPacs008Signer.java`, `aaniProxyPay.ts`, `mq-aep-channel.mqsc` | pacs.008 signing with RSA-SHA256 behind a PKIX `KeyManagerFactory`, proxy-pay JWS, MQ channel cipher spec |
| OPEN-FINANCE (high) | CBUAE, CUSTOMER-FACING | `NebrasFapiClient.cs` | FAPI private_key_jwt (`SecurityAlgorithms.RsaSsaPssSha256`, `EcdsaSha256`), mTLS `ClientCertificates.Add` |
| UAEPASS-IDENTITY (high) | PDPL, PERSONAL_DATA | `UaePassSamlValidator.cs`, `EmiratesIdVgClient.cs`, `UaePassLogin.swift`, `i18n.ar-AE.json` (negative) | `SignedXml` + xmldsig URIs, `ValidAlgorithms = {"RS256"}`, Emirates ID VG AES-CBC/HMAC, iOS Keychain + P-256 |
| T24-CORE-KYC (critical) | PDPL, DIFC, PERSONAL_DATA | `T24OfsSessionCipher.java`, `pkg_kyc_pii.pks`, `legacy_customer_pwd.sql`, `tde_uae_core.sql`, `CBEIDENC.cbl`, `iban_ae_validate.py` (negative), `README.ar.md` (negative) | OFS session DES (deliberately weak), DBMS_CRYPTO, MD5 password hash (deliberately weak), TDE, ICSF CSNBSYE Emirates-ID encryption |
| REG-FILING (medium) | *(none)* | `wps_sif_uploader.py`, `fta_peppol_as4.py`, `wps-schedule.yaml` (negative) | SIF SFTP + PGP, Peppol AS4 `xmlenc11#aes128-gcm` / `rsa-oaep` URI constants |
| BRANCH-INFRA (medium) | CBUAE, REMOTE-ACCESS | `branch-sslvpn.conf`, `rdgateway.reg`, `cbuae-tls-baseline.conf` | FortiOS `set ssl-min-proto-ver tls1-0` (deliberately weak), RD Gateway `.reg` SCHANNEL export enabling TLS 1.1 + 3DES, hardened TLS 1.2/1.3 baseline |

## Discovery accuracy (scanner only, `scripts/accuracy_benchmark.py`)

| pass | precision | recall | F1 | exact files |
|---|---|---|---|---|
| blind first pass (no scanner change) | 1.000 | 0.992 | **0.996** | 814/820 (6 UAE files short) |
| after wave-18 fixes | 1.000 | 1.000 | 1.000 | 820/820 |

Above the 95 % bar blind, zero false positives. The six misses were all *shape* gaps, each fixed once and shared:

* **`KeyManagerFactory` / `TrustManagerFactory.getInstance("PKIX" | "SunX509")`** with an injected `KeyStore` — an X.509 key/trust manager with no `KeyStore.getInstance` in the file (`java_rules.py`, X509 MEDIUM).
* **Microsoft.IdentityModel verifier/signer side** — `new RsaSecurityKey(…)`, `ECDsaSecurityKey`, `X509SecurityKey`, `TokenValidationParameters { ValidAlgorithms = … }`, `JsonWebKeySet`; and **mutual-TLS client certificates** `HttpClientHandler.ClientCertificates.Add(cert)` (`csharp_parser.py`).
* **XML-DSig / XML-Enc algorithm URIs as string constants in code** (`…xmldsig#rsa-sha256`, `…xmlenc11#aes128-gcm`, `…xmlenc#rsa-oaep`) — previously known only inside XML documents. Now one table, `scanner/parsers/xmlsec_uris.py`, used by the C# and Python parsers (SAML, WS-Security, XAdES, Peppol AS4 all spell their algorithms this way). Python comment stripping had to become token-based so the `#` inside the URI survives.
* **`SignedXml.CheckSignature(X509Certificate2, …)`** → X509 (the SAML IdP certificate is the trust anchor).
* **FortiOS / appliance CLI** `set ssl-min-proto-ver tls1-0`, `set dtls-min-proto-ver`, `set ssl-max-proto-ver` (`config_rules.py`, `appliance-min-proto-version`). The banned-cipher list on the same appliance is correctly *not* counted.
* **`.reg`-style SCHANNEL exports** — `[HKEY_…\SCHANNEL\Protocols\TLS 1.1\Server]` followed by `"Enabled"=dword:00000001` on the next line. Only the `.inf` same-line form was known; the bracketed-key form now shares the same name table and the same `DisabledByDefault` inversion, so a *disabled* protocol is still hardening, not use.

One label corrected against the detector: `SecurityAlgorithms.RsaSsaPssSha256` is the JWT alg `PS256` (corpus convention: JWT algs → `JWT`, resolved to primitives downstream), not a separate SHA-256 use.

## Whole-pipeline run (`services/worker/tests/unit/test_pipeline_uae_estate.py`)

The same 24 files are laid out as a repository with a `cryptoscan-systems.yml` carrying `criticality`, `owner`,
`depends_on` **and `compliance_scopes` per system**, and run through `PipelineRunner` against a real (SQLite)
database. Asserted:

1. **Accuracy survives the pipeline** — evidence rows scored against the blind labels: precision and recall ≥ 0.97, ≥ 95 % of files exact; the Arabic README / i18n / IBAN / schedule negatives produce no row (README and i18n JSON are not even routed to a scanner).
2. **Per-file compliance scopes** — every evidence row's `finding_data.compliance_scopes` equals the scopes of the declared system that owns its path (repo-level `System.compliance_scopes` ∪ declared system scopes). `REG-FILING` rows carry none.
3. **Scope-gated UAE rules fire only where the scope applies** — PDPL-001/002, DIFC-001/002 and ADGM-001 never evaluate (recorded `NOT_APPLICABLE`, "outside required scopes") on the card switch, Aani, Open Finance or branch infra; CBUAE-002..005 never evaluate on identity / core; the un-scoped regulatory filer gets no UAE scope rule at all. Concrete verdicts: TLS 1.0 on the SSL-VPN and TLS 1.1 on the RD Gateway → **CBUAE-003 FAIL** (REMOTE-ACCESS); TDES PIN translation on the switch → **CBUAE-001 FAIL**; DES / MD5 in core → **PDPL-002 + DIFC-002 FAIL**; the hardened CBUAE TLS baseline (TLS 1.2/1.3, AES-GCM, X25519) → no FAIL; every record carries content + chain hashes.
4. **Declared systems persisted** — `System` rows carry the declared scopes and criticality; `SystemDependency` edges include the declared `depends_on` (OPEN-FINANCE → UAEPASS-IDENTITY / T24-CORE-KYC); the cascade report shows all seven systems and TDES on the card switch.

### What the end-to-end run added to the product

| gap | effect before | change |
|---|---|---|
| `compliance_scopes` declared per business system were ignored | scopes came only from the *repository-level* `System` row, so one repo holding both the card switch and the KYC schema could only be "all CBUAE" or "all PDPL"; jurisdiction rules either fired everywhere or nowhere | `cryptoscan-systems.yml` `compliance_scopes:` is loaded (`analysis/cascade.load_system_map`), attached to the declared `System` rows on persist, and the policy stage computes **per-row scopes = repo scopes ∪ owning declared system's scopes** (`pipeline_runner._policy`, `_scopes_for_path`) before evaluation |
| `finding_data.compliance_scopes` was blank when scopes came from the repo `System` | evidence viewer / CBOM could not show *why* a rule was applied | now written per row |

Note for CBUAE-001 (forbidden legacy algorithms): it is deliberately **not** scope-gated — DES / 3DES / RC4 / MD5 /
SHA-1 / TLS < 1.2 fail in every system of a CBUAE-supervised estate; banks outside the UAE that do not want this rule
disable it in the policy set rather than by scope.

## Honest limits

* Representative fixture, not a bank's estate; the labels are ours. The blind first-pass number (0.996) is the
  measurement; the 1.000 after fixes is a regression guard.
* Scope rules are only as good as the `cryptoscan-systems.yml` a bank writes; nothing infers "personal data" from
  code content.
* The e2e run uses SQLite; PostgreSQL parity for these paths is covered by the existing worker integration suite,
  not by this test.
