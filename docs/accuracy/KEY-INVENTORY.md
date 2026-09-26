# Key & certificate inventory — what the HSMs, KMSs and keystores actually hold

`services/scanner/scanner/parsers/key_inventory_parser.py` · `scripts/ingest_key_inventory.py` · findings
`source.type = KEY_INVENTORY`, language `KEY-INVENTORY`, scanner `key-inventory-ingest-v1.0`.

Source scanning sees keys only where code *references* them. The bank's key estate lives in ICSF key data
sets, LMK-wrapped payShield key blocks, Luna / nShield / Utimaco partitions, cloud KMS, Vault and
keystores. Every one of those can export a listing; this stage turns the listings into findings with the
same shape as code findings (algorithm, key size, confidence) plus an `inventory` block (label, usage,
state, created / last-used / not-after, key store, exportability, rotation).

**Key values are never read** — only metadata. Opt-in: `CRYPTOSCAN_KEY_INVENTORY=1` for a tree walk
(content-sniffed `.txt/.lst/.out/.json/.csv/.rpt/.prt/.list/.dump`), or the ingestion script for a drop folder.

## Formats

| Source | Export the bank produces | What we extract |
|---|---|---|
| **ICSF CKDS / PKDS / TKDS** | KGUP `LIST`, `CSFKDSL`, ISPF panel / CSV export | label, key type (`DATA`, `PINGEN`, `EXPORTER`, `AES DATA`, `HMAC`, `RSA-CRT`, `ECC`, `QSA`…), algorithm, key length (bytes → bits), curve, created, last referenced, archived |
| **TR-31 / X9.143 key blocks** | payShield, Atalla, Futurex, SafeNet key exports | version A/B/C/D (A = deprecated binding), usage (`P0` PIN encryption, `K0` KEK, `B0` BDK, `C0` CVK, `E0–E7` EMV IMKs, `M*` MAC, `S0` signature…), algorithm, mode of use, exportability, key version, inferred key length |
| **Thales Luna** | `cmu list`, `cmu getattribute`, partition contents | label, class, key type, modulus bits / value length, extractable |
| **Entrust nShield** | `nfkminfo -l`, `kmfile-dump` | app, ident, type (RSA/DSA/ECDSA/Rijndael/DES3/HMAC…), bits |
| **Utimaco / generic PKCS#11** | `csadm ListKeys`, `pkcs11-tool --list-objects` | object class, type, bits/length, label, curve, usage |
| **AWS KMS** | `list-keys` + `describe-key` JSON | KeySpec → algorithm/size, KeyState, KeyUsage, origin (CloudHSM / external), rotation, multi-region, deletion date |
| **Azure Key Vault / Managed HSM** | `az keyvault key list/show` JSON | kty, key_size / curve, enabled, key_ops, exp, rotation policy |
| **GCP Cloud KMS / Cloud HSM / EKM** | `gcloud kms keys list --format=json` | versionTemplate.algorithm → algorithm/size, protection level, purpose, rotation period, primary state |
| **HashiCorp Vault transit** | `vault read transit/keys/<name>` JSON | type → algorithm/size, latest version, min decryption version, exportable, auto-rotate |
| **Java keytool** | `keytool -list -v` | alias, entry type, key algorithm/size, signature algorithm, validity (expired flag), self-signed |
| **RACF** | `RACDCERT LIST` | label, status, key type/size, ICSF vs software private key, signing algorithm, validity, ring owner |
| **Certificate inventories** | `openssl x509 -text`, Venafi / AppViewX / DigiCert CSV | subject, issuer, key algorithm/size, signature algorithm, not-after (expired / expiring ≤ 90 d) |

Certificate records also emit companion findings for the signature digest (`SHA-1` on a `sha1RSA` cert),
tagged `inventory.role = certificate signature digest`, so SHA-1 signing shows up in the algorithm inventory.

## The reconciliation (what makes it end-to-end)

`python scripts/ingest_key_inventory.py <exports> --source <repo>` prints:

1. the key estate by system × algorithm × bits;
2. flags — **weak** (below the registry floor: RSA/DSA/DH < 2048, EC < 256, AES < 128), **disallowed
   algorithm** (single DES, DSA, RC4…), **expired / expiring ≤ 90 d**, **stale** (last used > 365 d),
   **inactive** (archived, disabled, pending deletion), **exportable / extractable**, **TR-31 version-A
   binding**, **no rotation** on cloud KMS keys;
3. **consumers**: inventory labels / aliases / keystore names that the code references (via the cascade
   analysis' key-reference index) — e.g. `ICSF PAY.ZPK.ACQ001 ← Pay.java`;
4. **orphans**: keys with no consumer in any scanned repository — either dead keys, or a system the bank
   has not yet given us (both are answers a bank needs);
5. **not in any inventory**: key files / aliases the code uses that no export contains — keys living
   outside the HSM/KMS estate.

On the fixture set (14 exports, 12 systems): 52 findings / 45 keys & certs, 5 weak, 2 disallowed,
3 expired, 3 stale, 3 inactive, 2 exportable, 1 TR-31-A, 7 without rotation; reconciliation against a
one-file repo found 2 consumers, 36 orphans, 1 keystore outside the inventory.

## Status

Built and unit-tested on realistic fixtures written from the vendors' documented output formats. **No bank
export has been parsed yet** — field layouts (especially KGUP and vendor CSV columns) will need a first
real drop; the parsers are tolerant (keyword-based, not column-based) for that reason.

## Where it lands in the product

* Findings carry `source.type = KEY_INVENTORY` and the `inventory` attribute map; the worker stores the full finding in
  `evidence_records.finding_data`, so label / usage / state / dates / exportability are queryable and in the evidence pack.
* **Certificates table.** Certificate records from keytool, RACDCERT, openssl text, certificate CSVs and cloud KMS
  are upserted into `certificates` by the worker (`pipeline_runner.py::inventory_certificates`) so they appear in the
  Certificates page, the renewal queue and certificate-exposure graph queries next to TLS-probed certificates. Exports
  seldom include a SHA-256 fingerprint, so the row key is derived from subject | issuer | not_after | serial and flagged
  `extra.fingerprint_derived = true`; `extra.source = "KEY_INVENTORY"`, `extra.key_label`, `extra.key_store`,
  `extra.library` say where it came from. `usages` lists the export file path. Re-scanning the same export is idempotent.
* Enable per worker profile with `CRYPTOSCAN_KEY_INVENTORY=1` — see
  [admin-guide/scanner-configuration.md](../admin-guide/scanner-configuration.md).
* **Reconciliation API.** `GET /api/v1/scans/{inventory_scan_id}/key-reconciliation[?source_scan=<id>&source_scan=…]`
  joins the inventory scan's `KEY_INVENTORY` findings with the `key_references` section that every source scan's
  cascade report now carries (all keystore files / aliases / env vars / KMS ids the code refers to, one file is enough).
  Default source set = newest completed scan per target. Response: `summary`, `consumers` (inventory key → referencing
  files and scans), `orphans` (inventory keys no scanned repo uses — retire candidates or an unscanned system),
  `not_in_inventory` (aliases / keystore files in code that no export lists; env vars are excluded because they are not
  inventory items). Same logic as `scripts/ingest_key_inventory.py --source`, but DB-side and per scan.
* **Policy.** `services/policy/rule_definitions/key_inventory/` (KEYINV-001…009: exportable / extractable, TR-31 version A,
  expired, expiring ≤ 90 d, stale > 365 d, non-active state, weak key-block binding) via the `KEY_INVENTORY_ATTRIBUTE`
  condition — FAIL/WARN on export records, `NOT_APPLICABLE` on code, so the source-scan gate is unchanged
  ([admin-guide/policy-rules.md](../admin-guide/policy-rules.md)).
* **Drift & alerts.** Every inventory scan is reconciled in the worker (`worker/pipeline/inventory_drift.py`) against the
  newest source scans and against the *previous* export of the same drop — no approved baseline needed. New findings raise
  drift events that flow to the alert stage and the Drift page: `KEY_UNACCOUNTED` (HIGH — code uses an alias / keystore no
  inventory lists), `KEY_ORPHAN` (MEDIUM — inventory key no scanned repo references), `KEY_INVENTORY_REMOVED` (LOW — key
  gone from the export). Unchanged conditions do not re-alert; the first scan reports everything once (≤ 200 events, the
  rest is counted). The reconciliation is stored in `Scan.statistics.key_reconciliation`.
