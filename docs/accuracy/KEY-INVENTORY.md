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
