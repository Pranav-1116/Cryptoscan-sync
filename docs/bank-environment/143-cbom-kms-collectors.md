# Supported, existing, used: three answers for a key

`cryptoscan.cbom-kms-collectors-guide/1` · generated 2026-11-02T17:54:24.567749+00:00 · **4 pass · 0 partial · 0 fail** · 20 probes

The review's item 11: key metadata has to come from the key store, and the CBOM has to keep three facts apart that sound alike:

| Claim | Evidence class | Means |
|---|---|---|
| the module supports RSA-4096 | `VENDOR_DECLARED` | a capability, no key implied |
| an RSA-4096 key exists | `CONFIGURED` | an inventory fact, no use implied |
| RSA-4096 was used | `RUNTIME_OBSERVED` | the only one of the three that is usage |

`cbom.kms_collectors` implements that boundary: inventory rows become metadata records (never key material), usable keys become `CONFIGURED` events, and recorded operations become `RUNTIME_OBSERVED` events that require an inventoried key, an operation name, an evidence id and a timestamp.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `three_answers` | can the CBOM tell a supported algorithm from an existing key from a used one? | **PASS** | 6, 0 failing |
| `never_the_key` | does the collector store key references only, and refuse what it cannot attribute? | **PASS** | 7, 0 failing |
| `posture` | does the inventory say what is weak, what is stale, and what it does not know? | **PASS** | 4, 0 failing |
| `api_exposure` | can an operator feed a KMS inventory in and get three separate answers? | **PASS** | 3, 0 failing |

## `three_answers` — PASS

*can the CBOM tell a supported algorithm from an existing key from a used one?* (review 11)

- **PASS** `the-three-answers-are-three-classes` — a capability is a declaration; a configured key is an observation of the inventory; only an operation is usage
- **PASS** `an-inventoried-key-is-configured-and-not-used` — 1 key record(s) across 1 provider(s), metadata only
- **PASS** `a-key-nobody-used-produces-no-runtime-event` — 1 configured key(s), 0 recorded operation(s); a configured key is not usage
- **PASS** `a-recorded-operation-is-runtime-and-names-the-key` — 1 configured key(s), 1 recorded operation(s)
- **PASS** `the-two-layers-reach-the-usage-profile-separately` — AES (key_size=256, mode=GCM): observed; observed by USE-1, KMS-1
- **PASS** `a-key-that-exists-is-configured-not-runtime` — promoted level CONFIGURED; the ladder needs an operation to reach RUNTIME

## `never_the_key` — PASS

*does the collector store key references only, and refuse what it cannot attribute?* (review 11 / 12)

- **PASS** `a-row-with-key-material-is-refused-not-sanitised` — the row carries private_key; a CBOM stores key references, never material
- **PASS** `a-row-with-no-key-reference-is-refused` — a key record needs a key_ref; the material itself is never stored
- **PASS** `a-key-with-no-evidence-id-is-not-a-configured-event` — the inventory row has no evidence id
- **PASS** `a-disabled-key-is-inventoried-but-not-usable` — inventory keeps it; configuration does not claim it
- **PASS** `an-operation-on-an-uninventoried-key-is-refused` — the operation names a key that is not in the inventory; the inventory is incomplete, not the operation
- **PASS** `an-operation-without-evidence-or-time-is-refused` — a key operation is missing evidence_id, observed_at
- **PASS** `an-unknown-provider-is-kept-and-marked` — coerced into the nearest known provider would be a guess

## `posture` — PASS

*does the inventory say what is weak, what is stale, and what it does not know?* (review 11)

- **PASS** `weak-sizes-and-old-curves-are-named` — 2 weak key(s)
- **PASS** `rotation-is-judged-against-the-banks-policy-age` — 3 key(s) inventoried across 3 algorithm(s); 2 weak, 1 past 365 days without rotation, 1 with no recorded age
- **PASS** `a-key-with-no-recorded-age-is-unknown-not-fresh` — unknown age: ['unknown-age']
- **PASS** `posture-counts-what-the-inventory-actually-names` — {"AES": 1, "ECDSA": 1, "RSA": 1}

## `api_exposure` — PASS

*can an operator feed a KMS inventory in and get three separate answers?* (review 11)

- **PASS** `the-kms-route-exists-and-is-typed` — POST /cbom/kms/keys
- **PASS** `the-route-requires-a-cbom-reader-role` — role-gated, not merely authenticated
- **PASS** `the-route-uses-the-collector-not-a-copy` — one implementation, shared with the scripts and tests

## What this does not prove

- the collector reads rows it is given. It does not call AWS KMS, Azure Key Vault, GCP KMS or a PKCS#11 device itself, so 'the inventory is complete' is the caller's claim and the CBOM cannot check it
- metadata is only as current as the export. A key created after the inventory run is invisible, and an operation on it is refused as uninventoried rather than attributed to the nearest key
- rotation posture uses one policy age for the whole inventory. A bank with per-key-class policies gets one number here, so the finding is a trigger to look, not a breach
- 'usable' is decided from a fixed status vocabulary (ENABLED/ACTIVE/AVAILABLE/IN_USE). A provider with different states is inventoried and marked unusable, which under-claims rather than over-claims
- the distinction supported/exists/used is per key record, not per call site. Two applications using one KMS key produce one record; separating them needs the application column filled in the export
- private material is refused by field-name heuristics (private_key, secret, password, material, ...). A provider that returns key bytes in an innocuously named column would get past the filter, so the export should never contain them
- posture does not decide what to migrate: a weak-but-disabled key is still counted as weak, and the migration judgement belongs to the quantum and assessment engines
