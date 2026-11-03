# Passive observation, with the privacy contract enforced in code

`cryptoscan.cbom-passive-guide/1` · generated 2026-11-03T01:19:21.916488+00:00 · as of 2026-11-03T00:00:00Z · **5 pass · 0 partial · 0 fail** · 25 probes

Review item 15: cryptography recorded from traffic the estate already sends, gated on a privacy contract that is checked **before** a record is accepted.

```
capture ──▶ field known?  ──no──▶ refuse (unclassifiable)
             │yes
             ▼
        prohibited?     ──yes─▶ refuse (never even stripped)
             │no
             ▼
        in the contract? ──no──▶ refuse (the collector adds nothing)
             │yes
             ▼  pseudonymous ⇒ keyed hash, raw value discarded
        observation: OBSERVED · contract · expiry
```

contract DPC-2026-01 by dpo@bank.example: CRYPTO_INVENTORY, WEAK_PROTOCOL_DETECTION; retention 90d metadata / 30d pseudonymous; salt salt-2026q4

| class | fields |
|---|---|
| `METADATA` | `bytes_client_to_server`, `bytes_server_to_client`, `certificate_key_bits`, `certificate_key_type`, `certificate_sha256`, `cipher_suite`, `dst`, `dst_port`, `evidence_id`, `first_seen`, `kex_group`, `last_seen`, `packets`, `protocol`, `session_id_present`, `signature_algorithm`, `source`, `src`, `src_port`, `ssh_cipher`, `ssh_host_key`, `ssh_kex`, `ssh_mac`, `tls_version` |
| `PSEUDONYMOUS` | `client_address`, `ja3`, `ja4`, `server_name`, `session_id_hash` |
| `PROHIBITED` | `authorization`, `client_certificate_subject`, `cookie`, `decrypted`, `http_headers`, `password`, `payload`, `plaintext`, `private_key`, `token` |

Live observations: 3 · expired: CAP-OLD · refused: 0

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_contract` | is the privacy contract a check rather than a paragraph? | **PASS** | 5, 0 failing |
| `enforcement` | are prohibited fields refused visibly instead of dropped? | **PASS** | 5, 0 failing |
| `pseudonyms` | can an address be followed across records without being stored? | **PASS** | 5, 0 failing |
| `retention` | does an observation stop being evidence when its retention ends? | **PASS** | 5, 0 failing |
| `facts_and_shape` | does passive collection reach the CBOM without overreach? | **PASS** | 5, 0 failing |

## `the_contract` — PASS

*is the privacy contract a check rather than a paragraph?* (review 15)

- **PASS** `a-contract-that-cannot-be-checked-is-not-enforceable` — 4 problem(s) on an empty contract
- **PASS** `a-complete-contract-names-owner-purpose-and-retention` — contract DPC-2026-01 by dpo@bank.example: CRYPTO_INVENTORY, WEAK_PROTOCOL_DETECTION; retention 90d metadata / 30d pseudonymous; salt salt-2026q4
- **PASS** `a-prohibited-field-cannot-be-contracted-for` — payload is refused at contract time, not at capture time
- **PASS** `pseudonymous-data-may-not-outlive-metadata` — retention is per class and the shorter one is the binding one
- **PASS** `collecting-a-pseudonym-needs-a-deployment-salt-id` — without a salt id the pseudonym would be a global identifier

## `enforcement` — PASS

*are prohibited fields refused visibly instead of dropped?* (review 15)

- **PASS** `a-clean-capture-is-accepted` — handshake metadata only
- **PASS** `payload-is-refused-rather-than-stripped` — a sanitise() that quietly drops it would teach the schema to accept it
- **PASS** `an-unclassifiable-field-is-refused` — unknown is not the same as harmless
- **PASS** `a-field-outside-the-contract-is-refused` — the contract lists what may be collected and the collector adds nothing
- **PASS** `a-capture-without-an-evidence-id-is-refused` — a capture with no record is a claim

## `pseudonyms` — PASS

*can an address be followed across records without being stored?* (review 15)

- **PASS** `an-address-becomes-a-keyed-pseudonym-and-the-raw-value-never-lands` — p-6dee369539ee
- **PASS** `two-deployments-cannot-join-their-pseudonyms` — different salt, different pseudonym
- **PASS** `the-salt-id-is-recorded-and-the-salt-is-not` — the record can be audited without holding the secret
- **PASS** `a-pseudonym-without-a-salt-is-refused` — better a refusal than a raw address in the store
- **PASS** `metadata-stays-readable-so-the-inventory-is-still-useful` — the cryptography is the point; the client is not

## `retention` — PASS

*does an observation stop being evidence when its retention ends?* (review 15)

- **PASS** `an-observation-expires-with-its-shortest-lived-field` — 30 days, because a pseudonym lives beside the metadata
- **PASS** `an-observation-past-retention-is-marked-expired` — CAP-OLD
- **PASS** `an-expired-observation-contributes-no-facts` — retention is not a suggestion
- **PASS** `the-live-count-excludes-what-is-no-longer-evidence` — 4 observation(s) under contract DPC-2026-01, 3 live and 1 expired; suites seen: TLS_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA
- **PASS** `expiry-is-computed-against-an-explicit-as-of-not-the-wall-clock` — the same captures, a later moment, nothing left to cite

## `facts_and_shape` — PASS

*does passive collection reach the CBOM without overreach?* (review 15 / 16 boundary)

- **PASS** `a-passive-fact-says-how-it-was-collected` — 13 fact(s), each citing the contract
- **PASS** `a-passive-fact-is-never-promoted-to-configured` — a tap asked the device nothing
- **PASS** `roles-come-from-the-same-vocabulary-as-the-rest-of-the-platform` — BULK, KEY_EXCHANGE, PROTOCOL, SIGNATURE
- **PASS** `refusals-stay-visible-in-the-estate` — one accepted, one refused, both counted
- **PASS** `the-report-states-what-a-passive-tap-cannot-prove` — 5 stated limit(s)

## What this does not prove

- one capture is one conversation. A client can negotiate weaker than the server's policy allows on the next one, so a suite seen is not a policy
- a tap sees the traffic on its own span: what is tunnelled past it, off-net or on a path it does not cover is invisible, not absent
- a pseudonym is unlinkable across deployments and still a link inside one: the same client pseudonym appearing twice is a correlation
- the model reads handshake metadata only. It refuses payload, cookies and authorization headers, so it cannot say what was sent
- certificate validity is not derived from a fingerprint; the chain is guide 159's subject
- the contract is a technical check on the collector, not a legal opinion. An owner must still decide the lawful basis and sign it
