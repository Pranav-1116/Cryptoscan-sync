# Network asset identity: an address is an attribute, not a name

`cryptoscan.nbom-identity-guide/1` · generated 2026-11-02T19:17:29.869508+00:00 · **5 pass · 0 partial · 0 fail** · 31 probes

Review item 20: *not* `IP:port`, because IPs change. A stable identity is assembled from the attributes that survive an address change, and the address becomes history on that identity.

```
asset_id → device_id → hostname + environment + location
         → certificate fingerprint → service identity
an address is never part of any step
```

2 network asset(s) from 2 observation(s) across 2 collector source(s); 1 asset(s) answered on more than one address

4 change(s) across 2 identity(ies); 2 address change(s), which moved under the same asset id rather than renaming it

| identity source | what it means |
|---|---|
| `asset_id` | the CMDB's own id: strongest, kept verbatim |
| `device_id` | a device serial or asset tag |
| `hostname` + environment + zone | derived, deterministic, `NET-XXXXXXXXXX` |
| certificate fingerprint | weak: a shared certificate is not a shared device |
| `IP:port` alone | **refused** — an address is where an asset answered |

| churn kind | reported as |
|---|---|
| `IP_ADDED` / `IP_REMOVED` | an attribute change carrying first/last seen |
| `CERTIFICATE_CHANGED` | a rotation under the asset, not a replacement |
| `HOSTNAME_CHANGED` | an alias added or lost |
| `ASSET_RETIRED` | retired *or* unobserved: a question for the owner |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `not_an_address` | is an address an identity, or a property of one? | **PASS** | 5, 0 failing |
| `one_asset_many_addresses` | what happens to history when an address moves? | **PASS** | 6, 0 failing |
| `what_an_identity_is_made_of` | which fields identify a device, and which only describe it? | **PASS** | 7, 0 failing |
| `interface_is_not_an_application` | may a load balancer's name be read as the application behind it? | **PASS** | 7, 0 failing |
| `history_without_rekeying` | does the history survive a failover, a rotation and a retirement? | **PASS** | 6, 0 failing |

## `not_an_address` — PASS

*is an address an identity, or a property of one?* (review 20)

- **PASS** `an-ip-and-a-port-cannot-create-an-asset` — an IP:port is not an identity: this observation carries no asset id, device id, hostname or certificate, and an address changes
- **PASS** `the-review-s-example-keeps-every-field-it-names` — NET-001928 · LOAD_BALANCER · DMZ
- **PASS** `a-derived-identity-is-deterministic-and-ignores-the-address` — NET-28794BDBFD for both addresses
- **PASS** `an-explicit-asset-id-wins-over-a-derived-one` — the CMDB id is kept, not replaced by a hash
- **PASS** `no-key-material-is-ever-part-of-an-identity` — NOT_STORED

## `one_asset_many_addresses` — PASS

*what happens to history when an address moves?* (review 20)

- **PASS** `an-address-change-does-not-become-a-new-asset` — NET-001928, NET-28794BDBFD
- **PASS** `churn-is-reported-as-attributes-on-the-same-identity` — 4 change(s) across 2 identity(ies); 2 address change(s), which moved under the same asset id rather than renaming it
- **PASS** `every-address-carries-when-it-was-first-and-last-seen` — 10.20.1.10 first and last seen 2026-11-01
- **PASS** `two-addresses-at-once-is-a-multi-homed-asset-not-two-assets` — 2 addresses on one identity
- **PASS** `a-rotation-is-a-change-under-the-asset-not-a-replacement` — the certificate rotated, the asset did not
- **PASS** `the-statement-says-the-addresses-are-attributes` — NET-001928 (LOAD_BALANCER, PRODUCTION, DC1) seen 1 time(s) with 2 address(es) 10.20.1.10, 10.20.1.11; the addresses are attributes of this asset, not its identity

## `what_an_identity_is_made_of` — PASS

*which fields identify a device, and which only describe it?* (review 20)

- **PASS** `environment-and-zone-are-part-of-the-identity` — three contexts, three identities
- **PASS** `the-basis-is-recorded-so-a-reviewer-can-see-the-inference` — hostname
- **PASS** `two-collectors-seeing-one-device-produce-one-asset` — 1 network asset(s) from 2 observation(s) across 2 collector source(s)
- **PASS** `a-disagreeing-device-type-is-kept-as-a-conflict` — both answers survive; neither is silently chosen
- **PASS** `an-unknown-device-class-is-recorded-and-listed` — UNKNOWN is a fact, not a guess
- **PASS** `a-class-outside-the-vocabulary-is-refused` — MAINFRAME_THING is not an asset type this model records
- **PASS** `the-same-observations-in-another-order-give-the-same-inventory` — order does not create identity

## `interface_is_not_an_application` — PASS

*may a load balancer's name be read as the application behind it?* (review 20 / item 8 boundary)

- **PASS** `an-asset-with-no-mapping-names-no-application` — NET-001928 is an interface fact: no application is named, because inferring one from a hostname is how a load balancer becomes an application
- **PASS** `a-mapping-without-an-evidence-id-is-a-claim` — the mapping carries no evidence id, so it is a claim and not evidence
- **PASS** `a-declared-mapping-with-evidence-is-the-only-proof` — NET-001928 is declared to serve Payments API (CMDB-7)
- **PASS** `a-hostname-that-looks-like-an-application-is-still-just-a-hostname` — the name is an entry point until a mapping says otherwise
- **PASS** `the-report-counts-proven-and-unproven-links` — 2 asset(s): 0 linked to an application by a declared mapping, 2 left as interface facts
- **PASS** `a-hop-asset-is-attached-to-the-device-that-terminated-it` — 2 network crypto asset row(s): 2 attached to an asset identity, 0 left unresolved rather than given a name
- **PASS** `an-interface-with-no-record-is-left-unresolved` — no inventory record carries Mystery Box as a hostname, SNI or service identity

## `history_without_rekeying` — PASS

*does the history survive a failover, a rotation and a retirement?* (review 20 / 21 boundary)

- **PASS** `a-three-run-history-answers-what-moved-without-re-keying` — 1 change(s) across 2 identity(ies); no address moved; 0 arrival(s) and 1 disappearance(s) to reconcile with the CMDB
- **PASS** `a-disappearance-is-a-question-for-the-owner` — no observation in the later inventory: retired and not answering are indistinguishable, so this is a question for the owner, not a deletion
- **PASS** `changes-carry-the-evidence-from-both-inventories` — NET-1 → NET-9 on every change
- **PASS** `the-summary-counts-addresses-under-identities` — 2 network asset(s) from 2 observation(s) across 2 collector source(s); 1 asset(s) answered on more than one address
- **PASS** `the-summary-states-what-an-inventory-cannot-prove` — 4 stated limit(s)
- **PASS** `a-churn-report-refuses-two-things-that-are-not-inventories` — a foreign document is rejected, not diffed

## What this does not prove

- a derived identity is a convenience, not a CMDB record. It is stable for as long as the hostname, environment and location are, and it says DERIVED so nobody has to guess which kind of id they are reading
- an asset with no observation in a later run is reported as retired *or* unobserved. Distinguishing those needs the collector's attempted target list (guide 153), and this module will not guess
- two collectors reporting one hostname may be two devices behind one name. The evidence ids are kept separate and the observation count says how many times the identity was confirmed, not how many devices exist
- an address seen once is recorded with a timestamp; an address is not tracked to the second, so churn between two runs is reported as added and removed rather than as a move
- device type is whatever the source said, or UNKNOWN. A wrong type in the CMDB is silently wrong here too, which is why the type participates in a conflict but never in the identity
- linking an asset to an application needs a declared mapping with an evidence id. Nothing here infers an application from a name, a zone or a certificate, so an unlinked asset stays an interface fact
- a hop asset from guide 148 is attached to an identity by matching the interface name against a hostname, SNI or service identity. An interface with no matching record stays UNRESOLVED; the alternative is an asset invented from a label somebody typed on a diagram
